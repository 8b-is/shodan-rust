//! Quick threat response command - lookup + ban in one shot.

use crate::cli::args::ThreatArgs;
use crate::cli::commands::Context;
use crate::defend::State;
use anyhow::Result;
use colored::Colorize;
use i1_providers::HostLookup;
use std::io::{self, Write};

/// Execute the threat command.
pub async fn execute(ctx: &Context, args: &ThreatArgs) -> Result<()> {
    let ip = &args.ip;

    // Header
    println!("{}", "━".repeat(60).dimmed());
    println!("{} {}", "🎯 THREAT RESPONSE:".red().bold(), ip.yellow().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Try to look up the IP
    let host_info = match ctx.shodan_provider() {
        Ok(provider) => match provider.lookup_host(ip).await {
            Ok(info) => Some(info),
            Err(e) => {
                println!(
                    "{} Shodan lookup failed: {}",
                    "⚠".yellow(),
                    e.to_string().dimmed()
                );
                println!();
                None
            }
        },
        Err(_) => {
            println!("{} No API key configured, skipping lookup", "⚠".yellow());
            println!();
            None
        }
    };

    // Display threat intel if we got it
    if let Some(ref info) = host_info {
        // Organization & ASN - the most important info
        if let Some(ref org) = info.org {
            println!("  {} {}", "Organization:".cyan(), org.white().bold());
        }
        if let Some(ref asn) = info.asn {
            println!("  {} {}", "ASN:".cyan(), asn.yellow().bold());
        }
        if let Some(ref isp) = info.isp {
            println!("  {} {}", "ISP:".cyan(), isp);
        }

        // Location
        let loc_parts: Vec<String> = [
            info.location.city.clone(),
            info.location.region_code.clone(),
            info.location.country_name.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();

        if !loc_parts.is_empty() {
            println!("  {} {}", "Location:".cyan(), loc_parts.join(", "));
        }

        // Hostnames
        if !info.hostnames.is_empty() {
            println!("  {} {}", "Hostnames:".cyan(), info.hostnames.join(", "));
        }

        // Open ports - critical for threat assessment
        if !info.ports.is_empty() {
            let ports_str: Vec<String> = info.ports.iter().map(|p| p.to_string()).collect();
            println!(
                "  {} {}",
                "Open Ports:".cyan(),
                ports_str.join(", ").white()
            );
        }

        // Vulnerabilities - RED ALERT
        if !info.vulns.is_empty() {
            println!(
                "  {} {}",
                "🚨 VULNS:".red().bold(),
                info.vulns.join(", ").red()
            );
        }

        println!();
    }

    // Determine if we should ban
    let should_ban = args.ban || args.ban_asn || args.execute;

    if should_ban || args.yes {
        // Auto-ban mode
        do_ban(ip, args, &host_info).await?;
    } else {
        // Interactive mode - ask user what to do
        println!("{}", "Actions:".white().bold());
        println!("  [b] Ban this IP");
        if host_info.as_ref().and_then(|h| h.asn.as_ref()).is_some() {
            println!("  [a] Ban entire ASN");
        }
        println!("  [x] Show iptables command");
        println!("  [n] Do nothing");
        println!();

        print!("{} ", "Choice [b/a/x/n]:".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().to_lowercase().as_str() {
            "b" => {
                let mut new_args = args.clone();
                new_args.ban = true;
                do_ban(ip, &new_args, &host_info).await?;
            }
            "a" => {
                let mut new_args = args.clone();
                new_args.ban_asn = true;
                do_ban(ip, &new_args, &host_info).await?;
            }
            "x" => {
                let mut new_args = args.clone();
                new_args.execute = true;
                do_ban(ip, &new_args, &host_info).await?;
            }
            _ => {
                println!("{}", "No action taken.".dimmed());
            }
        }
    }

    Ok(())
}

/// Get the IP of the current SSH session (if any)
fn get_ssh_client_ip() -> Option<String> {
    std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .ok()
        .and_then(|s| s.split_whitespace().next().map(String::from))
}

async fn do_ban(ip: &str, args: &ThreatArgs, host_info: &Option<i1_core::HostInfo>) -> Result<()> {
    // Safety check: refuse to block your own SSH session
    if let Some(ssh_ip) = get_ssh_client_ip() {
        if ip == ssh_ip {
            println!();
            println!(
                "{} Refusing to block {} - that's YOUR SSH session!",
                "🛡️ PROTECTED:".yellow().bold(),
                ip.cyan()
            );
            println!();
            println!(
                "{}",
                "This prevents you from locking yourself out. You're welcome. 😉".dimmed()
            );
            return Ok(());
        }
    }

    let mut state = State::load()?;

    if args.execute {
        // Just show the command
        println!("{}", "━".repeat(60).dimmed());
        println!("{}", "Run this command to block:".green().bold());
        println!();
        println!(
            "  {}",
            format!("sudo iptables -I INPUT -s {} -j DROP", ip).white()
        );

        if args.ban_asn {
            if let Some(ref info) = host_info {
                if let Some(ref asn) = info.asn {
                    println!();
                    println!(
                        "  {}",
                        format!("# To block entire {}:", asn).dimmed()
                    );
                    println!(
                        "  {}",
                        format!("sudo ~/scripts/ban_as.sh {}", asn).white()
                    );
                }
            }
        }
        println!();
        return Ok(());
    }

    // Add to defend state
    if !state.blocked_ips.contains(&ip.to_string()) {
        state.blocked_ips.push(ip.to_string());
        println!("{} Added {} to block list", "✓".green(), ip.yellow());
    } else {
        println!("{} {} already in block list", "•".dimmed(), ip);
    }

    // Ban ASN if requested
    if args.ban_asn {
        if let Some(ref info) = host_info {
            if let Some(ref asn) = info.asn {
                if !state.blocked_asns.contains(asn) {
                    state.blocked_asns.push(asn.clone());
                    println!(
                        "{} Added {} to ASN block list",
                        "✓".green(),
                        asn.yellow()
                    );
                } else {
                    println!("{} {} already in ASN block list", "•".dimmed(), asn);
                }
            }
        }
    }

    state.save()?;

    println!();
    println!(
        "{}",
        "Generate firewall rules: i1 defend export --format iptables".dimmed()
    );

    Ok(())
}

impl Clone for ThreatArgs {
    fn clone(&self) -> Self {
        Self {
            ip: self.ip.clone(),
            ban: self.ban,
            ban_asn: self.ban_asn,
            yes: self.yes,
            execute: self.execute,
        }
    }
}
