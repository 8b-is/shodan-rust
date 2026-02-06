//! `i1` (no args) - Interactive security scan based on detected OS.

use anyhow::Result;
use colored::Colorize;
use std::io::Write;
use std::process::Command;

use super::Context;

pub async fn execute(ctx: Context) -> Result<()> {
    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .dimmed()
    );
    println!(
        "  {}  {}",
        "i1".cyan().bold(),
        "Security Operations CLI".dimmed()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .dimmed()
    );
    println!();

    // Detect OS
    let os = detect_os();
    let hostname = get_hostname();

    println!(
        "  {} {} on {}",
        "System:".bold(),
        os.name.cyan(),
        hostname.yellow()
    );

    // Get public IP
    print!("  {} ", "Public IP:".bold());
    std::io::stdout().flush()?;

    let my_ip = get_public_ip().await;
    match &my_ip {
        Some(ip) => println!("{}", ip.green()),
        None => println!("{}", "could not determine".dimmed()),
    }

    // Show defense status
    if let Ok(state) = crate::defend::State::load() {
        println!(
            "  {} {} blocked IPs, {} countries, {} ASNs",
            "Defense:".bold(),
            state.blocked_ips.len().to_string().red(),
            state.blocked_countries.len().to_string().red(),
            state.blocked_asns.len().to_string().red(),
        );
    }

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .dimmed()
    );
    println!("  {}", "What would you like to do?".bold());
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .dimmed()
    );
    println!();

    // Build menu based on OS capabilities
    let mut options: Vec<(&str, &str, &str)> = Vec::new();

    options.push((
        "s",
        "Security scan",
        "Scan this machine for open ports, services, and issues",
    ));

    if os.has_docker {
        options.push(("p", "Patrol logs", "Scan Docker/nginx logs for attackers"));
    }

    if os.has_iptables || os.has_nftables || os.has_pf {
        options.push(("f", "Firewall check", "Review current firewall rules"));
    }

    if my_ip.is_some() {
        options.push((
            "e",
            "External view",
            "See what Shodan/the internet sees about you",
        ));
    }

    options.push((
        "d",
        "Defense status",
        "Show all blocks, geoblocks, and whitelist",
    ));
    options.push(("q", "Quit", ""));

    for (key, label, desc) in &options {
        if desc.is_empty() {
            println!("  [{}] {}", key.dimmed(), label);
        } else {
            println!(
                "  [{}] {} - {}",
                key.cyan(),
                label.bold(),
                desc.dimmed()
            );
        }
    }

    println!();
    print!("{} ", "Choice:".cyan());
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim().to_lowercase();

    println!();

    match choice.as_str() {
        "s" => security_scan(&os).await,
        "p" if os.has_docker => patrol_scan().await,
        "f" => firewall_check(&os).await,
        "e" => external_view(&ctx, &my_ip).await,
        "d" => defense_status().await,
        "q" | "" => {
            println!("{}", "Bye!".dimmed());
            Ok(())
        }
        _ => {
            println!("{} Unknown option.", "?".yellow());
            Ok(())
        }
    }
}

struct OsInfo {
    name: String,
    is_macos: bool,
    has_docker: bool,
    has_iptables: bool,
    has_nftables: bool,
    has_pf: bool,
    has_fail2ban: bool,
    has_ss: bool,
}

fn detect_os() -> OsInfo {
    let uname = Command::new("uname").arg("-s").output().ok();
    let os_name = uname
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let is_linux = os_name == "Linux";
    let is_macos = os_name == "Darwin";

    let has =
        |cmd: &str| Command::new("which").arg(cmd).output().map(|o| o.status.success()).unwrap_or(false);

    OsInfo {
        name: if is_linux {
            Command::new("sh")
                .args([
                    "-c",
                    "cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d'\"' -f2",
                ])
                .output()
                .ok()
                .and_then(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if s.is_empty() {
                        None
                    } else {
                        Some(s)
                    }
                })
                .unwrap_or_else(|| "Linux".to_string())
        } else {
            os_name
        },
        is_macos,
        has_docker: has("docker"),
        has_iptables: has("iptables"),
        has_nftables: has("nft"),
        has_pf: has("pfctl"),
        has_fail2ban: has("fail2ban-client"),
        has_ss: has("ss"),
    }
}

fn get_hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn get_public_ip() -> Option<String> {
    reqwest::Client::new()
        .get("https://api.ipify.org")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()
        .map(|s| s.trim().to_string())
}

async fn security_scan(os: &OsInfo) -> Result<()> {
    println!("{}", "🔍 SECURITY SCAN".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // 1. Open ports
    println!("{}", "Open Ports:".bold());
    if os.has_ss {
        let output = Command::new("ss").args(["-tlnp"]).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut seen_ports: Vec<u16> = Vec::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let addr = parts[3];
                if let Some(port_str) = addr.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if seen_ports.contains(&port) {
                            continue;
                        }
                        seen_ports.push(port);

                        let is_local =
                            addr.starts_with("127.") || addr.starts_with("[::1]");
                        let binding = if is_local {
                            "localhost".dimmed().to_string()
                        } else {
                            "public".yellow().to_string()
                        };

                        let process = parts.get(5).unwrap_or(&"").to_string();

                        println!(
                            "  {} {:>5} ({}){}",
                            if is_local {
                                "✓".green()
                            } else {
                                "⚠".yellow()
                            },
                            port,
                            binding,
                            if process.is_empty() {
                                String::new()
                            } else {
                                format!(" {}", process.dimmed())
                            }
                        );
                    }
                }
            }
        }
    } else if os.is_macos {
        let output = Command::new("lsof")
            .args(["-iTCP", "-sTCP:LISTEN", "-nP"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1).take(20) {
            println!("  {}", line.dimmed());
        }
    }
    println!();

    // 2. SSH config
    println!("{}", "SSH:".bold());
    let ssh_config = std::path::Path::new("/etc/ssh/sshd_config");
    if ssh_config.exists() {
        let content = std::fs::read_to_string(ssh_config).unwrap_or_default();

        let port = content
            .lines()
            .find(|l| {
                let t = l.trim();
                t.starts_with("Port") && !t.starts_with('#')
            })
            .unwrap_or("Port 22");

        let root_login = content
            .lines()
            .find(|l| {
                let t = l.trim();
                t.starts_with("PermitRootLogin") && !t.starts_with('#')
            })
            .unwrap_or("PermitRootLogin (default)");

        let password_auth = content
            .lines()
            .find(|l| {
                let t = l.trim();
                t.starts_with("PasswordAuthentication") && !t.starts_with('#')
            })
            .unwrap_or("PasswordAuthentication (default)");

        if port.contains("22") && !port.contains("22") {
            println!(
                "  {} {} - consider a non-standard port",
                "⚠".yellow(),
                port
            );
        } else {
            println!("  {} {}", "✓".green(), port.trim());
        }

        if root_login.contains("yes") {
            println!(
                "  {} {} - disable root login",
                "✗".red(),
                root_login.trim()
            );
        } else if root_login.contains("prohibit-password")
            || root_login.contains("without-password")
        {
            println!("  {} {} (key-only)", "✓".green(), root_login.trim());
        } else {
            println!("  {} {}", "•".dimmed(), root_login.trim());
        }

        if password_auth.contains("yes") || password_auth.contains("default") {
            println!(
                "  {} {} - use key auth only",
                "⚠".yellow(),
                password_auth.trim()
            );
        } else {
            println!("  {} {}", "✓".green(), password_auth.trim());
        }
    } else {
        println!("  {} No sshd_config found", "•".dimmed());
    }
    println!();

    // 3. Firewall
    println!("{}", "Firewall:".bold());
    if os.has_iptables {
        let output = Command::new("sudo")
            .args(["iptables", "-L", "INPUT", "-n"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let drop_rules = stdout.lines().filter(|l| l.starts_with("DROP")).count();
            let accept_rules = stdout.lines().filter(|l| l.starts_with("ACCEPT")).count();
            println!(
                "  {} iptables: {} DROP rules, {} ACCEPT rules",
                if drop_rules > 0 {
                    "✓".green()
                } else {
                    "⚠".yellow()
                },
                drop_rules.to_string().red(),
                accept_rules.to_string().green()
            );
        }
    }
    if os.has_nftables {
        let output = Command::new("sudo")
            .args(["nft", "list", "tables"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let tables = stdout.lines().count();
            println!("  {} nftables: {} tables loaded", "✓".green(), tables);
        }
    }
    if os.has_pf {
        println!("  {} pf available (macOS/BSD)", "✓".green());
    }
    if !os.has_iptables && !os.has_nftables && !os.has_pf {
        println!("  {} No firewall detected!", "✗".red());
    }
    println!();

    // 4. Docker
    if os.has_docker {
        println!("{}", "Docker:".bold());
        let output = Command::new("docker")
            .args(["ps", "--format", "{{.Names}}: {{.Ports}}"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let containers: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
            println!("  {} {} running containers", "•".dimmed(), containers.len());
            for c in containers.iter().take(10) {
                println!("    {}", c.dimmed());
            }
            if containers.len() > 10 {
                println!("    ... and {} more", containers.len() - 10);
            }
        }
        println!();
    }

    // 5. Fail2ban
    if os.has_fail2ban {
        println!("{}", "Fail2ban:".bold());
        let output = Command::new("sudo")
            .args(["fail2ban-client", "status"])
            .output();
        if let Ok(out) = output {
            println!("  {} Active", "✓".green());
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                println!("    {}", line.dimmed());
            }
        }
        println!();
    }

    // Summary
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "Run patrol to find attackers: {} defend patrol run --dry-run",
        "i1".cyan()
    );

    Ok(())
}

async fn patrol_scan() -> Result<()> {
    println!("{}", "Running patrol scan...".cyan());
    println!();

    let status =
        Command::new(std::env::current_exe().unwrap_or_else(|_| "i1".into()))
            .args(["defend", "patrol", "run", "--dry-run"])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()?;

    if status.success() {
        println!();
        println!(
            "To apply bans: {} defend patrol run --execute",
            "i1".cyan()
        );
    }

    Ok(())
}

async fn firewall_check(os: &OsInfo) -> Result<()> {
    println!("{}", "🛡️ FIREWALL STATUS".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    if os.has_iptables {
        println!("{}", "iptables (IPv4):".bold());
        let output = Command::new("sudo")
            .args(["iptables", "-L", "INPUT", "-n"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let drop_count = stdout.lines().filter(|l| l.starts_with("DROP")).count();
        let accept_count = stdout
            .lines()
            .filter(|l| l.starts_with("ACCEPT"))
            .count();
        println!(
            "  {} DROP rules, {} ACCEPT rules",
            drop_count.to_string().red(),
            accept_count.to_string().green()
        );
        println!();

        println!("{}", "ip6tables (IPv6):".bold());
        let output = Command::new("sudo")
            .args(["ip6tables", "-L", "INPUT", "-n"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let drop_count = stdout.lines().filter(|l| l.starts_with("DROP")).count();
        let accept_count = stdout
            .lines()
            .filter(|l| l.starts_with("ACCEPT"))
            .count();
        println!(
            "  {} DROP rules, {} ACCEPT rules",
            drop_count.to_string().red(),
            accept_count.to_string().green()
        );
        println!();
    }

    if os.has_pf {
        println!("{}", "pf:".bold());
        let output = Command::new("sudo").args(["pfctl", "-sr"]).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules = stdout.lines().count();
        println!("  {} active rules", rules);
        println!();
    }

    if let Ok(state) = crate::defend::State::load() {
        println!("{}", "i1 Defend State:".bold());
        println!(
            "  Blocked IPs:      {}",
            state.blocked_ips.len().to_string().red()
        );
        println!(
            "  Blocked ASNs:     {}",
            state.blocked_asns.len().to_string().red()
        );
        println!(
            "  Blocked Countries: {}",
            state.blocked_countries.len().to_string().red()
        );
        println!(
            "  Whitelisted IPs:  {}",
            state.whitelisted_ips.len().to_string().green()
        );
    }

    Ok(())
}

async fn external_view(ctx: &Context, my_ip: &Option<String>) -> Result<()> {
    let ip = match my_ip {
        Some(ip) => ip.clone(),
        None => {
            println!("{} Could not determine public IP.", "Error:".red());
            return Ok(());
        }
    };

    println!("{}", "🌐 EXTERNAL VIEW - What the internet sees".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Look up our own IP on Shodan - show intel only, no ban prompt
    super::threat::lookup_only(ctx, &ip).await
}

async fn defense_status() -> Result<()> {
    let state = crate::defend::State::load()?;

    println!("{}", "🛡️ DEFENSE STATUS".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    println!(
        "  {} {}",
        "Blocked IPs:".bold(),
        state.blocked_ips.len().to_string().red()
    );
    for ip in state.blocked_ips.iter().take(10) {
        println!("    {}", ip.red());
    }
    if state.blocked_ips.len() > 10 {
        println!("    ... and {} more", state.blocked_ips.len() - 10);
    }
    println!();

    println!(
        "  {} {}",
        "Blocked ASNs:".bold(),
        state.blocked_asns.len().to_string().red()
    );
    for asn in &state.blocked_asns {
        println!("    {}", asn.red());
    }
    println!();

    println!(
        "  {} {}",
        "Blocked Countries:".bold(),
        state.blocked_countries.len().to_string().red()
    );
    for code in &state.blocked_countries {
        let name = crate::defend::country_name(code);
        println!("    {} - {}", code.to_uppercase().red(), name);
    }
    println!();

    println!(
        "  {} {}",
        "Whitelisted:".bold(),
        state.whitelisted_ips.len().to_string().green()
    );
    for ip in &state.whitelisted_ips {
        println!("    {}", ip.green());
    }

    Ok(())
}
