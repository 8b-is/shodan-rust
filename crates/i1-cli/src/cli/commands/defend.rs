//! `i1 defend` - Defensive tools: geo-blocking, IP bans, firewall rules.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{
    CommunityArgs, CommunityCommands, DefendArgs, DefendCommands, GeoblockArgs, GeoblockCommands,
    PatrolArgs, PatrolCommands, PullArgs, PushArgs, WhitelistArgs, WhitelistCommands,
};
use crate::defend;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: DefendArgs) -> Result<()> {
    match args.command {
        DefendCommands::Status { quick } => status(ctx, quick).await,
        DefendCommands::Geoblock(gb) => geoblock(ctx, gb).await,
        DefendCommands::Ban {
            target,
            as_number,
            dry_run,
        } => ban(ctx, &target, as_number, dry_run).await,
        DefendCommands::Unban { target } => unban(ctx, &target).await,
        DefendCommands::Whitelist(wl) => whitelist(ctx, wl).await,
        DefendCommands::Export { format } => export(ctx, &format).await,
        DefendCommands::Import { stdin, file } => import(ctx, stdin, file.as_deref()).await,
        DefendCommands::Undo => undo(ctx).await,
        DefendCommands::Disable => disable(ctx).await,
        DefendCommands::Push(args) => push(ctx, args).await,
        DefendCommands::Pull(args) => pull(ctx, args).await,
        DefendCommands::Community(args) => community(ctx, args).await,
        DefendCommands::Patrol(args) => patrol(ctx, args).await,
    }
}

async fn status(ctx: Context, quick: bool) -> Result<()> {
    let state = defend::State::load()?;

    if quick {
        println!(
            "Blocking {} countries (in), {} countries (out), {} IPs, {} ASNs | Whitelist: {} IPs",
            state.blocked_countries.len(),
            state.blocked_countries_outbound.len(),
            state.blocked_ips.len(),
            state.blocked_asns.len(),
            state.whitelisted_ips.len()
        );
        return Ok(());
    }

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&state)?);
        }
        _ => {
            println!("{}", "Defense Status".bold().underline());
            println!();

            // Countries (inbound)
            if state.blocked_countries.is_empty() {
                println!("{} None", "Blocked Countries (inbound):".bold());
            } else {
                println!("{}", "Blocked Countries (inbound):".bold());
                for code in &state.blocked_countries {
                    let name = defend::country_name(code);
                    println!("  {} - {}", code.to_uppercase().red(), name);
                }
            }
            println!();

            // Countries (outbound - honeypot mode)
            if !state.blocked_countries_outbound.is_empty() {
                println!(
                    "{} {}",
                    "Blocked Countries (outbound".bold(),
                    "- honeypot mode):".bold()
                );
                for code in &state.blocked_countries_outbound {
                    let name = defend::country_name(code);
                    println!("  {} - {} {}", code.to_uppercase().red(), name, "(no response)".dimmed());
                }
                println!();
            }

            // IPs
            println!(
                "{} {}",
                "Blocked IPs/Ranges:".bold(),
                state.blocked_ips.len()
            );
            for ip in state.blocked_ips.iter().take(10) {
                println!("  {}", ip.red());
            }
            if state.blocked_ips.len() > 10 {
                println!("  ... and {} more", state.blocked_ips.len() - 10);
            }
            println!();

            // ASNs
            println!("{} {}", "Blocked ASNs:".bold(), state.blocked_asns.len());
            for asn in state.blocked_asns.iter().take(5) {
                println!("  {}", asn.red());
            }
            println!();

            // Whitelist
            println!(
                "{} {}",
                "Whitelisted IPs:".bold(),
                state.whitelisted_ips.len()
            );
            for ip in &state.whitelisted_ips {
                println!("  {}", ip.green());
            }
            println!();

            // Tip
            println!(
                "{}",
                "Use 'defend export' to generate firewall rules.".dimmed()
            );
        }
    }

    Ok(())
}

async fn geoblock(_ctx: Context, args: GeoblockArgs) -> Result<()> {
    match args.command {
        GeoblockCommands::List => {
            let state = defend::State::load()?;
            let has_inbound = !state.blocked_countries.is_empty();
            let has_outbound = !state.blocked_countries_outbound.is_empty();

            if !has_inbound && !has_outbound {
                println!("No countries currently blocked.");
                println!();
                println!(
                    "Block countries with: {} defend geoblock add cn ru",
                    "i1".cyan()
                );
                println!(
                    "Honeypot mode:       {} defend geoblock add cn ru -d outbound",
                    "i1".cyan()
                );
            } else {
                if has_inbound {
                    println!("{}", "Blocked Countries (inbound):".bold());
                    for code in &state.blocked_countries {
                        let name = defend::country_name(code);
                        println!("  {} - {}", code.to_uppercase().red(), name);
                    }
                    println!();
                }
                if has_outbound {
                    println!(
                        "{} {}",
                        "Blocked Countries (outbound".bold(),
                        "- honeypot mode):".bold()
                    );
                    for code in &state.blocked_countries_outbound {
                        let name = defend::country_name(code);
                        println!("  {} - {} {}", code.to_uppercase().red(), name, "(no response)".dimmed());
                    }
                }
            }
            Ok(())
        }
        GeoblockCommands::Add {
            countries,
            direction,
            dry_run,
        } => {
            let mut state = defend::State::load()?;
            let mut added = Vec::new();
            let dir = direction.to_lowercase();

            let block_inbound = dir == "inbound" || dir == "both";
            let block_outbound = dir == "outbound" || dir == "both";

            if !block_inbound && !block_outbound {
                anyhow::bail!(
                    "Invalid direction: {}\nUse: inbound, outbound, or both",
                    direction
                );
            }

            for code in &countries {
                let normalized = code.to_lowercase();
                if block_inbound && !state.blocked_countries.contains(&normalized) {
                    state.blocked_countries.push(normalized.clone());
                    added.push(format!("{} (inbound)", normalized));
                }
                if block_outbound && !state.blocked_countries_outbound.contains(&normalized) {
                    state.blocked_countries_outbound.push(normalized.clone());
                    added.push(format!("{} (outbound)", normalized));
                }
            }

            if added.is_empty() {
                println!("All specified countries are already blocked.");
                return Ok(());
            }

            if dry_run {
                println!("{}", "[DRY RUN]".yellow().bold());
                println!("Would block: {}", added.join(", ").red());
                println!();
                println!("Run without --dry-run to apply.");
            } else {
                state.save()?;
                println!(
                    "{} Now blocking: {}",
                    "Success:".green().bold(),
                    added.join(", ").red()
                );
                if block_outbound {
                    println!();
                    println!(
                        "{}",
                        "Honeypot mode: they can connect in, but nothing goes back out."
                            .yellow()
                    );
                }
                println!();
                println!("Generate rules with: {} defend export", "i1".cyan());
            }

            Ok(())
        }
        GeoblockCommands::Remove {
            country,
            direction,
        } => {
            let mut state = defend::State::load()?;
            let normalized = country.to_lowercase();
            let dir = direction.to_lowercase();
            let mut removed = false;

            if dir == "inbound" || dir == "both" {
                if let Some(pos) = state
                    .blocked_countries
                    .iter()
                    .position(|c| c == &normalized)
                {
                    state.blocked_countries.remove(pos);
                    removed = true;
                }
            }

            if dir == "outbound" || dir == "both" {
                if let Some(pos) = state
                    .blocked_countries_outbound
                    .iter()
                    .position(|c| c == &normalized)
                {
                    state.blocked_countries_outbound.remove(pos);
                    removed = true;
                }
            }

            if removed {
                state.save()?;
                println!(
                    "{} Removed {} from blocked countries ({}).",
                    "Success:".green().bold(),
                    country.to_uppercase().cyan(),
                    dir
                );
            } else {
                println!(
                    "Country {} is not currently blocked ({}).",
                    country.to_uppercase(),
                    dir
                );
            }

            Ok(())
        }
        GeoblockCommands::Update => {
            println!("Updating IP ranges from ipdeny.com...");
            println!();
            println!(
                "{}",
                "This feature will download fresh IP ranges for blocked countries.".dimmed()
            );
            println!("{}", "Coming soon!".yellow());
            Ok(())
        }
        GeoblockCommands::Codes => {
            println!("{}", "Country Codes Reference".bold().underline());
            println!();
            println!("{}", "Common attack sources:".bold());
            println!(
                "  {} - China         {} - Russia        {} - Romania",
                "cn".red(),
                "ru".red(),
                "ro".red()
            );
            println!(
                "  {} - Poland        {} - Kazakhstan    {} - Ukraine",
                "pl".red(),
                "kz".red(),
                "ua".red()
            );
            println!(
                "  {} - Vietnam       {} - Brazil        {} - India",
                "vn".red(),
                "br".red(),
                "in".red()
            );
            println!(
                "  {} - South Korea   {} - Thailand      {} - Indonesia",
                "kr".yellow(),
                "th".yellow(),
                "id".yellow()
            );
            println!();
            println!(
                "Full list: {}",
                "https://www.ipdeny.com/ipblocks/".cyan().underline()
            );
            println!();
            println!(
                "Learn more: {}",
                "https://cheet.is/security/geoblock/countries".dimmed()
            );
            Ok(())
        }
    }
}

async fn ban(_ctx: Context, target: &str, as_number: bool, dry_run: bool) -> Result<()> {
    // Safety check: refuse to block your own SSH session
    if let Some(ssh_ip) = get_ssh_client_ip() {
        if target == ssh_ip || target.starts_with(&format!("{}/", ssh_ip)) {
            println!(
                "{} Refusing to block {} - that's your current SSH session!",
                "🛡️ PROTECTED:".yellow().bold(),
                target.cyan()
            );
            println!();
            println!(
                "{}",
                "This prevents you from locking yourself out.".dimmed()
            );
            return Ok(());
        }
    }

    let mut state = defend::State::load()?;

    if as_number {
        // Ban AS number
        let asn = target.trim_start_matches("AS").trim_start_matches("as");
        if dry_run {
            println!("{} Would block AS{}", "[DRY RUN]".yellow().bold(), asn);
        } else {
            state.blocked_asns.push(format!("AS{asn}"));
            state.save()?;
            println!("{} Blocked AS{}", "Success:".green().bold(), asn.red());
        }
    } else {
        // Ban IP or CIDR
        if dry_run {
            println!("{} Would block {}", "[DRY RUN]".yellow().bold(), target);
        } else {
            state.blocked_ips.push(target.to_string());
            state.save()?;
            println!("{} Blocked {}", "Success:".green().bold(), target.red());
        }
    }

    println!();
    println!("Generate rules with: {} defend export", "i1".cyan());

    Ok(())
}

async fn unban(_ctx: Context, target: &str) -> Result<()> {
    let mut state = defend::State::load()?;

    // Check if it's an ASN
    if target.to_uppercase().starts_with("AS") {
        if let Some(pos) = state
            .blocked_asns
            .iter()
            .position(|a| a.eq_ignore_ascii_case(target))
        {
            state.blocked_asns.remove(pos);
            state.save()?;
            println!("{} Unblocked {}", "Success:".green().bold(), target.cyan());
            return Ok(());
        }
    }

    // Check IPs
    if let Some(pos) = state.blocked_ips.iter().position(|i| i == target) {
        state.blocked_ips.remove(pos);
        state.save()?;
        println!("{} Unblocked {}", "Success:".green().bold(), target.cyan());
        return Ok(());
    }

    println!("{} {} is not currently blocked.", "Note:".yellow(), target);
    Ok(())
}

async fn whitelist(_ctx: Context, args: WhitelistArgs) -> Result<()> {
    match args.command {
        WhitelistCommands::Show => {
            let state = defend::State::load()?;
            if state.whitelisted_ips.is_empty() {
                println!("No IPs whitelisted.");
            } else {
                println!("{}", "Whitelisted IPs:".bold());
                for ip in &state.whitelisted_ips {
                    println!("  {}", ip.green());
                }
            }
            Ok(())
        }
        WhitelistCommands::Add { ip } => {
            let mut state = defend::State::load()?;
            if state.whitelisted_ips.contains(&ip) {
                println!("{ip} is already whitelisted.");
            } else {
                state.whitelisted_ips.push(ip.clone());
                state.save()?;
                println!(
                    "{} Added {} to whitelist.",
                    "Success:".green().bold(),
                    ip.green()
                );
            }
            Ok(())
        }
        WhitelistCommands::Remove { ip } => {
            let mut state = defend::State::load()?;
            if let Some(pos) = state.whitelisted_ips.iter().position(|i| i == &ip) {
                state.whitelisted_ips.remove(pos);
                state.save()?;
                println!(
                    "{} Removed {} from whitelist.",
                    "Success:".green().bold(),
                    ip
                );
            } else {
                println!("{ip} is not in the whitelist.");
            }
            Ok(())
        }
    }
}

async fn export(_ctx: Context, format: &str) -> Result<()> {
    let state = defend::State::load()?;

    match format.to_lowercase().as_str() {
        "nftables" | "nft" => {
            let rules = defend::generate_nftables(&state)?;
            println!("{rules}");
        }
        "iptables" | "ipt" => {
            let rules = defend::generate_iptables(&state)?;
            println!("{rules}");
        }
        "pf" => {
            let rules = defend::generate_pf(&state)?;
            println!("{rules}");
        }
        _ => {
            anyhow::bail!(
                "Unknown format: {format}\n\n\
                 Supported formats:\n  \
                 nftables  - Linux nftables (recommended)\n  \
                 iptables  - Legacy iptables\n  \
                 pf        - BSD/macOS pf"
            );
        }
    }

    Ok(())
}

async fn import(_ctx: Context, stdin: bool, file: Option<&str>) -> Result<()> {
    println!("{}", "Import feature coming soon!".yellow());
    println!();
    println!("This will allow importing IPs from:");
    if stdin {
        println!("  - Standard input (pipe from other commands)");
    }
    if let Some(f) = file {
        println!("  - File: {f}");
    }
    Ok(())
}

async fn undo(_ctx: Context) -> Result<()> {
    println!("{}", "Undo feature coming soon!".yellow());
    println!();
    println!("This will revert the last change to defense settings.");
    Ok(())
}

async fn disable(_ctx: Context) -> Result<()> {
    println!("{}", "EMERGENCY DISABLE".red().bold());
    println!();
    println!("This would remove all blocking rules immediately.");
    println!();
    println!("On Linux, run:");
    println!("  {}", "nft delete table inet geoblock".cyan());
    println!();
    println!("This is a safety feature - not applying automatically.");
    Ok(())
}

async fn push(_ctx: Context, args: PushArgs) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let state = defend::State::load()?;

    // Get current user's public IP to auto-whitelist
    let my_ip = get_my_public_ip().await.ok();

    // Parse SSH config
    let ssh_config_path = shellexpand::tilde("~/.ssh/config").to_string();
    let hosts = parse_ssh_config(&ssh_config_path)?;

    if hosts.is_empty() {
        println!("{} No hosts found in ~/.ssh/config", "Error:".red().bold());
        println!();
        println!("Add hosts to your SSH config like:");
        println!("  Host myserver");
        println!("    HostName 1.2.3.4");
        println!("    User root");
        return Ok(());
    }

    // Determine which hosts to push to
    let selected_hosts: Vec<String> = if let Some(ref specific) = args.hosts {
        // Use specified hosts
        specific
            .iter()
            .filter(|h| hosts.contains(h))
            .cloned()
            .collect()
    } else if args.all {
        // Use all hosts
        hosts.clone()
    } else {
        // Interactive selection
        println!("{}", "Available SSH hosts:".bold());
        for (i, host) in hosts.iter().enumerate() {
            println!("  [{}] {}", i + 1, host.cyan());
        }
        println!("  [a] All hosts");
        println!("  [q] Quit");
        println!();

        print!("{} ", "Select hosts (e.g., 1,2,3 or 'a' for all):".cyan());
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input == "q" || input.is_empty() {
            println!("{}", "Cancelled.".dimmed());
            return Ok(());
        }

        if input == "a" {
            hosts.clone()
        } else {
            input
                .split(',')
                .filter_map(|s| s.trim().parse::<usize>().ok())
                .filter_map(|i| hosts.get(i.saturating_sub(1)).cloned())
                .collect()
        }
    };

    if selected_hosts.is_empty() {
        println!("{} No valid hosts selected.", "Error:".red().bold());
        return Ok(());
    }

    // Build iptables commands
    let mut commands: Vec<String> = Vec::new();

    // Always whitelist the user's IP first!
    if let Some(ref ip) = my_ip {
        commands.push(format!(
            "iptables -C INPUT -s {} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s {} -j ACCEPT",
            ip, ip
        ));
    }

    // Add blocked IPs
    for ip in &state.blocked_ips {
        commands.push(format!(
            "iptables -C INPUT -s {} -j DROP 2>/dev/null || iptables -I INPUT -s {} -j DROP",
            ip, ip
        ));
    }

    // Add whitelisted IPs at the top
    for ip in &state.whitelisted_ips {
        commands.push(format!(
            "iptables -C INPUT -s {} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s {} -j ACCEPT",
            ip, ip
        ));
    }

    if commands.is_empty() {
        println!("{} No rules to push.", "Note:".yellow());
        return Ok(());
    }

    let script = commands.join(" && ");

    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{} {} host(s)",
        "Pushing to".green().bold(),
        selected_hosts.len()
    );
    if let Some(ref ip) = my_ip {
        println!(
            "{} Your IP {} will be whitelisted first",
            "✓".green(),
            ip.yellow()
        );
    }
    println!(
        "{} {} blocked IPs",
        "•".dimmed(),
        state.blocked_ips.len()
    );
    println!(
        "{} {} whitelisted IPs",
        "•".dimmed(),
        state.whitelisted_ips.len()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    if args.dry_run {
        println!("{}", "[DRY RUN] Would execute:".yellow().bold());
        println!();
        for host in &selected_hosts {
            println!("ssh {} '{}'", host.cyan(), script.dimmed());
            println!();
        }
        return Ok(());
    }

    // Execute on each host
    for host in &selected_hosts {
        print!("{} {}... ", "→".cyan(), host);
        std::io::stdout().flush()?;

        let output = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(host)
            .arg(&script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(out) if out.status.success() => {
                println!("{}", "✓".green());
            }
            Ok(out) => {
                println!("{}", "✗".red());
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.is_empty() {
                    println!("    {}", stderr.trim().dimmed());
                }
            }
            Err(e) => {
                println!("{} {}", "✗".red(), e.to_string().dimmed());
            }
        }
    }

    println!();
    println!("{}", "Done!".green().bold());

    Ok(())
}

/// Parse SSH config and extract host names
fn parse_ssh_config(path: &str) -> Result<Vec<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(Vec::new()),
    };

    let reader = BufReader::new(file);
    let mut hosts = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Look for "Host" entries (but not "Host *")
        if let Some(host_part) = line.strip_prefix("Host ").or_else(|| line.strip_prefix("Host\t"))
        {
            let host = host_part.trim();
            // Skip wildcards and patterns
            if !host.contains('*') && !host.contains('?') && !host.contains(' ') {
                hosts.push(host.to_string());
            }
        }
    }

    Ok(hosts)
}

/// Get current public IP address
async fn get_my_public_ip() -> Result<String> {
    let client = reqwest::Client::new();
    let ip = client
        .get("https://api.ipify.org")
        .send()
        .await?
        .text()
        .await?;
    Ok(ip.trim().to_string())
}

/// Get the IP of the current SSH session (if any)
fn get_ssh_client_ip() -> Option<String> {
    // SSH_CLIENT format: "client_ip client_port server_port"
    // SSH_CONNECTION format: "client_ip client_port server_ip server_port"
    std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .ok()
        .and_then(|s| s.split_whitespace().next().map(String::from))
}

async fn pull(_ctx: Context, args: PullArgs) -> Result<()> {
    use std::process::{Command, Stdio};

    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{} {}",
        "Pulling blocks from:".cyan().bold(),
        args.host.yellow()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // SSH to remote and get iptables rules
    print!("{} Fetching iptables rules... ", "→".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let output = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg(&args.host)
        .arg("iptables -L INPUT -n 2>/dev/null; ip6tables -L INPUT -n 2>/dev/null")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        println!("{}", "✗".red());
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("SSH failed: {}", stderr.trim());
    }

    println!("{}", "✓".green());

    let rules_output = String::from_utf8_lossy(&output.stdout);

    // Parse the iptables output to extract blocked IPs
    let mut blocked_ips: Vec<String> = Vec::new();
    let mut whitelisted_ips: Vec<String> = Vec::new();

    for line in rules_output.lines() {
        let line = line.trim();

        // Look for DROP rules with source IP
        // Format: "DROP       all  --  1.2.3.4              0.0.0.0/0"
        if line.starts_with("DROP") {
            if let Some(ip) = extract_source_ip(line) {
                if !blocked_ips.contains(&ip) && ip != "0.0.0.0/0" && ip != "::/0" {
                    blocked_ips.push(ip);
                }
            }
        }

        // Look for ACCEPT rules (whitelist) - only from specific IPs, not 0.0.0.0/0
        if line.starts_with("ACCEPT") && !line.contains("state") && !line.contains("ctstate") {
            if let Some(ip) = extract_source_ip(line) {
                if !whitelisted_ips.contains(&ip)
                    && ip != "0.0.0.0/0"
                    && ip != "::/0"
                    && !ip.starts_with("127.")
                {
                    whitelisted_ips.push(ip);
                }
            }
        }
    }

    println!();
    println!("{}", "Found:".bold());
    println!("  {} blocked IPs/ranges", blocked_ips.len().to_string().red());
    println!(
        "  {} whitelisted IPs",
        whitelisted_ips.len().to_string().green()
    );
    println!();

    if blocked_ips.is_empty() && whitelisted_ips.is_empty() {
        println!("{}", "No rules found to import.".yellow());
        return Ok(());
    }

    // Show preview
    if !blocked_ips.is_empty() {
        println!("{}", "Blocked IPs (first 10):".bold());
        for ip in blocked_ips.iter().take(10) {
            println!("  {}", ip.red());
        }
        if blocked_ips.len() > 10 {
            println!("  ... and {} more", blocked_ips.len() - 10);
        }
        println!();
    }

    if !whitelisted_ips.is_empty() {
        println!("{}", "Whitelisted IPs:".bold());
        for ip in &whitelisted_ips {
            println!("  {}", ip.green());
        }
        println!();
    }

    if args.dry_run {
        println!("{}", "[DRY RUN] Would import the above rules.".yellow());
        println!("Run without --dry-run to save.");
        return Ok(());
    }

    // Load current state and merge/replace
    let mut state = defend::State::load()?;

    if args.merge {
        // Merge with existing
        for ip in blocked_ips {
            if !state.blocked_ips.contains(&ip) {
                state.blocked_ips.push(ip);
            }
        }
        for ip in whitelisted_ips {
            if !state.whitelisted_ips.contains(&ip) {
                state.whitelisted_ips.push(ip);
            }
        }
        println!("{} Merged rules with existing state.", "✓".green());
    } else {
        // Replace
        state.blocked_ips = blocked_ips;
        state.whitelisted_ips = whitelisted_ips;
        println!("{} Replaced local state with remote rules.", "✓".green());
    }

    state.save()?;

    println!();
    println!(
        "{}",
        "Done! Use 'i1 defend status' to see current state.".dimmed()
    );

    Ok(())
}

async fn community(_ctx: Context, args: CommunityArgs) -> Result<()> {
    match args.command {
        CommunityCommands::Contribute {
            fail2ban,
            min_hits,
            dry_run,
        } => community_contribute(fail2ban, min_hits, dry_run).await,
        CommunityCommands::Fetch {
            min_reports,
            replace,
            dry_run,
        } => community_fetch(min_reports, replace, dry_run).await,
        CommunityCommands::Subscribe { interval, remove } => {
            community_subscribe(interval, remove).await
        }
        CommunityCommands::Stats => community_stats().await,
    }
}

/// Community API base URL
const COMMUNITY_API: &str = "https://api.i1.is/v1/community";

async fn community_contribute(fail2ban: bool, min_hits: u32, dry_run: bool) -> Result<()> {
    use std::collections::HashMap;
    use std::process::Command;

    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{}",
        "🌐 COMMUNITY THREAT SHARING".cyan().bold()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    let mut ips_to_contribute: HashMap<String, u32> = HashMap::new();

    // Get IPs from local i1 state
    let state = defend::State::load()?;
    for ip in &state.blocked_ips {
        *ips_to_contribute.entry(ip.clone()).or_insert(0) += 1;
    }

    // Get IPs from fail2ban if requested
    if fail2ban {
        print!("{} Scanning fail2ban... ", "→".cyan());
        std::io::Write::flush(&mut std::io::stdout())?;

        // Try to get banned IPs from fail2ban
        let output = Command::new("fail2ban-client")
            .args(["banned"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Parse fail2ban output - format varies but usually lists IPs
                for line in stdout.lines() {
                    // Extract IPs from the line
                    for word in line.split(|c: char| !c.is_ascii_digit() && c != '.') {
                        if is_valid_ip(word) {
                            *ips_to_contribute.entry(word.to_string()).or_insert(0) += 1;
                        }
                    }
                }
                println!("{}", "✓".green());
            }
            Ok(_) => {
                // Try alternative: parse fail2ban log directly
                let log_output = Command::new("sh")
                    .args(["-c", "grep -h 'Ban' /var/log/fail2ban.log* 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn"])
                    .output();

                if let Ok(log_out) = log_output {
                    let stdout = String::from_utf8_lossy(&log_out.stdout);
                    for line in stdout.lines() {
                        let parts: Vec<&str> = line.trim().split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(count) = parts[0].parse::<u32>() {
                                let ip = parts[1];
                                if is_valid_ip(ip) {
                                    *ips_to_contribute.entry(ip.to_string()).or_insert(0) += count;
                                }
                            }
                        }
                    }
                    println!("{} (from logs)", "✓".green());
                } else {
                    println!("{} (not available)", "⚠".yellow());
                }
            }
            Err(_) => {
                println!("{} (not installed)", "⚠".yellow());
            }
        }
    }

    // Filter by minimum hits
    let filtered: Vec<(String, u32)> = ips_to_contribute
        .into_iter()
        .filter(|(_, count)| *count >= min_hits)
        .collect();

    if filtered.is_empty() {
        println!();
        println!(
            "{} No IPs meet the minimum threshold of {} hits.",
            "Note:".yellow(),
            min_hits
        );
        println!("Try lowering --min-hits or add --fail2ban to include fail2ban data.");
        return Ok(());
    }

    println!();
    println!(
        "{} {} IPs ready to contribute (min {} hits each)",
        "Found:".bold(),
        filtered.len().to_string().green(),
        min_hits
    );
    println!();

    // Show top offenders
    let mut sorted = filtered.clone();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    println!("{}", "Top offenders:".bold());
    for (ip, count) in sorted.iter().take(10) {
        println!("  {} (blocked {} times)", ip.red(), count);
    }
    if sorted.len() > 10 {
        println!("  ... and {} more", sorted.len() - 10);
    }
    println!();

    if dry_run {
        println!("{}", "[DRY RUN] Would contribute the above IPs.".yellow());
        println!("Run without --dry-run to share with the community.");
        return Ok(());
    }

    // Submit to community API
    print!("{} Submitting to community... ", "→".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let client = reqwest::Client::new();
    let payload: Vec<_> = sorted.iter().map(|(ip, count)| {
        serde_json::json!({
            "ip": ip,
            "reports": count
        })
    }).collect();

    match client
        .post(format!("{}/contribute", COMMUNITY_API))
        .json(&serde_json::json!({
            "ips": payload,
            "source": "i1-cli",
            "version": env!("CARGO_PKG_VERSION")
        }))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("{}", "✓".green());
            println!();
            println!(
                "{} Thank you for contributing to community security!",
                "🎉".green()
            );
        }
        Ok(resp) => {
            println!("{}", "✗".red());
            println!(
                "Server returned: {} (API may not be live yet)",
                resp.status()
            );
        }
        Err(_) => {
            println!("{}", "⚠".yellow());
            println!();
            println!(
                "{}",
                "Community API not available yet - coming soon!".yellow()
            );
            println!("Your IPs have been saved locally. Once the API is live,");
            println!("run this command again to contribute.");
        }
    }

    Ok(())
}

async fn community_fetch(min_reports: u32, replace: bool, dry_run: bool) -> Result<()> {
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{}",
        "🌐 FETCHING COMMUNITY BLOCKLIST".cyan().bold()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    print!("{} Fetching from community... ", "→".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let client = reqwest::Client::new();

    match client
        .get(format!("{}/blocklist?min_reports={}", COMMUNITY_API, min_reports))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("{}", "✓".green());

            let data: serde_json::Value = resp.json().await?;
            let ips: Vec<String> = data["ips"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v["ip"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            println!();
            println!(
                "{} {} IPs from community (min {} reports)",
                "Received:".bold(),
                ips.len().to_string().green(),
                min_reports
            );

            if ips.is_empty() {
                println!("No IPs meet the minimum report threshold.");
                return Ok(());
            }

            // Show preview
            println!();
            println!("{}", "Preview (first 10):".bold());
            for ip in ips.iter().take(10) {
                println!("  {}", ip.red());
            }
            if ips.len() > 10 {
                println!("  ... and {} more", ips.len() - 10);
            }

            if dry_run {
                println!();
                println!("{}", "[DRY RUN] Would import the above IPs.".yellow());
                return Ok(());
            }

            // Save to state
            let mut state = defend::State::load()?;

            if replace {
                state.blocked_ips = ips;
                println!();
                println!("{} Replaced local blocklist with community list.", "✓".green());
            } else {
                let mut added = 0;
                for ip in ips {
                    if !state.blocked_ips.contains(&ip) {
                        state.blocked_ips.push(ip);
                        added += 1;
                    }
                }
                println!();
                println!("{} Added {} new IPs from community.", "✓".green(), added);
            }

            state.save()?;
        }
        Ok(resp) => {
            println!("{}", "✗".red());
            println!("Server returned: {}", resp.status());
        }
        Err(_) => {
            println!("{}", "⚠".yellow());
            println!();
            println!(
                "{}",
                "Community API not available yet - coming soon!".yellow()
            );
            println!();
            println!("In the meantime, you can manually share blocklists:");
            println!("  {} defend export --format json > blocklist.json", "i1".cyan());
            println!("  # Share blocklist.json with others");
        }
    }

    Ok(())
}

async fn community_subscribe(interval: u32, remove: bool) -> Result<()> {
    use std::process::Command;

    let i1_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("i1"));

    let cron_comment = "# i1 community threat sync";
    let cron_command = format!(
        "{} defend community fetch --min-reports 10 2>/dev/null",
        i1_path.display()
    );

    if remove {
        // Remove the cron job
        print!("{} Removing cron job... ", "→".cyan());
        std::io::Write::flush(&mut std::io::stdout())?;

        let output = Command::new("crontab")
            .arg("-l")
            .output();

        if let Ok(out) = output {
            let current = String::from_utf8_lossy(&out.stdout);
            let new_crontab: String = current
                .lines()
                .filter(|line| !line.contains("i1 defend community"))
                .filter(|line| !line.contains(cron_comment))
                .collect::<Vec<_>>()
                .join("\n");

            let mut child = Command::new("crontab")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                stdin.write_all(new_crontab.as_bytes())?;
                stdin.write_all(b"\n")?;
            }
            child.wait()?;

            println!("{}", "✓".green());
            println!("Community sync cron job removed.");
        } else {
            println!("{}", "✗".red());
            println!("Could not access crontab.");
        }

        return Ok(());
    }

    // Add the cron job
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{}",
        "🕐 SETTING UP COMMUNITY SYNC".cyan().bold()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Calculate cron schedule based on interval
    let cron_schedule = match interval {
        1 => "0 * * * *".to_string(),      // Every hour
        2 => "0 */2 * * *".to_string(),    // Every 2 hours
        6 => "0 */6 * * *".to_string(),    // Every 6 hours
        12 => "0 */12 * * *".to_string(),  // Every 12 hours
        24 => "0 0 * * *".to_string(),     // Daily
        _ => format!("0 */{} * * *", interval), // Custom
    };

    let cron_line = format!("{} {}", cron_schedule, cron_command);

    println!("Will add to crontab:");
    println!("  {}", cron_line.dimmed());
    println!();

    // Check if already exists
    let existing = Command::new("crontab").arg("-l").output();
    let mut current_crontab = String::new();

    if let Ok(out) = existing {
        current_crontab = String::from_utf8_lossy(&out.stdout).to_string();
        if current_crontab.contains("i1 defend community") {
            println!(
                "{} Cron job already exists. Use --remove to delete it first.",
                "Note:".yellow()
            );
            return Ok(());
        }
    }

    // Add to crontab
    print!("{} Adding to crontab... ", "→".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        if !current_crontab.is_empty() {
            stdin.write_all(current_crontab.as_bytes())?;
            if !current_crontab.ends_with('\n') {
                stdin.write_all(b"\n")?;
            }
        }
        stdin.write_all(cron_comment.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(cron_line.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    child.wait()?;
    println!("{}", "✓".green());

    println!();
    println!("{}", "Community sync enabled!".green().bold());
    println!("Your blocklist will sync every {} hours.", interval);
    println!();
    println!("To contribute your blocks back:");
    println!("  {} defend community contribute --fail2ban", "i1".cyan());
    println!();
    println!("To remove this cron job:");
    println!("  {} defend community subscribe --remove", "i1".cyan());

    Ok(())
}

async fn community_stats() -> Result<()> {
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "{}",
        "🌐 COMMUNITY THREAT INTELLIGENCE".cyan().bold()
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    print!("{} Fetching stats... ", "→".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let client = reqwest::Client::new();

    match client.get(format!("{}/stats", COMMUNITY_API)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("{}", "✓".green());
            println!();

            let stats: serde_json::Value = resp.json().await?;

            println!("{}", "Community Statistics:".bold());
            println!(
                "  Total blocked IPs:     {}",
                stats["total_ips"]
                    .as_u64()
                    .unwrap_or(0)
                    .to_string()
                    .green()
            );
            println!(
                "  Active contributors:   {}",
                stats["contributors"]
                    .as_u64()
                    .unwrap_or(0)
                    .to_string()
                    .cyan()
            );
            println!(
                "  Reports today:         {}",
                stats["reports_today"]
                    .as_u64()
                    .unwrap_or(0)
                    .to_string()
                    .yellow()
            );
            println!(
                "  Most reported ASN:     {}",
                stats["top_asn"].as_str().unwrap_or("N/A")
            );
            println!(
                "  Most reported country: {}",
                stats["top_country"].as_str().unwrap_or("N/A")
            );
        }
        Ok(_) | Err(_) => {
            println!("{}", "⚠".yellow());
            println!();
            println!(
                "{}",
                "Community API coming soon!".yellow().bold()
            );
            println!();
            println!("The i1 community threat sharing network will allow:");
            println!("  • {} - Share your blocked IPs", "Contribute".green());
            println!("  • {} - Get crowd-sourced blocklists", "Fetch".cyan());
            println!("  • {} - Auto-sync via cron", "Subscribe".yellow());
            println!();
            println!("Local stats:");

            let state = defend::State::load()?;
            println!("  Your blocked IPs:  {}", state.blocked_ips.len());
            println!("  Your blocked ASNs: {}", state.blocked_asns.len());
            println!("  Blocked countries: {}", state.blocked_countries.len());
            println!();
            println!("Share this project: {}", "https://github.com/...".cyan().underline());
        }
    }

    Ok(())
}

async fn patrol(_ctx: Context, args: PatrolArgs) -> Result<()> {
    match args.command {
        PatrolCommands::Run {
            threshold,
            window,
            dry_run,
            compose_dir,
            execute,
        } => patrol_run(threshold, window, dry_run, compose_dir, execute).await,
        PatrolCommands::Cron {
            interval,
            remove,
            threshold,
        } => patrol_cron(interval, remove, threshold).await,
        PatrolCommands::Log { lines } => patrol_log(lines).await,
    }
}

/// Suspicious patterns that indicate an attacker
const ATTACK_PATTERNS: &[&str] = &[
    // Webshell scanning
    ".php",
    // WordPress exploits
    "wp-content",
    "wp-admin",
    "wp-login",
    "wp-includes",
    "xmlrpc.php",
    // Common exploit paths
    ".env",
    "/.git/",
    "/config",
    "/admin",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/pma",
    "/myadmin",
    // Shell/backdoor attempts
    "/shell",
    "/cmd",
    "/eval",
    "/exec",
    "cgi-bin",
    // Scanner fingerprints
    "/actuator",
    "/api/v1",
    "/.well-known/security.txt",
    "/solr/",
    "/console",
    "/manager/html",
    // Path traversal
    "../",
    "..%2f",
    "%00",
];

/// IPs/ranges to never ban (health checks, internal, etc.)
const PATROL_NEVER_BAN: &[&str] = &[
    "127.0.0.1",
    "172.22.",   // Docker internal IPv4
    "10.",
    "192.168.",
    "fd4d:",     // Docker internal IPv6 (ULA)
    "fc",        // IPv6 ULA prefix
    "fd",        // IPv6 ULA prefix
    "fe80:",     // Link-local
    "::1",       // IPv6 loopback
];

struct PatrolHit {
    ip: String,
    total_requests: u32,
    attack_hits: u32,
    four04_hits: u32,
    sample_paths: Vec<String>,
}

async fn patrol_run(
    threshold: u32,
    window: u32,
    dry_run: bool,
    compose_dir: Option<String>,
    execute: bool,
) -> Result<()> {
    use std::collections::HashMap;
    use std::process::Command;

    println!("{}", "━".repeat(60).dimmed());
    println!("{}", "🔍 PATROL - Scanning for attackers".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "  Window: {} min | Threshold: {} hits | {}",
        window,
        threshold,
        if dry_run {
            "DRY RUN".yellow().to_string()
        } else {
            "LIVE".green().to_string()
        }
    );
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Load current state to know what's already banned
    let state = defend::State::load()?;
    let already_banned: std::collections::HashSet<&str> =
        state.blocked_ips.iter().map(|s| s.as_str()).collect();
    let whitelisted: std::collections::HashSet<&str> =
        state.whitelisted_ips.iter().map(|s| s.as_str()).collect();

    let since_arg = format!("{}m", window);
    let mut all_logs = String::new();
    let mut log_sources: Vec<String> = Vec::new();

    // ── Docker container log collection ──────────────────────────────────
    if let Some(ref dir) = compose_dir {
        // Explicit compose dir: use docker compose logs for all services
        print!("{} Fetching logs from {}... ", "→".cyan(), dir);
        std::io::Write::flush(&mut std::io::stdout())?;

        let output = Command::new("docker")
            .args([
                "compose",
                "-f",
                &format!("{}/docker-compose.yml", dir),
                "logs",
                "--no-color",
                "--since",
                &since_arg,
            ])
            .output();

        match output {
            Ok(out) if out.status.success() || !out.stdout.is_empty() => {
                let logs = String::from_utf8_lossy(&out.stdout).to_string();
                println!("{} ({} lines)", "✓".green(), logs.lines().count());
                all_logs.push_str(&logs);
                log_sources.push(format!("compose:{}", dir));
            }
            _ => {
                println!("{} (could not read)", "✗".red().dimmed());
            }
        }
    } else {
        // Auto-detect: discover all running Docker containers
        let docker_check = Command::new("docker").args(["ps", "-q"]).output();

        if let Ok(out) = docker_check {
            if out.status.success() && !out.stdout.is_empty() {
                // Get container names
                let ps_output = Command::new("docker")
                    .args([
                        "ps",
                        "--format",
                        "{{.Names}}",
                    ])
                    .output();

                if let Ok(ps) = ps_output {
                    let names: Vec<String> = String::from_utf8_lossy(&ps.stdout)
                        .lines()
                        .map(String::from)
                        .collect();

                    if !names.is_empty() {
                        println!(
                            "{} Found {} running container(s)",
                            "→".cyan(),
                            names.len()
                        );

                        for name in &names {
                            print!("  {} {}... ", "→".cyan(), name.dimmed());
                            std::io::Write::flush(&mut std::io::stdout())?;

                            let output = Command::new("docker")
                                .args([
                                    "logs",
                                    "--since",
                                    &since_arg,
                                    name,
                                ])
                                .output();

                            match output {
                                Ok(out) => {
                                    // Docker logs go to both stdout and stderr
                                    let stdout =
                                        String::from_utf8_lossy(&out.stdout).to_string();
                                    let stderr =
                                        String::from_utf8_lossy(&out.stderr).to_string();
                                    let combined_lines =
                                        stdout.lines().count() + stderr.lines().count();
                                    if combined_lines > 0 {
                                        println!(
                                            "{} ({} lines)",
                                            "✓".green(),
                                            combined_lines
                                        );
                                        all_logs.push_str(&stdout);
                                        all_logs.push('\n');
                                        all_logs.push_str(&stderr);
                                        all_logs.push('\n');
                                        log_sources.push(format!("docker:{}", name));
                                    } else {
                                        println!("{}", "empty".dimmed());
                                    }
                                }
                                _ => {
                                    println!("{}", "skip".dimmed());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── System logs (journalctl) ─────────────────────────────────────────
    // Check for auth/SSH logs regardless of Docker
    let journal_check = Command::new("journalctl")
        .args(["--since", &format!("{} min ago", window), "-u", "sshd", "--no-pager", "-q"])
        .output();

    if let Ok(out) = journal_check {
        if out.status.success() && !out.stdout.is_empty() {
            let logs = String::from_utf8_lossy(&out.stdout).to_string();
            let line_count = logs.lines().count();
            if line_count > 0 {
                print!("{} System SSH logs... ", "→".cyan());
                println!("{} ({} lines)", "✓".green(), line_count);
                all_logs.push_str(&logs);
                all_logs.push('\n');
                log_sources.push("journalctl:sshd".to_string());
            }
        }
    }

    // Check for nginx/apache system logs
    for unit in &["nginx", "apache2", "httpd"] {
        let journal = Command::new("journalctl")
            .args([
                "--since",
                &format!("{} min ago", window),
                "-u",
                unit,
                "--no-pager",
                "-q",
            ])
            .output();

        if let Ok(out) = journal {
            if out.status.success() && !out.stdout.is_empty() {
                let logs = String::from_utf8_lossy(&out.stdout).to_string();
                let line_count = logs.lines().count();
                if line_count > 0 {
                    print!("{} System {} logs... ", "→".cyan(), unit);
                    println!("{} ({} lines)", "✓".green(), line_count);
                    all_logs.push_str(&logs);
                    all_logs.push('\n');
                    log_sources.push(format!("journalctl:{}", unit));
                }
            }
        }
    }

    // ── Check for log files directly ─────────────────────────────────────
    for log_file in &["/var/log/auth.log", "/var/log/nginx/access.log"] {
        if std::path::Path::new(log_file).exists() {
            let output = Command::new("tail").args(["-n", "500", log_file]).output();

            if let Ok(out) = output {
                if !out.stdout.is_empty() {
                    let logs = String::from_utf8_lossy(&out.stdout).to_string();
                    let line_count = logs.lines().count();
                    if line_count > 0 {
                        print!("{} {}... ", "→".cyan(), log_file);
                        println!("{} ({} lines)", "✓".green(), line_count);
                        all_logs.push_str(&logs);
                        all_logs.push('\n');
                        log_sources.push(format!("file:{}", log_file));
                    }
                }
            }
        }
    }

    println!();

    if all_logs.is_empty() {
        println!("{}", "No log sources found.".yellow());
        println!("  Patrol checks: Docker containers, journalctl (sshd/nginx), /var/log/");
        println!(
            "  Use {} to specify a compose project.",
            "--compose-dir".cyan()
        );
        return Ok(());
    }

    println!(
        "{} Sources: {}",
        "✓".green(),
        log_sources.join(", ").dimmed()
    );
    println!();

    // ── Parse all logs ───────────────────────────────────────────────────
    let mut ip_stats: HashMap<String, PatrolHit> = HashMap::new();

    for line in all_logs.lines() {
        // Try to extract an IP and path from each line (nginx/access log format)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        // Find the IP (first thing that looks like an IP in the line)
        let ip = match parts.iter().find(|p| {
            (p.contains('.') && p.split('.').count() == 4 && p.parse::<std::net::Ipv4Addr>().is_ok())
                || (p.contains(':') && p.parse::<std::net::Ipv6Addr>().is_ok())
        }) {
            Some(ip) => ip.to_string(),
            None => {
                // Also try bracket-enclosed IPs: [1.2.3.4]
                if let Some(start) = line.find('[') {
                    if let Some(end) = line[start..].find(']') {
                        let candidate = &line[start + 1..start + end];
                        if is_valid_ip(candidate) {
                            candidate.to_string()
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        };

        // Skip internal/never-ban IPs
        if PATROL_NEVER_BAN.iter().any(|prefix| ip.starts_with(prefix)) {
            continue;
        }

        // Find the path (usually after "GET or "POST etc)
        let path = parts
            .iter()
            .find(|p| p.starts_with('/'))
            .unwrap_or(&"/")
            .to_string();

        // Find the HTTP status code (3 digit number)
        let status: u16 = parts
            .iter()
            .filter_map(|p| {
                if p.len() == 3 {
                    p.parse::<u16>().ok()
                } else {
                    None
                }
            })
            .find(|&s| (100..600).contains(&s))
            .unwrap_or(0);

        // Check for SSH/auth abuse patterns
        let is_ssh_abuse = line.contains("Failed password")
            || line.contains("Invalid user")
            || line.contains("authentication failure")
            || line.contains("Connection closed by authenticating user");

        // Check for SMTP abuse
        let is_smtp_abuse = line.contains("NOQUEUE: reject")
            || line.contains("authentication failed")
            || line.contains("too many errors");

        let is_attack = ATTACK_PATTERNS.iter().any(|pat| path.contains(pat))
            || is_ssh_abuse
            || is_smtp_abuse;
        let is_404 = status == 404;

        let hit = ip_stats.entry(ip.clone()).or_insert_with(|| PatrolHit {
            ip: ip.clone(),
            total_requests: 0,
            attack_hits: 0,
            four04_hits: 0,
            sample_paths: Vec::new(),
        });

        hit.total_requests += 1;
        if is_attack {
            hit.attack_hits += 1;
        }
        if is_404 {
            hit.four04_hits += 1;
        }
        if (is_attack || is_404) && hit.sample_paths.len() < 5 {
            if is_ssh_abuse {
                hit.sample_paths.push("SSH brute-force".to_string());
            } else if is_smtp_abuse {
                hit.sample_paths.push("SMTP abuse".to_string());
            } else {
                hit.sample_paths.push(path);
            }
        }
    }

    // Get our own IP to never ban ourselves
    let my_ip = get_my_public_ip().await.ok();
    let ssh_ip = get_ssh_client_ip();

    // Filter to attackers that exceed threshold
    // Key insight: require BOTH suspicious paths AND 404s for web scanning,
    // or high attack_hits for SMTP/SSH abuse (which doesn't produce 404s)
    let mut attackers: Vec<PatrolHit> = ip_stats
        .into_values()
        .filter(|h| {
            let has_web_scanning = h.four04_hits >= threshold;
            let has_abuse = (h.sample_paths.iter().any(|p| p == "SMTP abuse" || p == "SSH brute-force"))
                && h.attack_hits >= threshold;
            has_web_scanning || has_abuse
        })
        .collect();

    attackers.sort_by(|a, b| b.four04_hits.cmp(&a.four04_hits));

    // Separate new vs already-banned, skip our own IP and whitelisted
    let (new_attackers, known_attackers): (Vec<_>, Vec<_>) = attackers
        .into_iter()
        .filter(|h| {
            // Never ban our own IP
            if let Some(ref ip) = my_ip {
                if h.ip == *ip {
                    return false;
                }
            }
            if let Some(ref ip) = ssh_ip {
                if h.ip == *ip {
                    return false;
                }
            }
            true
        })
        .partition(|h| !already_banned.contains(h.ip.as_str()) && !whitelisted.contains(h.ip.as_str()));

    println!(
        "{} Scanned {} log lines across {} source(s)",
        "✓".green(),
        all_logs.lines().count(),
        log_sources.len()
    );
    println!();

    if !known_attackers.is_empty() {
        println!(
            "{} {} already-banned IPs seen (still probing)",
            "•".dimmed(),
            known_attackers.len()
        );
    }

    if new_attackers.is_empty() {
        println!("{}", "All clear! No new attackers detected.".green().bold());
        patrol_log_entry("patrol: clean - no new attackers")?;
        return Ok(());
    }

    println!(
        "{} {} new attacker(s) detected!",
        "⚠".yellow(),
        new_attackers.len()
    );
    println!();

    // Display attackers
    for attacker in &new_attackers {
        println!(
            "  {} {} - {} attack hits, {} 404s / {} total",
            "✗".red(),
            attacker.ip.red().bold(),
            attacker.attack_hits,
            attacker.four04_hits,
            attacker.total_requests
        );
        for path in &attacker.sample_paths {
            println!("    {}", path.dimmed());
        }
    }
    println!();

    if dry_run {
        println!("{}", "[DRY RUN] Would ban the above IPs.".yellow());
        return Ok(());
    }

    // Ban them
    let mut state = defend::State::load()?;
    let mut banned_count = 0;

    for attacker in &new_attackers {
        if !state.blocked_ips.contains(&attacker.ip) {
            state.blocked_ips.push(attacker.ip.clone());
            banned_count += 1;

            if execute {
                // Determine if IPv4 or IPv6
                let cmd = if attacker.ip.contains(':') {
                    "ip6tables"
                } else {
                    "iptables"
                };
                let _ = std::process::Command::new("sudo")
                    .args([cmd, "-I", "INPUT", "-s", &attacker.ip, "-j", "DROP"])
                    .output();
            }
        }
    }

    state.save()?;

    println!(
        "{} Banned {} new attacker(s){}",
        "✓".green(),
        banned_count,
        if execute {
            " + applied iptables rules"
        } else {
            ""
        }
    );

    if !execute {
        println!(
            "{}",
            "Use --execute to also apply iptables rules immediately.".dimmed()
        );
    }

    // Log the patrol action
    let log_msg = format!(
        "patrol: banned {} IPs: {}",
        banned_count,
        new_attackers
            .iter()
            .map(|a| a.ip.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    patrol_log_entry(&log_msg)?;

    Ok(())
}

async fn patrol_cron(interval: u32, remove: bool, threshold: u32) -> Result<()> {
    use std::process::Command;

    let i1_path =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("i1"));

    let cron_comment = "# i1 defend patrol - auto-ban attackers";
    let cron_command = format!(
        "{} defend patrol run --threshold {} --execute 2>&1 | logger -t i1-patrol",
        i1_path.display(),
        threshold
    );

    if remove {
        print!("{} Removing patrol cron job... ", "→".cyan());
        std::io::Write::flush(&mut std::io::stdout())?;

        let output = Command::new("crontab").arg("-l").output();

        if let Ok(out) = output {
            let current = String::from_utf8_lossy(&out.stdout);
            let new_crontab: String = current
                .lines()
                .filter(|line| !line.contains("i1 defend patrol"))
                .filter(|line| !line.contains(cron_comment))
                .collect::<Vec<_>>()
                .join("\n");

            let mut child = Command::new("crontab")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                stdin.write_all(new_crontab.as_bytes())?;
                stdin.write_all(b"\n")?;
            }
            child.wait()?;

            println!("{}", "✓".green());
            println!("Patrol cron job removed.");
        }

        return Ok(());
    }

    println!("{}", "━".repeat(60).dimmed());
    println!("{}", "🔍 SETTING UP PATROL CRON".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    let cron_schedule = format!("*/{} * * * *", interval);
    let cron_line = format!("{} {}", cron_schedule, cron_command);

    println!("Will add to crontab:");
    println!("  {}", cron_line.dimmed());
    println!();
    println!("This will:");
    println!("  • Scan Docker + system logs every {} minutes", interval);
    println!("  • Auto-ban IPs with {} or more attack hits", threshold);
    println!("  • Apply iptables rules immediately");
    println!("  • Log actions to syslog (journalctl -t i1-patrol)");
    println!();

    // Check if already exists
    let existing = Command::new("crontab").arg("-l").output();
    let mut current_crontab = String::new();

    if let Ok(out) = existing {
        current_crontab = String::from_utf8_lossy(&out.stdout).to_string();
        if current_crontab.contains("i1 defend patrol") {
            println!(
                "{} Patrol cron already exists. Use --remove to delete it first.",
                "Note:".yellow()
            );
            return Ok(());
        }
    }

    print!("{} Adding to crontab... ", "→".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        if !current_crontab.is_empty() {
            stdin.write_all(current_crontab.as_bytes())?;
            if !current_crontab.ends_with('\n') {
                stdin.write_all(b"\n")?;
            }
        }
        stdin.write_all(cron_comment.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(cron_line.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    child.wait()?;
    println!("{}", "✓".green());

    println!();
    println!("{}", "Patrol is active!".green().bold());
    println!("Script kiddies will be auto-banned every {} minutes.", interval);
    println!();
    println!("Monitor with:");
    println!("  {} defend patrol log", "i1".cyan());
    println!("  journalctl -t i1-patrol -f");
    println!();
    println!("Remove with:");
    println!("  {} defend patrol cron --remove", "i1".cyan());

    Ok(())
}

async fn patrol_log(lines: u32) -> Result<()> {
    let log_path = patrol_log_path()?;

    println!("{}", "━".repeat(60).dimmed());
    println!("{}", "🔍 PATROL LOG".cyan().bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    match std::fs::read_to_string(&log_path) {
        Ok(content) => {
            let all_lines: Vec<&str> = content.lines().collect();
            let start = all_lines.len().saturating_sub(lines as usize);
            if all_lines.is_empty() {
                println!("{}", "No patrol activity yet.".dimmed());
            } else {
                for line in &all_lines[start..] {
                    if line.contains("banned") {
                        println!("  {} {}", "⚠".yellow(), line);
                    } else if line.contains("clean") {
                        println!("  {} {}", "✓".green(), line);
                    } else {
                        println!("  {}", line);
                    }
                }
            }
        }
        Err(_) => {
            println!("{}", "No patrol activity yet.".dimmed());
            println!("Run: {} defend patrol run", "i1".cyan());
        }
    }

    Ok(())
}

fn patrol_log_path() -> Result<String> {
    let data_dir = shellexpand::tilde("~/.local/share/showdi1").to_string();
    std::fs::create_dir_all(&data_dir)?;
    Ok(format!("{}/patrol.log", data_dir))
}

fn patrol_log_entry(msg: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let path = patrol_log_path()?;
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "[{}] {}", timestamp, msg)?;
    Ok(())
}

fn is_valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Extract source IP from an iptables rule line
fn extract_source_ip(line: &str) -> Option<String> {
    // iptables -L -n format:
    // "DROP       all  --  1.2.3.4              0.0.0.0/0"
    // "DROP       all  --  192.168.1.0/24       0.0.0.0/0"
    let parts: Vec<&str> = line.split_whitespace().collect();

    // The source IP is typically the 4th field (index 3) after: TARGET PROTO OPT SOURCE
    if parts.len() >= 4 {
        let source = parts[3];
        // Validate it looks like an IP or CIDR
        if source.contains('.') || source.contains(':') {
            // Skip "anywhere" placeholder
            if source != "0.0.0.0/0" && source != "::/0" {
                return Some(source.to_string());
            }
        }
    }

    None
}
