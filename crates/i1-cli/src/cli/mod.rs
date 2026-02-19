//! CLI argument parsing and command dispatch.

pub mod args;
pub mod commands;

use anyhow::Result;
use args::{Cli, Commands};
use clap::Parser;

use crate::config::Config;
use crate::output::OutputFormat;

/// Run the CLI application.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load()?;

    // Determine output format
    let output_format = cli.output.unwrap_or(OutputFormat::Pretty);

    // Get API keys from CLI, env, or config
    let shodan_key = cli
        .api_key
        .or_else(|| std::env::var("SHODAN_API_KEY").ok())
        .or_else(|| std::env::var("I1_SHODAN_KEY").ok())
        .or_else(|| config.shodan_key.clone());

    // Create context for commands
    let ctx = commands::Context {
        shodan_key,
        censys_id: std::env::var("I1_CENSYS_ID")
            .ok()
            .or_else(|| config.censys_id.clone()),
        censys_secret: std::env::var("I1_CENSYS_SECRET")
            .ok()
            .or_else(|| config.censys_secret.clone()),
        criminalip_key: std::env::var("I1_CRIMINALIP_KEY")
            .ok()
            .or_else(|| config.criminalip_key.clone()),
        provider: cli.provider,
        output_format,
        explain: cli.explain,
        verbose: cli.verbose,
        no_color: cli.no_color,
    };

    // Dispatch to appropriate command, or run interactive scan if none given
    match cli.command {
        Some(Commands::Host(args)) => commands::host::execute(ctx, args).await,
        Some(Commands::Search(args)) => commands::search::execute(ctx, args).await,
        Some(Commands::Count(args)) => commands::count::execute(ctx, args).await,
        Some(Commands::Dns(args)) => commands::dns::execute(ctx, args).await,
        Some(Commands::Myip) => commands::myip::execute(ctx).await,
        Some(Commands::Defend(args)) => commands::defend::execute(ctx, args).await,
        Some(Commands::Config(args)) => commands::config::execute(ctx, args).await,
        Some(Commands::Threat(args)) => commands::threat::execute(&ctx, &args).await,
        Some(Commands::Audit(args)) => commands::audit::execute(ctx, args).await,
        None => commands::scan::execute(ctx).await,
    }
}
