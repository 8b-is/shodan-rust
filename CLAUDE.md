# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**i1** - Multi-provider security operations CLI for the i1.is platform. Aggregates threat intelligence from Shodan, Censys, and Criminal IP with local recon (WHOIS, DNS). Includes automated defense: log-based patrol, fleet sync via SSH, community blocklist sharing, honeypot generation, and certificate authority infrastructure. **No API keys required** for basic operation.

## Build Commands

```bash
cargo build --workspace           # Build all crates
cargo build --release             # Production build
cargo test --all                  # Full test suite
cargo test -p i1-shodan           # Test specific crate
cargo test search -- --nocapture  # Single test with output
cargo clippy -- -D warnings       # Lint (strict, must pass before commits)
cargo fmt                         # Format code
cargo run -p i1-cli -- --help     # Run CLI
```

## Architecture

Cargo workspace with trait-based multi-provider design:

```
crates/
├── i1-core/        # Shared types (HostInfo, GeoLocation, Service), I1Error, Config
├── i1-providers/   # Provider traits: Provider, HostLookup, SearchProvider, DnsProvider, WhoisProvider, VulnProvider
├── i1-shodan/      # Shodan API (auth: query param ?key=)
├── i1-censys/      # Censys API (auth: HTTP Basic)
├── i1-criminalip/  # Criminal IP API (auth: x-api-key header)
├── i1-native/      # Local provider: WHOIS + DNS, no API keys needed
├── i1-client/      # Unified client (builder pattern), aggregates providers, has lookup_host_all()
├── i1-recon/       # Local recon: port scanner, whois, enrichment (optional features)
├── i1-honeypot/    # Generates fake creds/cards/wallets that trap attackers
├── i1-ca/          # Certificate authority: air-gapped root → intermediate → end-entity hierarchy
├── i1/             # Facade crate, re-exports everything + prelude
└── i1-cli/         # CLI binary with all commands
```

### Provider System

All providers implement `Provider` trait (name, is_configured, health_check) plus capability traits (`HostLookup`, `SearchProvider`, etc.). The `I1Client` wraps them via `Arc<dyn ProviderBox>` in a HashMap.

**Auto-detection priority** (when `--provider auto` or unspecified): Shodan > Censys > Criminal IP. First configured provider wins. Use `--all` flag to query all simultaneously.

### CLI Structure (`crates/i1-cli/src/`)

- `cli/args.rs` - All clap command/subcommand definitions
- `cli/commands/mod.rs` - `Context` struct carrying API keys, provider selection, output format. Key methods: `host_provider()`, `search_provider()`, `has_any_provider()`
- `cli/commands/*.rs` - Individual command implementations (host, search, count, dns, myip, threat, scan, defend, config, alert, account)
- `defend/mod.rs` - Defense state management, firewall rule generation (nftables, iptables, pf)

**Interactive no-args mode** (`scan.rs`): Running `i1` with no arguments detects OS capabilities (Docker, iptables, nftables, pf, fail2ban), gets public IP, loads defense state, and presents a context-aware menu.

**Threat command** (`threat.rs`, alias `i1 t`): Quick threat response - IP lookup + optional ban in one command. Interactive by default, supports `--ban`, `--ban-asn`, `--execute`, `--yes`.

### Defense System

**State persistence**: `~/.local/share/i1/showdi1/defend_state.json` - stores blocked IPs, ASNs, countries (inbound + outbound), and whitelisted IPs.

**Geoblock directions**: Supports `--direction inbound|outbound|both`. Outbound blocking = honeypot mode: attackers can connect in, but nothing goes back out. Firewall generators emit both INPUT and OUTPUT chains.

**Patrol** scans logs for attack patterns (.php probes, wp-content, path traversal, .env/.git hunters, SMTP brute force):
1. Docker compose logs (if compose_dir specified)
2. Docker auto-discovery (`docker ps` → `docker logs` per container)
3. System journalctl (sshd, nginx, apache) and log files (/var/log/auth.log, etc.)

Thresholds: default 5 hits in 60 minutes. Configurable via `--threshold` and `--window`.

**Safety guards** (never banned): your SSH session IP (detected via `SSH_CLIENT`/`SSH_CONNECTION` env), loopback, Docker internal ranges (172.22.x, 10.x, 192.168.x), IPv6 ULA, whitelisted IPs.

**Fleet sync**: `defend push` sends blocks to remote servers via SSH config. `defend pull` imports from hardened servers. Auto-whitelists your IP on remotes.

**Community**: `defend community contribute` shares your blocks. `defend community fetch` pulls crowdsourced blocklist.

### Honeypot & CA Infrastructure

**i1-honeypot**: Generates LUHN-valid fake credit cards, login credentials, crypto wallets with seed phrases, and trap documents. Deploy as bait to detect when attackers explore compromised accounts.

**i1-ca**: Air-gapped root CA → intermediate CAs (general, per-user, per-session, honeypot, regional) → short-lived end-entity certs. Supports revocation tracking and "patient zero" tracing per-user intermediates.

### Config

Stored at `~/.config/i1/config.toml`. Keys loaded from: CLI flags > environment variables > config file.

```bash
SHODAN_API_KEY / I1_SHODAN_KEY    # Shodan
I1_CENSYS_ID + I1_CENSYS_SECRET  # Censys
I1_CRIMINALIP_KEY                 # Criminal IP
```

## Workspace Lint Configuration

Clippy is set to maximum strictness in root `Cargo.toml`:
- `all`, `pedantic`, `nursery`, `cargo` all at warn level
- `unsafe_code = "forbid"`
- Allowed: `module_name_repetitions`, `must_use_candidate`, `missing_errors_doc`, `missing_panics_doc`

## Notes

- Rust 2021 edition, min version 1.75+ (async trait stabilization)
- HTTP via `reqwest` with rustls, async via `tokio` multi-thread
- Rate limiting per-provider via `governor` crate
- License: MIT OR Apache-2.0
