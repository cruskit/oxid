//! The `oxid` command line.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use oxid::config::Config;
use oxid::server::ServerBuilder;

#[derive(Debug, Parser)]
#[command(
    name = "oxid",
    version,
    about = "oxID OpenID Provider (FAPI 2.0 / ConnectID)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the provider.
    Serve {
        /// Path to the TOML configuration file.
        #[arg(short, long, env = "OXID_CONFIG", default_value = "oxid.toml")]
        config: PathBuf,
        /// User experience at the authorization endpoint, overriding the
        /// configuration file: `technical` or `login`.
        #[arg(long, env = "OXID_EXPERIENCE")]
        experience: Option<oxid::experience::Kind>,
    },
    /// Read a password from standard input and print its Argon2 hash, for
    /// use as a user's `password_hash`.
    HashPassword,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let result = match cli.command {
        Command::Serve { config, experience } => serve(&config, experience),
        Command::HashPassword => hash_password(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn serve(
    config_path: &std::path::Path,
    experience: Option<oxid::experience::Kind>,
) -> Result<()> {
    let mut config = Config::load(config_path)?;
    if let Some(experience) = experience {
        config.experience = experience;
    }
    let server = ServerBuilder::new(config).start().await?;
    shutdown_signal().await;
    tracing::info!("shutting down");
    server.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = interrupt => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = interrupt.await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}

fn hash_password() -> Result<()> {
    let mut password = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut password)
        .context("reading password from stdin")?;
    let password = password.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        !password.is_empty(),
        "no password supplied on standard input"
    );
    writeln!(
        std::io::stdout(),
        "{}",
        oxid::user::hash_password(password)?
    )?;
    Ok(())
}
