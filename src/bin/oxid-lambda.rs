//! oxID as an AWS Lambda function. Package this binary as `bootstrap` for
//! the `provided.al2023` runtime; see `deploy/aws/README.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use oxid::config::Config;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // CloudWatch Logs shows escape codes literally and adds its own
        // timestamps.
        .with_ansi(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run() -> anyhow::Result<()> {
    let path =
        std::env::var_os("OXID_CONFIG").map_or_else(|| PathBuf::from("oxid.toml"), Into::into);
    let mut config = Config::load(&path)?;
    if let Some(experience) = std::env::var("OXID_EXPERIENCE")
        .ok()
        .filter(|value| !value.is_empty())
    {
        config.experience = experience
            .parse()
            .map_err(|error| anyhow::anyhow!("OXID_EXPERIENCE: {error}"))?;
    }
    oxid::lambda::run(&config).await
}
