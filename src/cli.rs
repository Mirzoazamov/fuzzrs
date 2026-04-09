use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "fuzzer-rs", version = "0.1.0", about = "High-performance clustered web fuzzer")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start a high-performance fuzzing scan targeting semantic anomalies
    Scan(ScanArgs),
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum OutputFormat {
    Json,
    Table,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ScanArgs {
    /// Target URL containing the FUZZ keyword
    pub url: String,

    /// Path to the wordlist
    #[arg(short, long)]
    pub wordlist: PathBuf,

    /// Max concurrency
    #[arg(short, long, default_value_t = 50)]
    pub concurrency: usize,

    /// Request timeout in milliseconds
    #[arg(short, long, default_value_t = 5000)]
    pub timeout: u64,

    /// Output format parameter
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Optional structured report output file saving mapped Text telemetry
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// Max retries for failed requests
    #[arg(long, default_value_t = 3)]
    pub retries: u32,

    /// Optional proxy URL (e.g. http://127.0.0.1:8080)
    #[arg(long)]
    pub proxy: Option<String>,
}

impl ScanArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.url.contains("FUZZ") {
            anyhow::bail!("Target URL must inherently contain the 'FUZZ' keyword for injection!");
        }
        if !self.wordlist.exists() {
            anyhow::bail!("Wordlist file does not exist locally: {}", self.wordlist.display());
        }
        Ok(())
    }
}
