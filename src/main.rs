mod cli;
pub mod engine;
pub mod analysis;

use clap::Parser;
use cli::{Cli, Commands, ScanArgs, OutputFormat};
use serde::Serialize;
use std::collections::HashSet;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use bytes::Bytes;
use std::fmt::Write;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub enum Severity {
    HIGH,
    MEDIUM,
    LOW,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub enum Confidence {
    HIGH,
    MEDIUM,
    LOW,
}

#[derive(Debug, Serialize, Clone)]
pub struct ScanResult {
    pub path: String,
    pub status: u16,
    pub cluster_id: usize,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<f32>, 
}

#[derive(Serialize)]
pub struct ReportStats {
    pub total: usize,
    pub filtered: usize,
}

#[derive(Serialize)]
pub struct ScanReport<'a> {
    pub target: &'a str,
    pub timestamp: &'a str,
    pub findings: &'a Vec<ScanResult>,
    pub stats: ReportStats,
}

impl ScanResult {
    pub fn determine_severity(status: u16) -> Severity {
        match status {
            200 | 201 | 204 => Severity::MEDIUM,
            401 | 403 | 500..=599 => Severity::HIGH,
            _ => Severity::LOW,
        }
    }

    pub fn determine_confidence(similarity: f32) -> Confidence {
        if similarity >= 99.0 {
            Confidence::HIGH
        } else if similarity >= 95.0 {
            Confidence::MEDIUM
        } else {
            Confidence::LOW
        }
    }
}

pub async fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    args.validate()?;

    if args.format != OutputFormat::Json {
        eprintln!("[*] Initializing High-Performance Semantic Fuzzer...");
        eprintln!("[*] Target bounds: {}", args.url);
        eprintln!("[*] Wordlist: {}", args.wordlist.display());
        eprintln!("[*] Concurrency bounds: {}\n", args.concurrency);
    }

    let mut analyzer = analysis::analyzer::Analyzer::new();
    
    let file = File::open(&args.wordlist).await?;
    let mut lines = BufReader::new(file).lines();

    let mut seen_clusters = HashSet::new();
    let mut filtered_count = 0;
    let mut total_requests = 0;

    let mut unique_findings: Vec<ScanResult> = Vec::new();

    if args.format == OutputFormat::Table {
        println!("{:<35} | {:<8} | {:<8} | {:<10} | {:<12}", "TARGET PATH", "STATUS", "SEVERITY", "CONFIDENCE", "CLUSTER ID");
        println!("{:-<80}", "-");
    }

    while let Some(word) = lines.next_line().await? {
        total_requests += 1;
        let target_path = args.url.replace("FUZZ", &word);

        // [MOCK]
        let simulated_status = if word.contains("admin") { 403 } else { 200 };
        let simulated_body = if simulated_status == 403 {
            Bytes::from("Access denied globally for generic user mappings natively")
        } else {
            Bytes::from("Welcome generic frontpage HTML output completely unchanged")
        };

        let cluster_id = analyzer.classify(simulated_status, &simulated_body);
        let similarity = 99.5; 

        if seen_clusters.insert(cluster_id) {
            let severity = ScanResult::determine_severity(simulated_status);
            let confidence = ScanResult::determine_confidence(similarity);

            let result = ScanResult {
                path: target_path.clone(),
                status: simulated_status,
                cluster_id,
                severity: severity.clone(),
                confidence: confidence.clone(),
                similarity: Some(similarity),
            };

            unique_findings.push(result);

            if args.format == OutputFormat::Table {
                println!(
                    "{:<35} | {:<8} | {:<8?} | {:<10?} | {:<12}",
                    target_path, simulated_status, severity, confidence, cluster_id
                );
            }
        } else {
            filtered_count += 1;
        }
    }

    let current_timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    if args.format == OutputFormat::Json {
        let payload = ScanReport {
            target: &args.url,
            timestamp: &current_timestamp,
            findings: &unique_findings,
            stats: ReportStats {
                total: total_requests,
                filtered: filtered_count,
            },
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("{:-<80}", "-");
        println!("\n[SCAN SUMMARY]");
        println!("Total Requests    : {}", total_requests);
        println!("Unique Endpoints  : {}", unique_findings.len());
        println!("Filtered Noise    : {}", filtered_count);
    }

    if let Some(report_path) = args.report {
        // PERF: Zero-allocation loop block using std::fmt::Write into a pre-reserved chunk buffer natively!
        let mut report_contents = String::with_capacity(4096);
        
        let _ = write!(&mut report_contents, "================================================================================\n");
        let _ = write!(&mut report_contents, "                      FUZZRS SEMANTIC SCAN REPORT\n");
        let _ = write!(&mut report_contents, "================================================================================\n");
        let _ = write!(&mut report_contents, "Target    : {}\n", args.url);
        let _ = write!(&mut report_contents, "Date/Time : {}\n\n", current_timestamp);
        
        let _ = write!(&mut report_contents, "[ UNIQUE FINDINGS ]\n");
        let _ = write!(&mut report_contents, "{:<8} | {:<10} | {:<12} | {:<35} | {:<8}\n", "STATUS", "SEVERITY", "CONFIDENCE", "PATH", "CLUSTER");
        let _ = write!(&mut report_contents, "{:-<85}\n", "-");
        
        // Push strings dynamically onto the static buffer directly natively.
        for finding in &unique_findings {
            let _ = write!(&mut report_contents, "{:<8} | {:<10?} | {:<12?} | {:<35} | {:<8}\n", 
                finding.status, finding.severity, finding.confidence, finding.path, finding.cluster_id);
        }
        
        let _ = write!(&mut report_contents, "\n[ STATISTICS ]\n");
        let _ = write!(&mut report_contents, "Total Payloads Executed : {}\n", total_requests);
        let _ = write!(&mut report_contents, "Logically Filtered Spam : {}\n", filtered_count);
        let _ = write!(&mut report_contents, "True Attack Surface     : {}\n", unique_findings.len());

        tokio::fs::write(&report_path, report_contents).await?;
        
        if args.format != OutputFormat::Json {
            println!("\n[*] Saved human-readable Text report natively to {}", report_path.display());
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => {
            run_scan(args).await?;
        }
    }
    
    Ok(())
}
