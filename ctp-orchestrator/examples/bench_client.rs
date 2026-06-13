//! Benchmark client for the CTP orchestrator gateway.
//!
//! Reads payloads from two files (benign, injections), sends each through the
//! gRPC `Evaluate` endpoint, and reports the verdict, the deciding layer, and
//! the round-trip latency. Prints a Markdown table to stdout and, optionally,
//! writes a CSV. Driven by `scripts/bench.sh`.
//!
//! Usage:
//!   bench_client <addr> <benign_file> <injection_file> [csv_out]
//!   e.g. bench_client http://127.0.0.1:50051 payloads/benign.txt \
//!        payloads/injections.txt results.csv

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::io::Write;
use std::time::Instant;

use ctp_orchestrator::orchestrator_proto::orchestrator_service_client::OrchestratorServiceClient;
use ctp_orchestrator::orchestrator_proto::{self, EvaluateRequest};

struct Row {
    expected: &'static str,
    payload: String,
    verdict: String,
    layer: String,
    latency_ms: f64,
}

fn read_payloads(path: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n - 1).collect();
        format!("{head}…")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: bench_client <addr> <benign_file> <injection_file> [csv_out]");
        std::process::exit(2);
    }
    let addr = args[1].clone();
    let benign = read_payloads(&args[2])?;
    let injections = read_payloads(&args[3])?;
    let csv_out = args.get(4).cloned();

    let mut client = OrchestratorServiceClient::connect(addr).await?;

    let mut rows: Vec<Row> = Vec::new();
    for (expected, payloads) in [("PASS", &benign), ("BLOCK", &injections)] {
        for payload in payloads {
            let request = EvaluateRequest {
                payload: payload.clone().into_bytes(),
                direction: orchestrator_proto::Direction::Inbound as i32,
                tool_name: "bench".into(),
                session_id: String::new(),
            };
            let start = Instant::now();
            let response = client.evaluate(request).await?.into_inner();
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let verdict = match orchestrator_proto::Verdict::try_from(response.verdict) {
                Ok(orchestrator_proto::Verdict::Pass) => "PASS",
                Ok(orchestrator_proto::Verdict::Block) => "BLOCK",
                _ => "UNKNOWN",
            };
            rows.push(Row {
                expected,
                payload: payload.clone(),
                verdict: verdict.to_string(),
                layer: response.layer,
                latency_ms,
            });
        }
    }

    // Markdown table.
    println!("| Payload | Expected | Verdict | Layer | Latency (ms) | OK |");
    println!("|---|---|---|---|---:|:-:|");
    let mut correct = 0usize;
    for r in &rows {
        let ok = r.verdict == r.expected;
        if ok {
            correct += 1;
        }
        println!(
            "| {} | {} | {} | {} | {:.1} | {} |",
            truncate(&r.payload, 48),
            r.expected,
            r.verdict,
            r.layer,
            r.latency_ms,
            if ok { "✓" } else { "✗" }
        );
    }
    let total = rows.len();
    let lat: Vec<f64> = rows.iter().map(|r| r.latency_ms).collect();
    let max = lat.iter().cloned().fold(0.0_f64, f64::max);
    let mean = if total > 0 {
        lat.iter().sum::<f64>() / total as f64
    } else {
        0.0
    };
    println!("\nAccuracy: {correct}/{total} correct. Latency mean {mean:.0} ms, max {max:.0} ms.");

    if let Some(path) = csv_out {
        let mut f = fs::File::create(&path)?;
        writeln!(f, "expected,verdict,layer,latency_ms,payload")?;
        for r in &rows {
            // CSV-escape the payload (quote, double inner quotes).
            let p = r.payload.replace('"', "\"\"");
            writeln!(
                f,
                "{},{},{},{:.3},\"{}\"",
                r.expected, r.verdict, r.layer, r.latency_ms, p
            )?;
        }
        eprintln!("wrote {path}");
    }

    Ok(())
}
