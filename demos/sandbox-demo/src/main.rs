//! sandbox-demo run <scenarios dir> --out <dir>
//! Prints the summary table and writes <dir>/summary.json and <dir>/runs/.
//!
//! sandbox-demo route --state <dir> [--guest-deadline-ms N] < task.json
//! The isolate route door (STUBBED, real: false); see src/route.rs.

use std::fs;
use std::path::PathBuf;
use std::process::{exit, Command};

use sandbox_demo::{blockers, load_dir, not_supported, run_scenario, table, Mutations};
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("route") {
        exit(sandbox_demo::route::main_route(&args[2..]));
    }
    if args.len() < 3 || args[1] != "run" {
        eprintln!(
            "usage: sandbox-demo run <scenarios dir> [--out DIR] | sandbox-demo route --state DIR"
        );
        exit(2);
    }
    let dir = PathBuf::from(&args[2]);
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("out"));
    let scenarios = load_dir(&dir).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    if scenarios.is_empty() {
        // Zero scenarios would report fail 0 over nothing.
        eprintln!("no scenario files in {}", dir.display());
        exit(2);
    }
    let mut results = Vec::new();
    for scn in &scenarios {
        match run_scenario(scn, None, Mutations::default()) {
            Ok(r) => results.push(r),
            Err(e) => {
                eprintln!("{}: {e}", scn["name"]);
                exit(2);
            }
        }
    }
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let failed = results.iter().filter(|r| r.status != "PASS").count();
    let summary = json!({
        "repo": "isolation-layer",
        "commit": commit,
        "synthetic_data": true,
        "scenarios": results.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
        "pass": results.len() - failed,
        "fail": failed,
        "not_supported": not_supported(),
        "blockers": blockers(),
    });
    fs::create_dir_all(out.join("runs")).expect("out dir");
    for r in &results {
        fs::write(
            out.join("runs").join(format!("{}.json", r.scenario)),
            serde_json::to_string_pretty(&r.to_json()).unwrap(),
        )
        .expect("receipt");
    }
    fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .expect("summary");
    print!("{}", table(&results));
    println!();
    println!(
        "commit {commit}  scenarios {}  pass {}  fail {failed}",
        results.len(),
        results.len() - failed
    );
    println!("wrote {}", out.join("summary.json").display());
    for ns in summary["not_supported"].as_array().unwrap() {
        println!(
            "not supported: {}: {}",
            ns["scenario"].as_str().unwrap(),
            ns["reason"].as_str().unwrap()
        );
    }
    for b in summary["blockers"].as_array().unwrap() {
        println!(
            "{}: {} {} Needs: {}",
            b["id"].as_str().unwrap(),
            b["what"].as_str().unwrap(),
            b["why"].as_str().unwrap(),
            b["needs"].as_str().unwrap()
        );
    }
    if failed > 0 {
        exit(1);
    }
}
