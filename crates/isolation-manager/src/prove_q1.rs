//! Stage-Q1 A/B prove: marker Hold/Drop + optional size_cap Drop.
//! Does not re-run the full vestibule prove path.

use std::thread;
use std::time::Duration;

use inspector::{Disposition, StagedBlob};

use crate::inspect_vm::run_disposable_inspect_expect;

pub fn run() -> i32 {
    match run_inner() {
        Ok(()) => {
            println!("q1_prove_ok=true");
            0
        }
        Err(e) => {
            eprintln!("q1 prove failed: {e}");
            println!("q1_prove_ok=false");
            1
        }
    }
}

fn run_inner() -> Result<(), String> {
    // A: clear (no markers)
    run_case(b"hello-q1-clear", Disposition::Advance, "clear")?;
    // A: suspect marker → Hold
    run_case(
        b"prefix AEGIS_Q1_MARKER_SUSPECT suffix",
        Disposition::Hold,
        "suspect",
    )?;
    // A: failed marker → Drop (wins over suspect if both; here alone)
    run_case(
        b"prefix AEGIS_Q1_MARKER_FAILED suffix",
        Disposition::Drop,
        "failed",
    )?;
    // B: size_cap → Drop (1 MiB + 1)
    let mut oversized = vec![b'x'; 1_048_576 + 1];
    oversized.extend_from_slice(b"no-marker");
    run_case(&oversized, Disposition::Drop, "size_cap")?;

    Ok(())
}

fn run_case(body: &[u8], expect: Disposition, label: &str) -> Result<(), String> {
    let shelf_root = std::env::temp_dir().join(format!(
        "aegis-q1-shelf-{}-{}",
        label,
        std::process::id()
    ));
    let stage_root = std::env::temp_dir().join(format!(
        "aegis-q1-stage-{}-{}",
        label,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&shelf_root);
    let _ = std::fs::remove_dir_all(&stage_root);
    std::fs::create_dir_all(&shelf_root).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&stage_root).map_err(|e| e.to_string())?;

    let handoff = crate::handoff::handoff_trusted_body(&shelf_root, body)
        .map_err(|e| format!("q1[{label}] handoff: {e}"))?;
    let staged: StagedBlob = inspector::stage_from_shelf(&shelf_root, &handoff.hash, &stage_root)
        .map_err(|e| format!("q1[{label}] stage: {e}"))?;

    println!("q1_case={label}");
    println!("q1_expect_disposition={}", expect.as_str());
    let r = run_disposable_inspect_expect(&staged, expect)
        .map_err(|e| format!("q1[{label}] inspect: {e}"))?;
    println!(
        "q1_{label}_ok=true claim={} disposition={}",
        r.claim_outcome, r.disposition
    );

    let _ = staged.dispose();
    let _ = std::fs::remove_dir_all(&shelf_root);
    let _ = std::fs::remove_dir_all(&stage_root);
    thread::sleep(Duration::from_secs(1));
    Ok(())
}
