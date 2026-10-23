//! The demo scenarios as test assertions: each expect block holds at its own
//! seed and at a changed seed, runs are deterministic, and removing the
//! control a scenario targets turns it red.

use std::path::PathBuf;

use sandbox_demo::{load_dir, load_scenario, run_scenario, Mutations};
use serde_json::Value;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scenarios")
}

fn scn(name: &str) -> Value {
    load_scenario(&dir().join(format!("{name}.json"))).unwrap()
}

fn failed(r: &sandbox_demo::ScenarioResult) -> Vec<String> {
    r.checks.iter().filter(|c| !c.ok).map(|c| format!("{} expected {} got {}", c.name, c.expected, c.actual)).collect()
}

#[test]
fn every_scenario_expect_holds() {
    for s in load_dir(&dir()).unwrap() {
        let r = run_scenario(&s, None, Mutations::default()).unwrap();
        assert_eq!(r.status, "PASS", "{}: {:?}", r.scenario, failed(&r));
    }
}

#[test]
fn every_scenario_holds_under_a_changed_seed() {
    for s in load_dir(&dir()).unwrap() {
        let seed = s["seed"].as_u64().unwrap() + 1000;
        let r = run_scenario(&s, Some(seed), Mutations::default()).unwrap();
        assert_eq!(r.status, "PASS", "{} seed {seed}: {:?}", r.scenario, failed(&r));
    }
}

#[test]
fn every_scenario_is_deterministic() {
    for s in load_dir(&dir()).unwrap() {
        let a = run_scenario(&s, None, Mutations::default()).unwrap();
        let b = run_scenario(&s, None, Mutations::default()).unwrap();
        assert_eq!(a.measured, b.measured, "{}", a.scenario);
        assert_eq!(a.events_sha256, b.events_sha256, "{}", a.scenario);
    }
}

#[test]
fn a_changed_seed_changes_the_events() {
    let s = scn("S07-vestibule-schema-violation");
    let a = run_scenario(&s, None, Mutations::default()).unwrap();
    let b = run_scenario(&s, Some(9999), Mutations::default()).unwrap();
    assert_ne!(a.events_sha256, b.events_sha256);
}

#[test]
fn the_known_chain_gaps_are_measured() {
    // Recorded so a change in either direction shows up; see not_supported in summary.json.
    let r = run_scenario(&scn("S08-iso-decision-chain-tamper"), None, Mutations::default()).unwrap();
    assert_eq!(r.measured["tail_drop_detected"], 0);
    assert_eq!(r.measured["edit_append_refused"], 0);
    assert_eq!(r.measured["delete_append_refused"], 0);
}

// --- mutation checks: remove the control, the scenario goes red ------------

#[test]
fn mutation_s07_schema_checks_off_goes_red() {
    let m = Mutations { vestibule_disabled: true, ..Default::default() };
    let r = run_scenario(&scn("S07-vestibule-schema-violation"), None, m).unwrap();
    assert_eq!(r.status, "FAIL");
    assert!(r.measured["planted_on_shelf"] > 0);
}

#[test]
fn mutation_sb1_trusting_the_guest_hash_goes_red() {
    let m = Mutations { trust_claim_hash: true, ..Default::default() };
    let r = run_scenario(&scn("SB1-sandbox-lifecycle"), None, m).unwrap();
    assert_eq!(r.status, "FAIL");
    assert_eq!(r.measured["hash_lie_dropped"], 0);
}

#[test]
fn mutation_sb1_leaky_teardown_goes_red() {
    let m = Mutations { leak_every_teardown: true, ..Default::default() };
    let r = run_scenario(&scn("SB1-sandbox-lifecycle"), None, m).unwrap();
    assert_eq!(r.status, "FAIL");
    assert_eq!(r.measured["hygiene_clean"], 0);
}

#[test]
fn mutation_sb1_schema_checks_off_goes_red() {
    let m = Mutations { vestibule_disabled: true, ..Default::default() };
    let r = run_scenario(&scn("SB1-sandbox-lifecycle"), None, m).unwrap();
    assert_eq!(r.status, "FAIL");
    assert_eq!(r.measured["vestibule_rejected"], 0);
}

#[test]
fn mutation_s08_verify_skipped_goes_red() {
    let m = Mutations { chain_verify_noop: true, ..Default::default() };
    let r = run_scenario(&scn("S08-iso-decision-chain-tamper"), None, m).unwrap();
    assert_eq!(r.status, "FAIL");
}

#[test]
fn every_scenario_record_is_byte_identical_across_runs() {
    // Detail text masks scratch folders and per-run chain hashes, so the whole
    // record, not just the counts, is the same on every run.
    for s in load_dir(&dir()).unwrap() {
        let a = run_scenario(&s, None, Mutations::default()).unwrap().to_json().to_string();
        let b = run_scenario(&s, None, Mutations::default()).unwrap().to_json().to_string();
        assert_eq!(a, b, "{}", s["name"]);
    }
}
