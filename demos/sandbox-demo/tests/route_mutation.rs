//! Mutation checks for the route door: turning a control off through the
//! library entry flips the R-test outcome. main never sets these switches.

use sandbox_demo::route::{run_route, RouteOpts};
use sandbox_demo::Mutations;
use serde_json::json;

fn task(code: &str, i: usize) -> Vec<u8> {
    json!({
        "schema": "isolate-route-task/1",
        "route_ticket": format!("{i:0>32}"),
        "tool_call_id": format!("c{i}"),
        "tool": "execute_code",
        "skill": "synth-agent",
        "args": {"code": code},
        "gate_decision_sha256": "ab".repeat(32),
    })
    .to_string()
    .into_bytes()
}

fn state(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("route-mut-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn lax_vestibule_lets_the_off_schema_result_advance() {
    let s = state("lax");
    let m = Mutations {
        vestibule_disabled: true,
        ..Mutations::default()
    };
    let r = run_route(
        &task("SYNTH_GUEST_MALFORMED", 1),
        &s,
        &RouteOpts::default(),
        m,
    )
    .unwrap();
    assert_eq!(
        r["disposition"], "advance",
        "R3 goes red under a lax parse mode"
    );
    let real = run_route(
        &task("SYNTH_GUEST_MALFORMED", 2),
        &s,
        &RouteOpts::default(),
        Mutations::default(),
    )
    .unwrap();
    assert_eq!(real["disposition"], "rejected");
    let _ = std::fs::remove_dir_all(&s);
}

#[test]
fn trusting_the_claimed_hash_lets_the_hash_lie_advance() {
    let s = state("trust");
    let m = Mutations {
        trust_claim_hash: true,
        ..Mutations::default()
    };
    let r = run_route(
        &task("SYNTH_GUEST_HASH_LIE", 1),
        &s,
        &RouteOpts::default(),
        m,
    )
    .unwrap();
    assert_eq!(r["disposition"], "advance");
    let _ = std::fs::remove_dir_all(&s);
}

#[test]
fn a_leaky_teardown_is_reported_not_hidden() {
    let s = state("leak");
    let m = Mutations {
        leak_every_teardown: true,
        ..Mutations::default()
    };
    let r = run_route(&task("print(1)", 1), &s, &RouteOpts::default(), m).unwrap();
    assert_eq!(r["teardown_clean"], false);
    assert_eq!(r["hygiene_ok"], false);
    let _ = std::fs::remove_dir_all(&s);
}
