//! `sandbox-demo route`: the door the capability gate calls for an ISOLATE
//! verdict. One task arrives on stdin and one receipt leaves on stdout.
//!
//! STUBBED (real: false). The VM is the stub host from this crate: a fresh
//! jail id and a real jail folder per task, fake VMM pids, no Firecracker
//! process. Everything after the guest is real: the guest frame goes over a
//! Unix socket to the vestibule listener in enforce mode, rejects go to the
//! reject log, accepted bodies pass the dropbox host guard and the inspector
//! stage, the disposition comes from decide_disposition on the host hash,
//! and launch, verdict and teardown rows go on the decision chain.
//!
//! The stub guest reads synthetic markers from the task text to pick what it
//! sends, so the gate's tests and the S14 scenario can plant each outcome.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use aegis_common::{assert_host_vmm_hygiene, ChainVerdict, DecisionChain};
use dropbox::{content_hash, HostGuard, Shelf};
use inspector::{decide_disposition, stage_from_guard};
use serde_json::{json, Map, Value};
use vestibule::schema::MAX_BODY_BYTES;
use vestibule::{serve_one_with_opts, ParseMode, RejectLog, ServeOpts, SCHEMA_VERSION};

use crate::{result_json, short_err, stub_claim, Mutations, Rng, StubHost, Wire};

pub const TASK_SCHEMA: &str = "isolate-route-task/1";
pub const RECEIPT_SCHEMA: &str = "isolate-route-receipt/1";
/// Largest task the door reads. The gate refuses bigger tasks before launch.
pub const MAX_TASK_BYTES: usize = 64 * 1024;
const TASK_KEYS: [&str; 7] = [
    "schema",
    "route_ticket",
    "tool_call_id",
    "tool",
    "skill",
    "args",
    "gate_decision_sha256",
];

/// Exit codes. 0 is a receipt (any disposition).
pub const EXIT_REFUSED: i32 = 2;
pub const EXIT_GUEST_DEADLINE: i32 = 4;
pub const EXIT_CHAIN: i32 = 5;
pub const EXIT_IO: i32 = 6;

#[derive(Debug, Clone)]
pub struct RouteOpts {
    /// How long the door waits for the guest frame. The gate's own deadline
    /// (30 s stub) sits above this one, so the door answers before the gate gives up.
    pub guest_deadline: Duration,
}

impl Default for RouteOpts {
    fn default() -> Self {
        RouteOpts {
            guest_deadline: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
pub struct RouteError {
    pub code: i32,
    pub message: String,
}

fn err(code: i32, message: impl Into<String>) -> RouteError {
    RouteError {
        code,
        message: message.into(),
    }
}

fn io(e: impl std::fmt::Display) -> RouteError {
    err(EXIT_IO, format!("door io error: {e}"))
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Check the task envelope. Every refusal happens before any launch.
pub fn parse_task(input: &[u8]) -> Result<Map<String, Value>, RouteError> {
    let refuse = |why: &str| err(EXIT_REFUSED, format!("task refused: {why}"));
    if input.len() > MAX_TASK_BYTES {
        return Err(refuse(&format!("over {MAX_TASK_BYTES} bytes")));
    }
    let v: Value = serde_json::from_slice(input).map_err(|_| refuse("not JSON"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| refuse("not an object"))?
        .clone();
    for k in obj.keys() {
        if !TASK_KEYS.contains(&k.as_str()) {
            return Err(refuse(&format!("unknown field {k:?}")));
        }
    }
    for k in TASK_KEYS {
        if !obj.contains_key(k) {
            return Err(refuse(&format!("missing field {k:?}")));
        }
    }
    let text = |k: &str| {
        obj[k]
            .as_str()
            .ok_or_else(|| refuse(&format!("{k} is not a string")))
    };
    if text("schema")? != TASK_SCHEMA {
        return Err(refuse("schema is not isolate-route-task/1"));
    }
    if !is_hex(text("route_ticket")?, 32) {
        return Err(refuse("route_ticket is not 32 hex"));
    }
    let call = text("tool_call_id")?;
    if call.is_empty() || call.len() > 128 {
        return Err(refuse("tool_call_id empty or over 128"));
    }
    let tool = text("tool")?;
    if tool.is_empty() || tool.len() > 128 {
        return Err(refuse("tool empty or over 128"));
    }
    if text("skill")?.len() > 128 {
        return Err(refuse("skill over 128"));
    }
    if !obj["args"].is_object() {
        return Err(refuse("args is not an object"));
    }
    if !is_hex(text("gate_decision_sha256")?, 64) {
        return Err(refuse("gate_decision_sha256 is not 64 hex"));
    }
    Ok(obj)
}

/// sha256 over the task fields as compact JSON with sorted keys, the same
/// bytes the gate hashes (json.dumps sort_keys, no spaces, ensure_ascii off).
pub fn task_sha256(task: &Map<String, Value>) -> String {
    let sorted: BTreeMap<&str, &Value> = TASK_KEYS.iter().map(|k| (*k, &task[*k])).collect();
    content_hash(canonical(&json!(sorted)).as_bytes())
}

fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<&String, &Value> = m.iter().collect();
            let parts: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => serde_json::to_string(other).unwrap(),
    }
}

fn fresh_id() -> Result<String, RouteError> {
    let mut b = [0u8; 8];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(io)?;
    Ok(format!("jail-route-{:016x}", u64::from_be_bytes(b)))
}

/// What the stub guest does, picked from markers in the task text.
enum Guest {
    Send(Wire),
    Silent,
    Stall,
}

fn guest_for(task_text: &str, task_digest: &str, rng_seed: u64) -> (Guest, bool) {
    let mut rng = Rng::new(rng_seed);
    let tid = format!("t-{}", &task_digest[..16]);
    let mut body = format!(
        "box result for task {task_digest} value {:016x}",
        rng.next_u64()
    );
    for m in ["SYNTH_MARKER_SUSPECT", "SYNTH_MARKER_FAILED"] {
        if task_text.contains(m) {
            body.push(' ');
            body.push_str(m);
        }
    }
    let hash_lie = task_text.contains("SYNTH_GUEST_HASH_LIE");
    if task_text.contains("SYNTH_GUEST_SILENT") {
        return (Guest::Silent, false);
    }
    if task_text.contains("SYNTH_GUEST_STALL") {
        return (Guest::Stall, false);
    }
    let kind = if task_text.contains("SYNTH_GUEST_MALFORMED") {
        "exec"
    } else {
        "result"
    };
    if task_text.contains("SYNTH_GUEST_OVERSIZE") {
        body = format!("{body} {}", "A".repeat(MAX_BODY_BYTES + 64));
    }
    let payload = serde_json::to_vec(&result_json(
        json!(SCHEMA_VERSION),
        kind,
        &tid,
        "artifact.txt",
        &body,
    ))
    .unwrap();
    (Guest::Send(Wire::Json(payload)), hash_lie)
}

/// What the door got from the listener thread.
enum Delivery {
    Answer(Result<vestibule::ResultMessage, vestibule::ListenError>),
    Deadline,
    ListenerDied,
}

/// Serve one guest connection with the real listener, under a deadline.
/// The listener itself has no accept or read deadline (suspect b), so the
/// door holds the deadline: on expiry it stops waiting and the process exit
/// ends the listener thread.
fn deliver_with_deadline(
    sock: &Path,
    guest: Guest,
    mode: ParseMode,
    reject: &RejectLog,
    deadline: Duration,
    listener_panics: bool,
) -> Delivery {
    let (tx, rx) = mpsc::channel();
    let path = sock.to_path_buf();
    let opts = ServeOpts {
        reject_log: Some(reject.clone()),
        harden: false,
    };
    thread::spawn(move || {
        if listener_panics {
            panic!("listener mutation: panic before serve");
        }
        let _ = tx.send(serve_one_with_opts(&path, mode, &opts));
    });
    let gpath = sock.to_path_buf();
    thread::spawn(move || {
        let wire = match guest {
            Guest::Silent => return,
            Guest::Stall => vec![0u8, 0u8],
            Guest::Send(w) => w.bytes(),
        };
        let mut stream = None;
        for _ in 0..2000 {
            if let Ok(s) = UnixStream::connect(&gpath) {
                stream = Some(s);
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let Some(mut stream) = stream else { return };
        let _ = stream.write_all(&wire);
        if wire.len() == 2 {
            // Stall: hold the socket open mid frame.
            thread::sleep(Duration::from_secs(3600));
        }
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut ack = Vec::new();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.read_to_end(&mut ack);
    });
    // A listener that dies drops its sender, which is not a slow guest.
    let out = match rx.recv_timeout(deadline) {
        Ok(v) => Delivery::Answer(v),
        Err(mpsc::RecvTimeoutError::Timeout) => Delivery::Deadline,
        Err(mpsc::RecvTimeoutError::Disconnected) => Delivery::ListenerDied,
    };
    let _ = fs::remove_file(sock);
    out
}

/// Run one task. Returns the receipt; every error is a refusal or a failure
/// the caller must treat as a block.
pub fn run_route(
    input: &[u8],
    state: &Path,
    opts: &RouteOpts,
    m: Mutations,
) -> Result<Value, RouteError> {
    let task = parse_task(input)?;
    let digest = task_sha256(&task);
    let call = task["tool_call_id"].as_str().unwrap().to_string();
    let ticket = task["route_ticket"].as_str().unwrap().to_string();
    let task_text = canonical(&task["args"]);

    fs::create_dir_all(state).map_err(io)?;
    let chain = DecisionChain::open(state.join("decision-chain.jsonl"));
    if state.join("decision-chain.jsonl").exists() {
        chain
            .verify()
            .map_err(|e| err(EXIT_CHAIN, format!("door chain does not verify: {e}")))?;
    }
    let reject = RejectLog::open(state.join("vestibule-rejects.jsonl")).map_err(io)?;
    let guard = HostGuard::new(Shelf::open(state.join("shelf")).map_err(io)?);
    let stage_root = state.join("stages");
    let seed = u64::from_str_radix(&digest[..16], 16).unwrap_or(0);
    let mut rng = Rng::new(seed);
    let mut host = StubHost::new(&state.join("host").join(&ticket), &mut rng);
    let jail = fresh_id()?;
    let session = format!("route-{ticket}");
    let row = |v: ChainVerdict, why: &str| {
        chain
            .append(&jail, v, why, Some(&session), Some(&call))
            .map(|_| ())
            .map_err(|e| err(EXIT_CHAIN, e.to_string()))
    };

    let before = host.snapshot();
    host.launch(&jail);
    row(
        ChainVerdict::Launch,
        "stub vm launch for an isolate route (no KVM on this host)",
    )?;

    let (guest, hash_lie) = guest_for(&task_text, &digest, seed);
    let mode = if m.vestibule_disabled {
        ParseMode::Disabled
    } else {
        ParseMode::Enforce
    };
    let sock = state.join(format!("{ticket}.sock"));
    let got = deliver_with_deadline(
        &sock,
        guest,
        mode,
        &reject,
        opts.guest_deadline,
        m.listener_panics,
    );

    let finish = |host: &mut StubHost| -> Result<(bool, bool), RouteError> {
        let leak = m.leak_every_teardown;
        host.teardown(&jail, leak);
        let jail_gone = !host.base.join(&jail).exists();
        row(ChainVerdict::Teardown, "stub vm teardown")?;
        let hygiene = assert_host_vmm_hygiene(&before, &host.snapshot()).is_ok();
        host.teardown(&jail, false);
        let _ = fs::remove_dir_all(state.join("host").join(&ticket));
        Ok((jail_gone, hygiene))
    };

    let (disposition, reason, result_hash) = match got {
        Delivery::ListenerDied => {
            row(
                ChainVerdict::FailClosed,
                "listener died before the guest answered",
            )?;
            finish(&mut host)?;
            return Err(err(EXIT_IO, "listener died before the guest answered"));
        }
        Delivery::Deadline => {
            row(
                ChainVerdict::FailClosed,
                "guest never answered inside the door deadline",
            )?;
            finish(&mut host)?;
            return Err(err(
                EXIT_GUEST_DEADLINE,
                format!(
                    "guest never answered within {} ms",
                    opts.guest_deadline.as_millis()
                ),
            ));
        }
        Delivery::Answer(Err(e)) => {
            let why = format!("vestibule: {}", short_err(&e));
            row(ChainVerdict::Reject, &why)?;
            ("rejected".to_string(), why, content_hash(b""))
        }
        Delivery::Answer(Ok(msg)) => {
            let hash = guard.handoff_roundtrip(msg.body.as_bytes()).map_err(io)?;
            let staged = stage_from_guard(&guard, &hash, &stage_root).map_err(io)?;
            let bytes = fs::read(&staged.blob_path).map_err(io)?;
            let mut claim = stub_claim(&bytes, &staged.hash);
            if hash_lie {
                claim.content_hash = content_hash(format!("other bytes {call}").as_bytes());
            }
            let host_hash = if m.trust_claim_hash {
                claim.content_hash.clone()
            } else {
                staged.hash.clone()
            };
            let d = decide_disposition(&claim, &host_hash);
            let why = format!("disposition {}", d.as_str());
            row(ChainVerdict::Prove, &why)?;
            staged.dispose().map_err(io)?;
            (d.as_str().to_string(), why, hash)
        }
    };
    let (teardown_clean, hygiene_ok) = finish(&mut host)?;
    let tip = chain
        .tip_hash()
        .map_err(|e| err(EXIT_CHAIN, e.to_string()))?;
    let receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "route_ticket": ticket,
        "tool_call_id": call,
        "task_sha256": digest,
        "gate_decision_sha256": task["gate_decision_sha256"],
        "jail_id": jail,
        "disposition": disposition,
        "reason": reason,
        "result_sha256": result_hash,
        "teardown_clean": teardown_clean,
        "hygiene_ok": hygiene_ok,
        "chain_tip": tip,
        "real": false,
        "mode": "STUBBED",
    });
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state.join("receipts.jsonl"))
        .map_err(io)?;
    writeln!(f, "{receipt}").map_err(io)?;
    Ok(receipt)
}

/// Entry for `sandbox-demo route`. Returns the process exit code.
pub fn main_route(args: &[String]) -> i32 {
    let mut state: Option<PathBuf> = None;
    let mut opts = RouteOpts::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--state" => state = it.next().map(PathBuf::from),
            "--guest-deadline-ms" => match it.next().and_then(|v| v.parse::<u64>().ok()) {
                Some(ms) if (1..=120_000).contains(&ms) => {
                    opts.guest_deadline = Duration::from_millis(ms)
                }
                _ => {
                    eprintln!("route: --guest-deadline-ms takes 1 to 120000");
                    return EXIT_REFUSED;
                }
            },
            other => {
                eprintln!("route: unknown argument {other:?}");
                return EXIT_REFUSED;
            }
        }
    }
    let Some(state) = state else {
        eprintln!("usage: sandbox-demo route --state DIR [--guest-deadline-ms N] < task.json");
        return EXIT_REFUSED;
    };
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_TASK_BYTES as u64 + 1)
        .read_to_end(&mut input)
    {
        eprintln!("route: door io error: {e}");
        return EXIT_IO;
    }
    match run_route(&input, &state, &opts, Mutations::default()) {
        Ok(r) => {
            println!("{r}");
            0
        }
        Err(e) => {
            eprintln!("route: {}", e.message);
            e.code
        }
    }
}
