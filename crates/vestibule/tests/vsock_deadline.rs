//! The vsock listener's timeout bounds the whole serve, not just the wait for
//! the base socket. Failure class: a guest that never connects, or connects and
//! stalls mid frame, holds the host listener forever.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use vestibule::{encode_frame, serve_vsock_one, ParseMode};

const TIMEOUT: Duration = Duration::from_secs(1);
const WATCH: Duration = Duration::from_secs(5);

fn base(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vsock-deadline-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let b = d.join("vsock.sock");
    std::fs::write(&b, b"").unwrap();
    b
}

fn serve(b: PathBuf, port: u16) -> mpsc::Receiver<(Result<String, String>, Duration)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let t0 = Instant::now();
        let r = serve_vsock_one(&b, port, ParseMode::Enforce, TIMEOUT)
            .map(|m| m.task_id)
            .map_err(|e| e.to_string());
        let _ = tx.send((r, t0.elapsed()));
    });
    rx
}

fn connect(b: &std::path::Path, port: u16) -> UnixStream {
    let path = PathBuf::from(format!("{}_{port}", b.display()));
    for _ in 0..50 {
        if let Ok(c) = UnixStream::connect(&path) {
            return c;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("listener never bound {}", path.display());
}

#[test]
fn vsock_guest_that_never_connects_errors_inside_the_deadline() {
    let rx = serve(base("none"), 61);
    let (r, took) = rx
        .recv_timeout(WATCH)
        .expect("listener still blocked after the watch");
    let err = r.expect_err("no guest connected, yet the listener returned a message");
    assert!(err.contains("timed out"), "{err}");
    assert!(took < TIMEOUT + Duration::from_secs(2), "{took:?}");
}

#[test]
fn vsock_guest_that_stalls_mid_frame_errors_inside_the_deadline() {
    let b = base("stall");
    let rx = serve(b.clone(), 62);
    let mut c = connect(&b, 62);
    c.write_all(&[0, 0]).unwrap(); // half a length header, then silence
    let (r, took) = rx
        .recv_timeout(WATCH)
        .expect("listener still blocked after the watch");
    assert!(r.is_err(), "{r:?}");
    assert!(took < TIMEOUT + Duration::from_secs(2), "{took:?}");
    drop(c);
}

#[test]
fn vsock_prompt_guest_is_still_served() {
    let b = base("ok");
    let rx = serve(b.clone(), 63);
    let mut c = connect(&b, 63);
    let body = serde_json::json!({"schema_version":1,"kind":"result","task_id":"t-ok","filename":"r.txt","body":"ok"}).to_string();
    c.write_all(&encode_frame(body.as_bytes()).unwrap())
        .unwrap();
    let (r, _) = rx.recv_timeout(WATCH).expect("listener did not return");
    assert_eq!(r, Ok("t-ok".to_string()));
}
