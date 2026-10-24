//! The unix socket listener has a deadline. Failure class: a guest that never
//! connects, or connects and stalls mid frame, holds the listener forever.
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use vestibule::{encode_frame, serve_one_with_deadline, ParseMode, ServeOpts, UDS_SERVE_DEADLINE};

const TIMEOUT: Duration = Duration::from_secs(1);
const WATCH: Duration = Duration::from_secs(5);

fn sock(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("uds-deadline-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("v.sock")
}

fn serve(p: PathBuf) -> mpsc::Receiver<(Result<String, String>, Duration)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let t0 = Instant::now();
        let r = serve_one_with_deadline(&p, ParseMode::Enforce, &ServeOpts::default(), TIMEOUT)
            .map(|m| m.task_id)
            .map_err(|e| e.to_string());
        let _ = tx.send((r, t0.elapsed()));
    });
    rx
}

fn connect(p: &std::path::Path) -> UnixStream {
    for _ in 0..50 {
        if let Ok(c) = UnixStream::connect(p) {
            return c;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("listener never bound {}", p.display());
}

#[test]
fn uds_guest_that_never_connects_errors_inside_the_deadline() {
    let rx = serve(sock("none"));
    let (r, took) = rx
        .recv_timeout(WATCH)
        .expect("listener still blocked after the watch");
    let err = r.expect_err("no guest connected, yet the listener returned a message");
    assert!(err.contains("timed out"), "{err}");
    assert!(took < TIMEOUT + Duration::from_secs(2), "{took:?}");
}

#[test]
fn uds_guest_that_stalls_mid_frame_errors_inside_the_deadline() {
    let p = sock("stall");
    let rx = serve(p.clone());
    let mut c = connect(&p);
    c.write_all(&[0, 0]).unwrap();
    let (r, took) = rx
        .recv_timeout(WATCH)
        .expect("listener still blocked after the watch");
    assert!(
        r.as_ref().err().is_some_and(|e| e.contains("timed out")),
        "{r:?}"
    );
    assert!(took < TIMEOUT + Duration::from_secs(2), "{took:?}");
    drop(c);
}

#[test]
fn uds_prompt_guest_is_still_served() {
    let p = sock("ok");
    let rx = serve(p.clone());
    let mut c = connect(&p);
    let body = serde_json::json!({"schema_version":1,"kind":"result","task_id":"t-ok","filename":"r.txt","body":"ok"}).to_string();
    c.write_all(&encode_frame(body.as_bytes()).unwrap())
        .unwrap();
    let (r, _) = rx.recv_timeout(WATCH).expect("listener did not return");
    assert_eq!(r, Ok("t-ok".to_string()));
}

#[test]
fn uds_default_serve_has_a_bounded_deadline() {
    assert!(UDS_SERVE_DEADLINE > Duration::ZERO);
    assert!(UDS_SERVE_DEADLINE <= Duration::from_secs(120));
}

/// A guest that sends one byte every 150 ms keeps each read short but the
/// whole frame long. The deadline holds over the frame, not over each read.
#[test]
fn uds_guest_that_drips_a_frame_errors_inside_the_deadline() {
    let p = sock("drip");
    let rx = serve(p.clone());
    let mut c = connect(&p);
    let body =
        br#"{"schema_version":1,"kind":"result","task_id":"drip","filename":"r.txt","body":"ok"}"#;
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    thread::spawn(move || {
        for byte in frame {
            if c.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(150));
        }
        thread::sleep(Duration::from_secs(20));
    });
    let (r, took) = rx
        .recv_timeout(WATCH)
        .expect("listener still blocked after the watch");
    assert!(
        r.as_ref().err().is_some_and(|e| e.contains("timed out")),
        "{r:?}"
    );
    assert!(took < TIMEOUT + Duration::from_secs(2), "{took:?}");
}
