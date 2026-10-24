//! vsock_roundtrip (the prove vsock check) is bounded by its timeout. Failure
//! class: a guest that never connects, or connects and never closes, holds
//! prove forever because accept and read_to_end had no deadline.
//! Firecracker cannot boot on the dev host, so these tests use a socket stub:
//! a plain file as the vsock base and a unix socket peer on `<base>_<port>`,
//! the path Firecracker forwards guest connections to.
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aegis_common::firecracker::{vsock_roundtrip, FcError};

const TIMEOUT: Duration = Duration::from_secs(1);
const WATCH: Duration = Duration::from_secs(5);

fn base(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vsock-rt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let b = d.join("v.sock");
    std::fs::write(&b, b"").unwrap();
    b
}

fn roundtrip(b: PathBuf, port: u16) -> mpsc::Receiver<(Result<String, String>, Duration)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let t0 = Instant::now();
        let r = vsock_roundtrip(&b, port, TIMEOUT).map_err(|e| match e {
            FcError::Io(e) => format!("{:?}: {e}", e.kind()),
            e => e.to_string(),
        });
        let _ = tx.send((r, t0.elapsed()));
    });
    rx
}

fn connect(b: &Path, port: u16) -> UnixStream {
    let p = PathBuf::from(format!("{}_{port}", b.display()));
    for _ in 0..200 {
        if let Ok(c) = UnixStream::connect(&p) {
            return c;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("roundtrip never bound {}", p.display());
}

fn timed_out_inside(rx: mpsc::Receiver<(Result<String, String>, Duration)>) {
    let (r, took) = rx
        .recv_timeout(WATCH)
        .expect("vsock_roundtrip still blocked after the watch");
    assert!(
        r.as_ref().err().is_some_and(|e| e.starts_with("TimedOut")),
        "{r:?}"
    );
    assert!(took < TIMEOUT + Duration::from_secs(2), "{took:?}");
}

#[test]
fn roundtrip_guest_that_never_connects_errors_inside_the_deadline() {
    timed_out_inside(roundtrip(base("none"), 52));
}

#[test]
fn roundtrip_guest_that_never_closes_errors_inside_the_deadline() {
    let b = base("open");
    let rx = roundtrip(b.clone(), 53);
    let mut c = connect(&b, 53);
    c.write_all(b"ping").unwrap();
    timed_out_inside(rx);
    drop(c);
}

#[test]
fn roundtrip_guest_that_drips_errors_inside_the_deadline() {
    let b = base("drip");
    let rx = roundtrip(b.clone(), 54);
    let mut c = connect(&b, 54);
    thread::spawn(move || {
        for _ in 0..100 {
            if c.write_all(b"p").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(150));
        }
    });
    timed_out_inside(rx);
}

#[test]
fn roundtrip_prompt_guest_gets_its_pong() {
    let b = base("ok");
    let rx = roundtrip(b.clone(), 55);
    let mut c = connect(&b, 55);
    c.write_all(b"ping").unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut pong = Vec::new();
    let _ = c.read_to_end(&mut pong);
    let (r, _) = rx.recv_timeout(WATCH).expect("roundtrip did not return");
    assert_eq!(r, Ok("ping".to_string()));
    assert_eq!(pong, b"pong:ping");
}
