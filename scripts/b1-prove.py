#!/usr/bin/env python3
"""B1: boot Firecracker microVM, measure BS-00, run isolation spot-checks."""

from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
ART = ROOT / "artifacts" / "x86_64"
RUN = ROOT / "run" / f"b1-{int(time.time())}"


def curl_api(sock: Path, method: str, path: str, body: dict | None = None) -> str:
    cmd = ["curl", "-fsS", "--unix-socket", str(sock), "-X", method, f"http://localhost{path}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    return subprocess.check_output(cmd, text=True)


def serial_reader(proc: subprocess.Popen[str], out_q: queue.Queue[str]) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        out_q.put(line)


def drain_for(out_q: queue.Queue[str], seconds: float) -> str:
    deadline = time.time() + seconds
    chunks: list[str] = []
    while time.time() < deadline:
        try:
            chunks.append(out_q.get(timeout=0.2))
        except queue.Empty:
            pass
    return "".join(chunks)


def wait_for_patterns(out_q: queue.Queue[str], patterns: list[str], timeout: float) -> tuple[float, str]:
    start = time.monotonic()
    buf = ""
    while time.monotonic() - start < timeout:
        try:
            buf += out_q.get(timeout=0.2)
        except queue.Empty:
            continue
        for pat in patterns:
            if pat in buf:
                return time.monotonic() - start, buf
    raise TimeoutError(f"patterns {patterns!r} not seen in {timeout}s; tail={buf[-800:]!r}")


def vsock_roundtrip(uds_path: Path, port: int = 52, timeout: float = 60) -> dict:
    result: dict = {"ok": False, "port": port}
    listen_path = Path(f"{uds_path}_{port}")
    deadline = time.time() + timeout
    while not uds_path.exists() and time.time() < deadline:
        time.sleep(0.1)
    if not uds_path.exists():
        result["error"] = "vsock base uds not created"
        return result

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(listen_path))
    srv.listen(1)
    srv.settimeout(timeout)
    conn, _ = srv.accept()
    data = conn.recv(4096)
    conn.sendall(b"pong:" + data)
    conn.close()
    srv.close()
    listen_path.unlink(missing_ok=True)
    result["rx"] = data.decode("utf-8", errors="replace")
    result["ok"] = True
    return result


def main() -> int:
    RUN.mkdir(parents=True, exist_ok=True)
    api_sock = RUN / "firecracker.socket"
    vsock_uds = RUN / "vsock.sock"
    log_path = RUN / "firecracker.log"
    serial_log = RUN / "serial.log"

    vm_config = {
        "boot-source": {
            "kernel_image_path": str(ART / "vmlinux-6.1.176"),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/bin/init rw",
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": str(ART / "ubuntu-24.04.ext4"),
                "is_root_device": True,
                "is_read_only": False,
            }
        ],
        "machine-config": {"vcpu_count": 2, "mem_size_mib": 512},
        "vsock": {"guest_cid": 3, "uds_path": str(vsock_uds)},
    }
    cfg_path = RUN / "vm_config.json"
    cfg_path.write_text(json.dumps(vm_config))

    env = os.environ.copy()
    env["PATH"] = f"{BIN}:{env.get('PATH', '')}"

    out_q: queue.Queue[str] = queue.Queue()
    t0 = time.perf_counter()
    fc = subprocess.Popen(
        [
            str(BIN / "firecracker"),
            "--api-sock",
            str(api_sock),
            "--config-file",
            str(cfg_path),
            "--log-path",
            str(log_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        bufsize=1,
    )
    threading.Thread(target=serial_reader, args=(fc, out_q), daemon=True).start()
    print(f"Firecracker launched at t=0.000s (config-file auto-starts VM)")

    try:
        init_elapsed, boot_buf = wait_for_patterns(
            out_q,
            [
                "Reached target multi-user",
                "Reached target Multi-User",
                "login:",
                "cloud-init",
            ],
            timeout=120,
        )
    except TimeoutError as exc:
        tail = drain_for(out_q, 2)
        serial_log.write_text(tail)
        fc.terminate()
        print("BOOT_FAIL:", exc, file=sys.stderr)
        print("serial_tail:", tail[-2000:], file=sys.stderr)
        return 1

    t_init = time.perf_counter() - t0
    print(f"BS-00 time_to_userspace_ms={t_init * 1000:.1f}")
    serial_log.write_text(boot_buf)

    checks: dict[str, str] = {}
    for cmd in [
        "ls /dev/kvm 2>&1",
        "ps aux 2>&1 | grep -E 'firecracker|jailer' | grep -v grep || echo NO_VMM_PROCS",
        "ls /home/landen 2>&1 || echo NO_HOST_HOME",
        "uname -a",
    ]:
        assert fc.stdin is not None
        fc.stdin.write(cmd + "\n")
        fc.stdin.flush()
        chunk = drain_for(out_q, 3)
        checks[cmd] = chunk
        print(f"=== guest: {cmd} ===")
        print(chunk)

    vsock_result: dict = {"ok": False}
    vsock_thread = threading.Thread(
        target=lambda: vsock_result.update(vsock_roundtrip(vsock_uds, port=52)),
        daemon=True,
    )
    vsock_thread.start()
    time.sleep(0.2)
    assert fc.stdin is not None
    fc.stdin.write("ls /dev/vsock; command -v socat; echo hello-from-guest | socat - VSOCK-CONNECT:2:52; echo VS_EXIT=$?\n")
    fc.stdin.flush()
    guest_vsock_out = drain_for(out_q, 5)
    print("=== guest vsock client ===")
    print(guest_vsock_out)
    vsock_thread.join(timeout=20)
    print(f"vsock_roundtrip_ok={vsock_result.get('ok')}")
    if vsock_result.get("rx"):
        print(f"vsock_rx={vsock_result['rx']!r}")

    t_work = time.perf_counter() - t0
    print(f"BS-00 time_to_workload_ms={t_work * 1000:.1f}")

    results = {
        "time_to_userspace_ms": round(t_init * 1000, 1),
        "time_to_workload_ms": round(t_work * 1000, 1),
        "vsock_roundtrip": vsock_result,
        "checks": checks,
    }
    (RUN / "b1_results.json").write_text(json.dumps(results, indent=2))

    curl_api(api_sock, "PUT", "/actions", {"action_type": "SendCtrlAltDel"})
    time.sleep(1)
    fc.terminate()
    try:
        fc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        fc.kill()

    print(f"run_dir={RUN}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
