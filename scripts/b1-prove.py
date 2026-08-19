#!/usr/bin/env python3
"""B1: boot Firecracker microVM, measure BS-00, run isolation spot-checks."""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
FC_SYSTEM = Path("/usr/local/bin/firecracker")
JAILER_SYSTEM = Path("/usr/local/bin/jailer")
ART = ROOT / "artifacts" / "x86_64"
JAILER_BASE = ROOT / "jailer"


@dataclass
class LaunchContext:
    mode: str
    run_dir: Path
    api_sock: Path
    vsock_uds: Path
    log_path: Path
    proc: subprocess.Popen[str]
    jail_id: str | None = None
    jail_root: Path | None = None


def curl_api(sock: Path, method: str, path: str, body: dict | None = None) -> str:
    cmd = [
        "curl",
        "-fsS",
        "--unix-socket",
        str(sock),
        "-X",
        method,
        f"http://localhost{path}",
    ]
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


def wait_for_patterns(
    out_q: queue.Queue[str], patterns: list[str], timeout: float
) -> tuple[float, str]:
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
    raise TimeoutError(
        f"patterns {patterns!r} not seen in {timeout}s; tail={buf[-800:]!r}"
    )


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


def vm_config_dict(kernel: str, rootfs: str, vsock_path: str) -> dict:
    return {
        "boot-source": {
            "kernel_image_path": kernel,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/bin/init rw",
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": rootfs,
                "is_root_device": True,
                "is_read_only": False,
            }
        ],
        "machine-config": {"vcpu_count": 2, "mem_size_mib": 512},
        "vsock": {"guest_cid": 3, "uds_path": vsock_path},
    }


def hardlink_or_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def prepare_jail_root(jail_id: str, run_dir: Path) -> tuple[Path, Path]:
    jail_root = JAILER_BASE / "firecracker" / jail_id / "root"
    if jail_root.exists():
        shutil.rmtree(jail_root.parent)
    jail_root.mkdir(parents=True, exist_ok=True)

    hardlink_or_copy(ART / "vmlinux-6.1.176", jail_root / "vmlinux-6.1.176")
    hardlink_or_copy(ART / "ubuntu-24.04.ext4", jail_root / "ubuntu-24.04.ext4")

    vsock_uds = jail_root / "vsock.sock"
    cfg = vm_config_dict("vmlinux-6.1.176", "ubuntu-24.04.ext4", "vsock.sock")
    (jail_root / "vm_config.json").write_text(json.dumps(cfg))
    shutil.copy2(jail_root / "vm_config.json", run_dir / "vm_config.jailed.json")
    return jail_root, vsock_uds


def launch_direct(run_dir: Path) -> LaunchContext:
    api_sock = run_dir / "firecracker.socket"
    vsock_uds = run_dir / "vsock.sock"
    log_path = run_dir / "firecracker.log"
    cfg_path = run_dir / "vm_config.json"
    cfg_path.write_text(
        json.dumps(
            vm_config_dict(
                str(ART / "vmlinux-6.1.176"),
                str(ART / "ubuntu-24.04.ext4"),
                str(vsock_uds),
            )
        )
    )

    env = os.environ.copy()
    env["PATH"] = f"{BIN}:{env.get('PATH', '')}"
    fc_bin = BIN / "firecracker" if (BIN / "firecracker").exists() else FC_SYSTEM

    proc = subprocess.Popen(
        [
            str(fc_bin),
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
    return LaunchContext("direct", run_dir, api_sock, vsock_uds, log_path, proc)


def launch_jailed(run_dir: Path) -> LaunchContext:
    if not JAILER_SYSTEM.is_file():
        raise RuntimeError(f"jailer not found at {JAILER_SYSTEM}")
    if not FC_SYSTEM.is_file():
        raise RuntimeError(f"firecracker not found at {FC_SYSTEM}")

    jail_id = f"b1-jailed-{int(time.time())}"
    jail_root, vsock_uds = prepare_jail_root(jail_id, run_dir)
    api_sock = jail_root / "api.sock"
    log_path = jail_root / "firecracker.log"

    cmd = [
        "sudo",
        str(JAILER_SYSTEM),
        "--id",
        jail_id,
        "--exec-file",
        str(FC_SYSTEM),
        "--uid",
        str(os.getuid()),
        "--gid",
        str(os.getgid()),
        "--chroot-base-dir",
        str(JAILER_BASE),
        "--cgroup-version",
        "2",
        "--",
        "--api-sock",
        "api.sock",
        "--config-file",
        "vm_config.json",
        "--log-path",
        "firecracker.log",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"failed to exec jailer: {exc}") from exc

    # Fail fast if sudo could not start jailer.
    time.sleep(0.5)
    if proc.poll() is not None:
        output = proc.stdout.read() if proc.stdout else ""
        if "sudo:" in output or proc.returncode != 0:
            raise PermissionError(
                "jailer launch requires root via sudo.\n"
                "Operator command:\n"
                f"  sudo {sys.executable} {Path(__file__).resolve()} --mode jailed\n"
                f"sudo output:\n{output}"
            )

    deadline = time.time() + 10
    while not api_sock.exists() and time.time() < deadline:
        if proc.poll() is not None:
            output = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(
                f"jailer exited early (code={proc.returncode}):\n{output}"
            )
        time.sleep(0.1)
    if not api_sock.exists():
        proc.terminate()
        raise RuntimeError("jailer did not create api.sock within 10s")

    return LaunchContext(
        "jailed", run_dir, api_sock, vsock_uds, log_path, proc, jail_id, jail_root
    )


def teardown(ctx: LaunchContext) -> None:
    try:
        curl_api(ctx.api_sock, "PUT", "/actions", {"action_type": "SendCtrlAltDel"})
    except subprocess.CalledProcessError:
        pass
    time.sleep(1)
    ctx.proc.terminate()
    try:
        ctx.proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        ctx.proc.kill()
        ctx.proc.wait(timeout=5)


def run_prove(mode: str) -> int:
    run_dir = ROOT / "run" / f"b1-{mode}-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    serial_log = run_dir / "serial.log"

    try:
        ctx = launch_jailed(run_dir) if mode == "jailed" else launch_direct(run_dir)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out_q: queue.Queue[str] = queue.Queue()
    threading.Thread(target=serial_reader, args=(ctx.proc, out_q), daemon=True).start()
    print(f"Launch mode={ctx.mode} at t=0.000s")

    t0 = time.perf_counter()
    try:
        _, boot_buf = wait_for_patterns(
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
        teardown(ctx)
        print("BOOT_FAIL:", exc, file=sys.stderr)
        print("serial_tail:", tail[-2000:], file=sys.stderr)
        if ctx.log_path.exists():
            print("log_tail:", ctx.log_path.read_text()[-2000:], file=sys.stderr)
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
        assert ctx.proc.stdin is not None
        ctx.proc.stdin.write(cmd + "\n")
        ctx.proc.stdin.flush()
        chunk = drain_for(out_q, 3)
        checks[cmd] = chunk
        print(f"=== guest: {cmd} ===")
        print(chunk)

    vsock_result: dict = {"ok": False}
    vsock_thread = threading.Thread(
        target=lambda: vsock_result.update(vsock_roundtrip(ctx.vsock_uds, port=52)),
        daemon=True,
    )
    vsock_thread.start()
    time.sleep(0.2)
    assert ctx.proc.stdin is not None
    ctx.proc.stdin.write(
        "ls /dev/vsock; command -v socat; echo hello-from-guest | socat - VSOCK-CONNECT:2:52; echo VS_EXIT=$?\n"
    )
    ctx.proc.stdin.flush()
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
        "mode": ctx.mode,
        "jail_id": ctx.jail_id,
        "jail_root": str(ctx.jail_root) if ctx.jail_root else None,
        "time_to_userspace_ms": round(t_init * 1000, 1),
        "time_to_workload_ms": round(t_work * 1000, 1),
        "vsock_roundtrip": vsock_result,
        "checks": checks,
    }
    (run_dir / "b1_results.json").write_text(json.dumps(results, indent=2))

    teardown(ctx)
    print(f"run_dir={run_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="B1 Firecracker boot proof")
    parser.add_argument(
        "--mode",
        choices=("direct", "jailed"),
        default="direct",
        help="direct: firecracker binary; jailed: /usr/local/bin/jailer (requires sudo)",
    )
    args = parser.parse_args()
    return run_prove(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
