# Deploy: jailer-launch privileged helper

## Critical: helper binary permissions

The helper **must** be installed **root-owned, mode `0755`, in a root-owned directory, and not writable by the Manager user (`landen`)**.

If the invoking user can rewrite `/usr/local/bin/jailer-launch`, the scoped `NOPASSWD` rule is equivalent to passwordless root.

Verify after install:

```bash
ls -la /usr/local/bin/jailer-launch
# expect: -rwxr-xr-x 1 root root ... /usr/local/bin/jailer-launch
namei -l /usr/local/bin/jailer-launch
# every directory in the path must not be group/world-writable; /usr/local/bin must not be owned by landen
```

## Build (unprivileged)

From `~/isolation-layer`:

```bash
cargo build --release -p jailer-launch -p isolation-manager
cargo test -p aegis-common -p jailer-launch
```

## Operator install (root steps — not performed by the agent)

```bash
cd ~/isolation-layer

# 1. Install helper (root-owned, not user-writable)
sudo install -o root -g root -m 0755 target/release/jailer-launch /usr/local/bin/jailer-launch

# 2. Install scoped sudoers fragment
sudo cp deploy/sudoers.d/aegis-jailer /etc/sudoers.d/aegis-jailer
sudo chown root:root /etc/sudoers.d/aegis-jailer
sudo chmod 0440 /etc/sudoers.d/aegis-jailer
sudo visudo -cf /etc/sudoers.d/aegis-jailer

# 3. End-to-end proof (Manager as normal user)
cargo run -p isolation-manager -- prove
```

## What stays unprivileged

- `isolation-manager` — never run with sudo
- All orchestration, boot confirm, vsock round-trip, host diff — normal user

## What acquires privilege

- Only `sudo /usr/local/bin/jailer-launch ...` via the scoped sudoers rule
- Helper validates jail id, allowlisted image paths, uid/gid vs `SUDO_UID`/`SUDO_GID`, cgroup v2 fixed
- Helper execs `/usr/local/bin/jailer` with `/usr/local/bin/firecracker` hardcoded — no caller-controlled exec-file

## End-to-end status

| Component | Status |
|---|---|
| `jailer-launch` helper + validation tests | **RECORD** (built, tests pass without root) |
| `isolation-manager` skeleton | **RECORD** (built) |
| Host-untouched diff harness | **RECORD** (in `aegis-common::host_snapshot`) |
| Proposed sudoers rule | **RECORD** (`deploy/sudoers.d/aegis-jailer`) |
| Manager launch/teardown under jailer | **BLOCKED** until operator runs install steps above |
