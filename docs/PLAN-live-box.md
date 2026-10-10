# PLAN: live Firecracker box (build, test, background, log)

Day: 2026-10-03
Roof: isolation-layer (not Job_Search sprint)
Owner: Landen (sudo, substrate, enable service) ; Cursor/CC (code, tests, receipts)
Approved-by-ask: Landen 2026-10-03 (stop parking the box as a label; want it built, tested, functional, background, logged)

## Program locks (2026-10-03 brainstorm)

- **Subject seat:** Hermes `profiles/tester` at minimum privilege. No Honcho on tester. Isolated CG/atoms copies. Not Aegis.
- **Partner seat:** `profiles/aegis` keeps Honcho and daily partner surface. Harden Aegis separately; do not gut it to get a canary.
- **Guest path (Landen chose C):** Suite + observe firings on WSL `tester` now. Cases that claim the box wait for live-box green (manager + host logs), then join. Refuse `four_plane_complete` until join is dest-read.
- **Atoms enforce / judge apply:** still Landen GO after would-deny adjudication on tester. Not bundled into first done line.
- **First campaign done (Landen chose A):** Charter/spec this sitting, then execute live-box + tester observe + suite FALSE-ALLOW growth. No atoms enforce in the first done line. Career lab SPEAK/gateway/wall stays parallel (CC verify wall); not a gate on this program.
- **Council 2026-10-03:** six coarse todos ≠ full coverage. Expanded plan SoT: `~/.cursor/plans/four-plane_program_a_13a585ba.plan.md` (W0–W6, join schema, remainder register, SPEAK unlock = prove exit 0 only).
- **Charter (approved execute 2026-10-03):** `The_Boswell_Archive/Agent/Security/corpus-capture/specs/2026-10-03-four-plane-spine-design.md` — Frame, locks, join schema, remainder, branch names, hop/socket decisions. Landen GO = implement order on that plan.

---

# Q

Can Landen boot a jailed Firecracker microVM from a command he can repeat, leave the **manager** running, destroy the **guest** after each task, and show a host-side hash-chained log of launches, rejects, and teardowns?

# ATTACK

On **aegisbox** (not WSL): dest-read `/dev/kvm` and `/dev/vhost-vsock`, then `cargo run -p isolation-manager -- prove` after operator install per `deploy/INSTALL.md`. Path already on disk: `scripts/b1-prove.py`, `docs/b1-record.md`, `docs/b2-record.md`.

# SCALE

Frontier lab. One campaign on this roof. Instrument, measure, residual. Then stop.

# Motion

Gate: scheduled workstreams with receipts. Walks: talk tracks after dest-read prove.

# Done

- `isolation-manager prove` exit 0 on aegisbox this sitting (or a dated receipt that dest-reads a failed closed prove).
- Host decision jsonl verifies; tamper fails.
- Vestibule reject log append-only.
- systemd unit: manager up, no idle guest.
- SPEAK cites that prove command only after dest-read. Sprint still `firecracker_started: false`.

# Fence

No sudo by agents. No WSL vsock as primary substrate. No `dispatch.py` Firecracker. No THE BODY. No north-star / always_invoked flip. No commit unless Landen says commit. Guest bytes never trusted as log truth.

# Will NOT do

Claim 125 ms. Claim maximum isolation under nested Hyper-V. Claim the career Python lab starts a VM. Run a long-lived guest as "background."

---

# Why the career lab did not start Firecracker

`Job_Search/prep/agent-security-lab` is a stdlib, no-network, claim-safe sprint. Isolation there is a **label** so scores stay reproducible on any PC. That protected interviews. It did not teach the box.

The box already lives here: Rust workspace, B1 boot RECORD on aegisbox, B2 manager + jailer-launch, B3 vestibule listener + reject jsonl. Today's WSL session (`LandensPC`) has `/dev/kvm` and **no** `firecracker` binary. Spec v1.5: WSL2 kernel has no `CONFIG_VHOST_VSOCK`; dedicated Linux VM is the substrate.

---

# Architecture

```
Windows host
  -> aegisbox (Linux VM, Firecracker is L1)
       -> isolation-manager (unprivileged, long-lived)
            -> sudo jailer-launch (scoped, root-owned helper)
                 -> jailer -> firecracker v1.16.1
                      -> ephemeral guest (destroyed)
            -> host logs: VMM file, reject jsonl, decision chain jsonl
```

Background = **manager stays up**. Guest = **one task, then destroy**. Idle = no microVM.

Manager today is CLI (`prove` then exit). Functional background is systemd (user or system, non-root) + unix socket or oneshot-on-job. Health: `systemctl is-active` and last chain row verifies.

---

# Logging (three host layers)

1. **VMM/jailer** — existing `log_path` / `--log-path`. Do not treat serial as SoT.
2. **Vestibule reject log** — `crates/vestibule/src/reject.rs`, jsonl, never truncate. systemd names the path.
3. **Decision chain (to build, TDD)** — host jsonl: `prev` + sha256. Fields: jail_id, layer=box, verdict (launch|prove|teardown|reject|fail_closed|host_untouched), reason, timestamp. No guest payload, no prompt text. Verify like `run_lab.verify`. Fail-closed prove still appends.

CISO sentence: the record is kept because boxes boot and die, not because we wrote a page.

---

# Operator vs agent

**Landen (privilege):** boot aegisbox; confirm kvm + vhost-vsock + kvm group; `sudo scripts/install-firecracker.sh`; `scripts/fetch-golden-image.sh` if artifacts missing; `sudo install` jailer-launch + sudoers (`deploy/INSTALL.md`); `visudo -cf`; first `isolation-manager prove`; enable systemd once the unit exists.

**Agent:** tests, chain module, manager append, unit file **content**, PLAN/receipts. Never sudo. Never retune Job_Search 16/16.

---

# Test matrix

| Layer | How | Pass |
|---|---|---|
| Rust unit | `cargo test -p aegis-common -p jailer-launch -p vestibule` | no root |
| Chain | append two rows; tamper fails | |
| Fail closed | prove without helper/kvm logs fail row; process does not hang | |
| Live | `cargo run -p isolation-manager -- prove` on aegisbox | dest-read json |
| Listener | off-schema grows reject log; `--disabled` is the negative control | |
| Service | unit starts; `prove` via socket; guest gone after; chain grew | |

Live prove is on aegisbox. Tests without kvm skip or fail closed, never skip-and-claim-green.

---

# Workstreams (do in this order)

1. **Substrate dest-read** — aegisbox: kvm, vhost-vsock, `firecracker --version`, artifacts under `artifacts/x86_64`. Write `docs/RECEIPT-SUBSTRATE-<date>.md`. If aegisbox is down, stop; do not install on WSL as the vsock path.

2. **Operator install** — INSTALL.md + install-firecracker.sh. Agent waits.

3. **TDD decision chain** — new small module (Rust in aegis-common or Python next to scripts). Tests first.

4. **Manager writes the chain** — `prove` / inspect / teardown / fail_closed.

5. **systemd unit** — manager long-lived; guests ephemeral; journald + jsonl paths.

6. **Live prove** — dest-read result. Residual: nested TCB, ~1s cold boot, always_invoked false.

7. **Career SPEAK** — only after dest-read: one line paired with the real prove command. `test_dispatch` still asserts Python did not start Firecracker.

8. **Receipt + CC verify** — `docs/RECEIPT-LIVE-BOX-<date>.md`. No commit unless named.

---

# Out of scope until named

Spec B4 staged Q0–Q3 flow. B5 egress proxy + nftables + canary. Snapshot warm start. `run_all.py` invoking Firecracker. WSL as primary Firecracker host.

---

# Residual (always say)

Nested Hyper-V TCB is trusted-but-unproven vs bare metal. Cold boot is the measured ~1s class, not Firecracker's 125 ms brochure. Floor still runs allowed tools without the box until the manager is actually on the path (`always_invoked` false).
