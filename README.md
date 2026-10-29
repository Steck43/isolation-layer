# isolation-layer

[![floor](https://github.com/Steck43/isolation-layer/actions/workflows/floor.yml/badge.svg)](https://github.com/Steck43/isolation-layer/actions/workflows/floor.yml)

A host-side isolation layer for agent tool calls: one Firecracker microVM per
task, launched under the jailer and torn down when the task ends, with a
schema-checked listener for what comes back from the guest, an inert
content-addressed shelf for the bytes it hands back, and a hash-chained host
log of every launch, verdict and teardown. It is designed as the step after
[capability-gate](https://github.com/Steck43/capability-gate), for a call the
gate cannot settle. The gate's decide path does not call this layer. The
gate's isolate route hands an `isolate` call to a door command, and today that
door is the stub `sandbox-demo route` in this repo, so no microVM boots on that
path.

## What it is

A Rust workspace under `crates/`:

| Crate | What the code does |
|---|---|
| `isolation-manager` | CLI. `prove` launches and tears down one jailed box and checks boot, vsock and that the host is untouched; `handoff`, `inspect-stage` and `inspect-vm` move a result through the shelf into a disposable inspector; `read` serves an allowlisted host-path read with a sha256; `serve` is a long-lived unix socket listener. |
| `jailer-launch` | Validates a launch request and runs the Firecracker jailer with dropped privileges. |
| `vestibule` | Host listener for guest results over vsock or a unix socket. Frames are size-bounded and schema-checked, rejects are logged, and the listener hardens itself after bind: no-new-privs, not dumpable, no core files, a seccomp allowlist that kills by default, a filter that denies `PROT_EXEC` mappings, its own cgroup memory and pid limits, and a Landlock path allowlist. |
| `dropbox` | Inert shelf: bytes go in and come out by sha256. The shelf has no verbs, and the guest never sees its path. |
| `inspector` | Stages a shelf object into a throwaway folder, checks the claim against the bytes, gives a verdict (advance, hold or drop) and disposes of the stage. |
| `aegis-common` | Shared paths, launch validation, the Firecracker API client, host snapshots, and `DecisionChain`: JSONL rows appended with `prev` and `sha256`, written by the host and locked against concurrent writers. |

`scripts/box_entry.py` is the host entry for one tool call into the box. It
spends each receipt id and each box ticket once, in a locked
`box-entry-spent.jsonl` beside the decision chain, so a receipt or ticket sent
again within 24 hours, by two calls at once, from another process or after a
restart is refused. A call is refused when that store cannot be read or
written. A prune writes the kept rows to a synced temp file and renames it over
the store, and the next prune removes a temp file that a killed prune left.
`tests/test_box_entry_replay.py` covers these cases.

`demos/sandbox-demo` also builds `sandbox-demo route --state DIR`, the stub
isolate route door capability-gate calls. Every receipt it prints carries
`real: false` and `mode: STUBBED`.

Scripts for live runs on a KVM host are in `scripts/` and `deploy/`; the
operator install is in [deploy/INSTALL.md](deploy/INSTALL.md).

## Why a microVM and not a sandbox

The design is chosen against one threat: **an agent that disables its own fence.**

Leonardo Di Donato documented this class for Ona on March 3, 2026: a coding agent escaped a bubblewrap sandbox by using `/proc/self/root` as a denylist synonym for a blocked path, then tried to disable bubblewrap once caught ([How Claude Code Escapes its Own Denylist and Sandbox](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox)). The failure was structural, not a missing rule. The fence and the fenced shared a trust domain, and a denylist that enumerates badness loses to an opponent that routes around it.

A Firecracker microVM removes the shared domain rather than hardening it. The boundary is enforced by KVM in the host kernel and by a separate guest kernel. It is not an object inside the guest: no namespace to unshare, no LSM policy to disable, no fence process in the guest's PID table to kill. Firecracker exposes five emulated devices: virtio-net, virtio-block, virtio-vsock, serial console, and a minimal keyboard controller. Everything not implemented is attack surface that does not exist.

The jailer sits underneath as a backstop, wrapping the Firecracker process itself in cgroups, namespaces, seccomp, and a chroot and dropping privileges before the guest runs. Two boundaries: the VM is primary, the jailer catches a hypothetical VMM-barrier compromise in a jailed host process rather than as root on the host.

![Isolation path from the jailer to the dropbox](docs/diagrams/isolation-layer-path.svg)

The alternatives were considered and rejected on the record, not overlooked. Plain containers share the host kernel, which is the same weakness the escape class exploits. Docker is runtime, packaging and test infrastructure, never the isolation boundary. This repo has no Dockerfile. bubblewrap with Landlock and seccomp is the exact configuration that was escaped. gVisor is strong and needs no hardware virtualization, but its boundary is a user-space kernel processing guest syscalls, a wider surface than KVM plus five devices; it is the named fallback, not a shipped runtime (`git grep` finds it in docs, not in `crates/`). WebAssembly is the wrong shape for code that needs a real filesystem and subprocesses.

ASI05 Unexpected Code Execution is the class this contains: one microVM per task under the jailer, seccomp default KILL, Landlock on the host listener. That control is built and tested, and untested live on the full path, because the box is not invoked on every permitted call. ASI07 is not mapped.

## Claim tense

Every claim in this repository carries its evidence rung. The distinction is load-bearing and is enforced in the docs.

| Tag | Meaning |
|---|---|
| `RECORD` | Off-the-shelf and proven today. Shipped code, a real primitive, or a verified source is named. |
| `VISION` | A target or design intent. Not yet standing. |
| `SOURCE:` | The primary source named *before* the claim that rests on it. |
| `ASSUMPTION (verify):` | An input taken on faith, with the exact check to run. |

Building a thing and watching it work does not promote a claim by itself. A boundary probe with a named negative control does.

## How to run it

From a fresh clone, with a Rust toolchain:

    make demo-all

That builds `demos/sandbox-demo`, runs every scenario in `demos/scenarios/`
through the real `vestibule`, `dropbox`, `inspector` and `aegis-common`
crates, prints a summary table and writes `out/summary.json` plus one record
per scenario in `out/runs/`. It exits non-zero if any row is FAIL. All traffic
is synthetic and generated from the seed in each scenario file. The
scenarios touch no network (the initial build fetches crates from crates.io),
nothing needs sudo, and no VM boots.

    make demo-test

runs the same scenarios as cargo tests, at a changed seed, twice for
determinism, and once per control with the control removed so the row goes
red. See [demos/README.md](demos/README.md).

The full test suites:

    cargo test --workspace
    PYTHONPATH=. python3 -m pytest -q

CI runs `make demo-all` on every push and pull request, then
`scripts/readme_proof.py check`, which fails if any number in the Proof section
below differs from the `out/summary.json` that run just wrote.

## Proof

Generated by `python3 scripts/readme_proof.py write` from `out/summary.json`
after `make demo-all`. Each row and each count line names its scenario and
seed; rerun `make demo-all` to get the same numbers. REAL means the row uses
the real crates end to end. STUBBED means a stub VM host stands in for the
Firecracker guest: S07 has a host thread play the guest over a real unix
socket, and SB1 runs the lifecycle against a stub VM.

<!-- proof:start -->
| scenario | seed | result | REAL/STUBBED |
|---|---|---|---|
| S07-vestibule-schema-violation | 1307 | PASS | STUBBED |
| S08-iso-decision-chain-tamper | 1408 | PASS | REAL |
| SB1-sandbox-lifecycle | 1401 | PASS | STUBBED |

Counts from the same run (`actual` in out/summary.json):

- S07-vestibule-schema-violation, seed 1307: events=56, accepted=43, acks=43, frames=56, injection_text_on_shelf=3, planted_on_shelf=0, reject_log_lines=13, rejected=13, shelf_objects=43
- S08-iso-decision-chain-tamper, seed 1408: events=20, baseline_verified=4, delete_detected=1, delete_index_matches=1, edit_detected=1, edit_index_matches=1, rows_per_chain=20, torn_tail_append_refused=1, torn_tail_detected=1, torn_tail_log_unchanged=1
- SB1-sandbox-lifecycle, seed 1401: events=14, advance=7, chain_ok=1, chain_rows=42, claims_valid=13, drop=3, hash_lie_dropped=1, hold=3, hygiene_clean=13, launched=14, leak_detected=1, reject_log_lines=1, stages_disposed=13, tasks=14, torn_down=14, unique_jail_ids=14, vestibule_rejected=1
<!-- proof:end -->

## Not shown yet

These are listed in `not_supported` and `blockers` in `out/summary.json` and
are not claimed here:

- A real microVM boot. S07, SB1 and the route door run on a stub VM host. On
  the dev host, Firecracker hits a host kernel bug at vCPU creation under
  nested virtualization. A real boot needs a host where KVM vCPU creation works,
  `/dev/kvm` access set up by the operator, the golden kernel and rootfs, and
  `jailer-launch` installed.
- The handoff from capability-gate into a real box. The gate's decide path
  does not call this layer (capability-gate
  `tests/test_fig1_box_uncalled.py`), and its isolate route reaches the stub
  route door, not a microVM.
- The vestibule's post-bind hardening (seccomp, the `PROT_EXEC` filter,
  cgroup limits, Landlock): S07 runs the listener with hardening off,
  because seccomp would apply to the demo process itself.
- S05 secret in prompt and S06 PII in the audit log: there is no redaction
  layer in this repo.
- S10 phishing investigation, S11 alert triage and S13 token usage: those
  workflows and their usage records do not exist yet.
- S08-iso measures two gaps without asserting them: a chain cut cleanly after
  a full row still verifies, because `DecisionChain` keeps no witness of the
  expected head and row count, and `append` does not verify the chain before
  it writes, so it appends after a mid-chain edit or delete.
- The gate scenarios (S01, S02, S03, S04, S09, S12) run in the
  capability-gate demo.

## Related work

- Stecker, L. (2026). capability-gate. Zenodo. https://doi.org/10.5281/zenodo.22018052. Sibling layer. The prove receipt binds a gate digest and an atoms digest to one call id. Borrows the concept record. Differs: this tree is the box, and it is not invoked on every permitted call.
- Agache et al. (2020). Firecracker. NSDI. https://www.usenix.org/conference/nsdi20/presentation/agache. Borrows the KVM microVM and the small device set. Differs: nested L1 guest, and the measured cold start is 958.6 ms jailed.
- Firecracker jailer. https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md. Borrows the jailer as the second boundary. `jailer_argv` wraps it.
- Linux seccomp BPF. https://docs.kernel.org/userspace-api/seccomp_filter.html. Borrows a default-KILL allowlist and the PROT_EXEC filter on the host listener.
- Linux Landlock. https://docs.kernel.org/userspace-api/landlock.html. Borrows an ABI 1 path-beneath allowlist on the host listener, not in the guest.
- gVisor. https://gvisor.dev/docs/. Differs. Named fallback. The boundary here is KVM plus a guest kernel, not a user-space kernel.
- Kata Containers architecture. https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md. Differs. This repo drives Firecracker directly and does not inherit cloud orchestration.

## License

`LICENSE` is MIT. The Cargo workspace (`Cargo.toml`) declares `MIT`. Citation metadata is in
[CITATION.cff](CITATION.cff).
