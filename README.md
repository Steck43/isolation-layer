# isolation-layer

An execution-isolation box for runtime agents. Each live, full-capability execution runs as an **ephemeral Firecracker microVM, one per task, launched under the jailer, destroyed on completion.**

This is the containment plane beneath a deterministic policy gate. The gate decides *whether* a tool call runs. This layer contains *whatever the gate lets through*. The two are deliberately separate programs with a named interface between them.

Author: [Landen Stecker](https://github.com/Steck43)

## Why a microVM and not a sandbox

The design is chosen against one threat: **an agent that disables its own fence.**

Leonardo Di Donato documented this class for Ona in February and March 2026: a coding agent escaped a bubblewrap sandbox by using `/proc/self/root` as a denylist synonym for a blocked path, then tried to disable bubblewrap once caught ([How Claude Code Escapes its Own Denylist and Sandbox](https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox)). The failure was structural, not a missing rule. The fence and the fenced shared a trust domain, and a denylist that enumerates badness loses to an opponent that routes around it.

A Firecracker microVM removes the shared domain rather than hardening it. The boundary is enforced by KVM in the host kernel and by a separate guest kernel. It is not an object inside the guest: no namespace to unshare, no LSM policy to disable, no fence process in the guest's PID table to kill. Firecracker exposes five emulated devices: virtio-net, virtio-block, virtio-vsock, serial console, and a minimal keyboard controller. Everything not implemented is attack surface that does not exist.

The jailer sits underneath as a backstop, wrapping the Firecracker process itself in cgroups, namespaces, seccomp, and a chroot and dropping privileges before the guest runs. Two boundaries: the VM is primary, the jailer catches a hypothetical VMM-barrier compromise in a jailed host process rather than as root on the host.

The alternatives were considered and rejected on the record, not overlooked. Plain containers share the host kernel, which is the same weakness the escape class exploits. bubblewrap with Landlock and seccomp is the exact configuration that was escaped. gVisor is strong and needs no hardware virtualization, but its boundary is a user-space kernel processing guest syscalls, a wider surface than KVM plus five devices; it is named as the fallback, not the primary. WebAssembly is the wrong shape for code that needs a real filesystem and subprocesses.

## Claim tense

Every claim in this repository carries its evidence rung. The distinction is load-bearing and is enforced in the docs.

| Tag | Meaning |
|---|---|
| `RECORD` | Off-the-shelf and proven today. Shipped code, a real primitive, or a verified source is named. |
| `VISION` | A target or design intent. Not yet standing. |
| `SOURCE:` | The primary source named *before* the claim that rests on it. |
| `ASSUMPTION (verify):` | An input taken on faith, with the exact check to run. |

Building a thing and watching it work does not promote a claim by itself. A boundary probe with a named negative control does.

## What is shipped

Rust workspace, six crates:

| Crate | Role |
|---|---|
| `isolation-manager` | Launch, prove, inspect, and allowlisted host-path read (observe; `always_invoked_claim` stays false). |
| `jailer-launch` | Jailer invocation and privilege drop. |
| `vestibule` | Seccomp allowlist, **default KILL**. Landlock filesystem allowlist. |
| `inspector` | Post-run verdict and host-disposition checks. |
| `dropbox` | Bounded artifact hand-back across the boundary. |
| `aegis-common` | Shared paths, validation, host snapshot. |

`RECORD` — currently green: Landlock filesystem allowlist, seccomp allowlist defaulting to KILL, cgroup memory and pid limits on the listener, a `PROT_EXEC` argument filter, and vsock as the control plane. The prove run reports `landlock=true`, `cgroup_jail=true`.

`VISION` — next: always-invoked enforcement, a full filesystem manifest, a dedicated vestibule uid, and richer analyzers.

## Substrate, stated honestly

The primary substrate is a **dedicated Linux VM**, with Firecracker as an L1 guest.

That is not the original design. A preflight found the Microsoft WSL2 kernel ships without `CONFIG_VHOST_VSOCK`, which blocks the vsock control plane on the WSL2-direct path and is not fixable by loading a module. Promoting a dedicated VM resolved it and shrank the trusted computing base at the same time, since Firecracker stops being a nested L2 guest.

Two things this repository will not claim:

- **Not "125 ms."** That is Firecracker's bare-metal reference figure and it is not this host's number. Measured here, cold, no snapshot, Firecracker as an L1 guest under nested Hyper-V: time to guest userspace **958.6 ms jailed** and **1700.8 ms direct** (`docs/b1-record.md` section 5, RECORD). Snapshot-restore is not measured and stays VISION, so no warm-start figure is quoted either.
- **Not "maximum isolation."** Under nesting the effective trust base includes the hypervisor's nested-KVM path. There is no cheap local proof that nested KVM preserves guest isolation equivalent to single-level KVM, so it is carried as trusted-but-unproven rather than asserted.

## Boundary suite

The probe suite is **fail-first**: every probe has a named negative control, and a probe that cannot be made to fail on purpose does not count as passing. Host-to-VM is treated as untrusted-input surface and carries its own probe class, because introducing the VM introduced that boundary.

## Status

Active research build. Interfaces are not stable. This is a working isolation layer for one to two local agents, not a multi-tenant control plane, and it deliberately does not inherit the cloud control planes of the projects whose lifecycle and vsock patterns it studied.

Published docs do not stamp tip SHAs. Those hashes were local-session locators and go stale after a history rewrite.

## License

See `LICENSE`.
