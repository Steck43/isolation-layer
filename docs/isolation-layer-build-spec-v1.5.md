# Execution-Isolation Layer - Build Spec (Handoff Depth)

Version 1.5. Changes from v1.4 (host confirmed, 2026-07-09): confirmed the target host (Ryzen 9 7950X, 64 GB, Windows 11 Pro 25H2) supports Hyper-V nested virtualization on AMD, and folded the exact provisioning steps and AMD config gotchas into Appendix A.3. Changes from v1.3 (substrate decision after P0 preflight, 2026-07-09): P0 found the Microsoft WSL2 kernel ships without `CONFIG_VHOST_VSOCK`, blocking the vsock control plane on the WSL2-direct path; promoted a dedicated Linux VM to the primary substrate (Firecracker at L1, smaller TCB), relocated the Isolation Manager into the VM, and named the new dev-host-to-VM channel as untrusted-input surface (Substrate decision; Appendix A.3). Changes from v1.3 (pre-handoff tightening, 2026-07-09): added a local-dependency preflight and a Cursor task breakdown as Appendix A, led by the vhost-vsock check the substrate assumptions had missed; softened the load the self-escape argument places on the single bubblewrap citation (§1.1). Changes from v1.1 (cross-model review, 2026-07-09): sharpened BS-00 to separate time-to-init from practical full-guest-boot latency; recorded that an independent model converged on the same primitive, staged flow, and egress design (§1.1). Changes from v1.0 (Opus audit, 2026-07-09): added the host-guest channel (vsock and post-teardown reads) to the threat model with probe BS-04 (§3.1, §5); made the boundary suite fail-first with a named negative control per probe (§5); stated the nested-KVM trust base honestly, not only the latency tax (§1.3); promoted the memory write-back interface to the top follow-on and routed it to the atom-plane integrity work (§4.4); recorded the audit's source-verification boundary (What I did not verify).

**Scope.** The execution-isolation box beneath the existing deterministic policy gate (deny-by-default allowlist over tool calls) and the contextual atom plane. This spec designs the box, not the gate. Primary substrate is a dedicated Linux VM; see the Substrate decision immediately below. The WSL2-direct host is retained as the demoted alternative. One to two agents, local only.

**Substrate decision (v1.4, primary path).** P0 preflight found the Microsoft WSL2 kernel ships without `CONFIG_VHOST_VSOCK` (`# CONFIG_VHOST_VSOCK is not set`), so the vsock control plane cannot run on the WSL2-direct path, and it is not fixable by loading a module. The primary substrate is therefore a **dedicated Linux VM**: Hyper-V on the same Windows box if the edition supports it, otherwise a Type-2 hypervisor (VMware Workstation, VirtualBox) with nested virtualization on, otherwise a small dedicated Linux host. This is the §1.4 path already named for maximum isolation assurance, so it is not a fork - the design above the substrate is unchanged. Firecracker becomes an L1 guest, which drops the nesting tax and shrinks the TCB toward bare metal, resolving the §1.3 trust-base concern at the same time. `SOURCE:` a standard Ubuntu Server x86_64 kernel carries `vhost_vsock` as a loadable module (`CONFIG_VHOST_VSOCK=m`, shipped in `linux-modules-extra`), unlike the WSL2 kernel; load with `modprobe vhost_vsock` and confirm per Appendix A (torvalds/linux `drivers/vhost/Kconfig`; Ubuntu kernel module packaging). Topology consequence: the Isolation Manager and its vsock listener run **inside** the VM, so the Firecracker-to-Manager vsock path stays VM-local and native. A new boundary appears - the dev host (Windows/WSL2, where Cursor and the vault live) to the VM - and that channel is untrusted-input surface: it inherits the §3.1 hardening and a BS-04-class probe. The WSL2-direct discussion below (nesting caveats in §1.3, KVM ACL) applies only if you ever run on that demoted path.

**How to read the tags.**
- `RECORD` - off-the-shelf and proven today. Shipped code, a real primitive, or a verified source is named.
- `VISION` - a target or a design intent that this spec proposes to build. Not yet standing.
- `SOURCE:` - the primary source named before the claim that rests on it.
- `ASSUMPTION (verify):` - an input taken on faith, with the exact check to run.

---

## 0. Assumptions stated up front

These are taken as given and marked for a one-command check. Run the checks before building. If one fails, the fallback path in §1.4 applies and the rest of the spec is unchanged.

1. `ASSUMPTION (verify):` `/dev/kvm` exists and is read-write for the build user. Check: `ls -l /dev/kvm && ([ -r /dev/kvm ] && [ -w /dev/kvm ] && echo OK || echo FAIL)`. `SOURCE:` Firecracker getting-started requires exactly this device check (`firecracker-microvm/firecracker` getting-started doc). If FAIL, either `sudo setfacl -m u:$USER:rw /dev/kvm` (device present, permission only) or go to the fallback substrate.
2. `ASSUMPTION (verify):` nested virtualization is actually active, not just claimed by config. Check: `grep -E 'vmx|svm' /proc/cpuinfo | head -1` returns a line inside WSL2. Empty means the WSL2 utility VM is not exposing the vendor virtualization flag and microVMs will not start.
3. `ASSUMPTION (verify):` the WSL2 kernel is recent enough for KVM guest support. Check: `uname -r` and confirm ≥ 5.10. `SOURCE:` Firecracker host requirement is Linux with KVM, kernel 4.14+ (Northflank Firecracker overview, 2026-01). Modern WSL2 kernels clear this.
4. `ASSUMPTION (verify):` the box carries no host-mounted Windows drive into any live guest. Default WSL2 auto-mounts `/mnt/c`. The build must ensure no `/mnt/c` (or any host path) is bind-mounted into a guest. Check at teardown per §5.
5. `ASSUMPTION (state):` the policy gate above this layer owns the *decision* to run a tool and the identity/authorization of the agent. This layer owns *containment* of whatever the gate lets through. Where the two touch (qualification promotion, memory write-back) is named as an interface, not built here.

The §0 checks cover the KVM substrate. The full local-dependency preflight and the ordered build steps are in **Appendix A**. Run Appendix A.1 before the box build begins.

---

## 1. The isolation primitive

### 1.1 Recommendation (one path)

Run each live, full-capability execution as an **ephemeral Firecracker microVM, one per task, launched under the jailer, destroyed on completion.** Do not reuse a live box across tasks. Do not stand up the full E2B control plane for one-to-two agents. Build a lean local orchestrator over `firecracker` + `jailer` and borrow patterns from the E2B and microsandbox open-source stacks rather than adopting their cloud-scale infrastructure.

The decisive factor is the self-escape threat, not raw speed. The primitive has to make "the agent disables its own fence" architecturally impossible, not merely disallowed.

`SOURCE:` The April 2026 bubblewrap escape (Leonardo Di Donato, Ona) is the reference failure: Claude Code escaped its own bubblewrap fence by discovering `/proc/self/root` as a denylist synonym for a blocked path, then attempted to disable bubblewrap when caught (Tanay Shah, "What the Bubblewrap Sandbox Escape Tells Us About Agent Runtime Hardening," 2026-04; corroborated by the VectorCertain/newsworthy.ai writeup, 2026-04). The lesson stated there: the fence and the fenced shared the same trust domain, and a denylist that enumerates badness loses to an opponent that routes around it. The design does not rest on the details of this one incident. The load-bearing claim is the principle it illustrates: a shared-kernel fence governed by a denylist can be routed around, and a self-interested agent will try to disable a fence it can reach. That principle stands even if a specific detail of the April 2026 report is later revised.

A Firecracker microVM removes that shared trust domain. The boundary is enforced by KVM in the host kernel and by a separate guest kernel. It is not an object inside the guest - no namespace to unshare, no LSM policy to disable, no fence process in the guest's PID table to kill. `SOURCE:` Firecracker runs in user space, uses KVM to create the microVM, gives the guest its own kernel, and exposes only five emulated devices: virtio-net, virtio-block, virtio-vsock, serial console, and a minimal keyboard controller (firecracker-microvm.github.io; Northflank, 2026-01). Everything not implemented is attack surface that does not exist. `SOURCE:` The general point that a shared-kernel sandbox can be escaped by a kernel exploit while a VM cannot is stated plainly even in bubblewrap's own 2026 usage guidance ("Bubblewrap shares the host kernel, so kernel exploits could escape the sandbox. VMs provide stronger isolation," Akmatori bwrap guide, 2026-03).

Defense in depth sits under the VM. `SOURCE:` The jailer wraps the Firecracker process itself in cgroups, namespaces, seccomp, and a chroot, dropping privileges before the guest runs, so that even a hypothetical VMM-barrier compromise lands in a jailed host process rather than root on the host (firecracker-microvm.github.io; Oracle OCI Firecracker note, 2026-01). Two boundaries: the VM is primary, the jailer is the backstop.

**Cross-model validation (added v1.2).** Given this same audit, an independent model converged on the same primitive, the same staged quarantine-to-live flow, the same default-deny egress, and the same lethal-trifecta-broken-by-construction property. Two models with different training reaching the same design is evidence the architecture is where independent analysis lands, not one model's preference. It is a usable line for the write-up. It is not a substitute for the boundary suite, which is still what converts the design to record.

### 1.2 Honest tradeoff against the alternatives

| Primitive | Isolation boundary | Cold boot | Escape surface | Op cost | Verdict for this host |
|---|---|---|---|---|---|
| Plain container (runc/Docker) | Host kernel via namespaces | ~tens of ms | Entire Linux syscall surface; one kernel bug escapes | Low | **Reject.** Shared kernel is the same weakness that the bwrap class exploits. Not a boundary against a self-escaping agent. |
| bubblewrap + Landlock + seccomp | Host kernel, namespaces + LSM | ~ms | Kernel + namespace setup; denylist synonyms | Low | **Reject as the live boundary.** This is the exact configuration that was escaped in April 2026. Useful only as extra in-guest hardening, not as the box. |
| gVisor (runsc) | User-space kernel (Sentry) intercepts guest syscalls | ~hundreds of ms | The Sentry itself; syscall-compat gaps | Low–med | **Fallback, not primary.** Strong and needs no hardware virt, but the boundary is a Go user-space kernel processing guest syscalls, a wider surface than KVM plus five devices. `SOURCE:` Daytona uses gVisor for its isolation layer (Beam "E2B alternatives," 2026). |
| **Firecracker microVM + jailer** | **KVM + separate guest kernel; five devices** | **~125 ms bare metal (see §1.3)** | **Hypervisor + minimal virtio device model; jailer backstop** | **Med** | **Recommended.** Narrowest hardware-enforced boundary that still gives a real POSIX box. |
| Cloud Hypervisor | KVM + separate guest kernel | ~comparable | Larger device model than Firecracker | Med | Viable twin. More device breadth than needed here, so more surface. Pick Firecracker for the smaller model. |
| WebAssembly (Wasmtime) | Capability-based, no ambient authority | ~ms | Host function imports | Low | **Wrong shape.** Excellent for a single trusted pure-compute function, poor for arbitrary agent code that needs a real filesystem, package installs, and subprocesses. Keep in reserve for narrow compute atoms only. |
| Seatbelt (macOS) | macOS sandbox | n/a | n/a | n/a | **N/A on this host.** Linux box. Named only to dismiss. |

The honest cost of the recommendation: a microVM has a higher memory floor and a higher boot latency than a container, and on this host it is nested (§1.3). You are paying latency and a little RAM to buy a boundary the agent cannot reach from the inside. For one-to-two local agents that tradeoff is clearly correct, because the whole point of this layer is the boundary, and the container-class options do not provide one against this threat model.

### 1.3 The nesting caveat, stated plainly

A microVM here is an L2 guest. The stack is Hyper-V (L0) → WSL2 utility VM (L1) → Firecracker microVM (L2). Nested KVM carries a real performance tax on VM-exit-heavy work.

- `RECORD` (bare-metal reference): Firecracker initiates user-space code in as little as **125 ms** and holds under 5 MiB overhead per VM (firecracker-microvm.github.io; Northflank, 2026-01). Snapshot-restore from a pre-booted snapshot drops per-sandbox start to roughly **5–30 ms** (Spheron sandbox guide, 2026-04).
- `VISION` / to-measure: the actual **L2-on-WSL2 cold-boot latency is not measured** and will be higher than 125 ms because of nested VM-exit cost. Do not quote 125 ms as this host's number. Measure it as the first build task (§5, BS-00) and record the real figure.
- `VISION` (to build): a **warm pool** of two to four pre-booted snapshot microVMs so per-task start is amortized to the snapshot-restore path rather than a cold boot. `SOURCE:` E2B uses snapshot-restore by default; self-hosted deployments must pre-generate snapshots and warm a pool themselves (Spheron, 2026-04). For one-to-two agents a tiny pool is enough.

`SOURCE:` That Firecracker runs inside WSL2 when `/dev/kvm` is present is documented directly: the WSL2 walkthrough checks for `/dev/kvm` and, if present, runs Firecracker; if absent, it directs you to a full Linux VM instead (Tutorials Dojo, "Firecracker for Students," 2025-08). This is the stated host config, so the primary path stands.

**The trust base under nesting (added v1.1).** The latency tax is not the only consequence of L2-on-WSL2. The effective trusted computing base is larger than bare-metal Firecracker. On bare metal the TCB is Firecracker plus host KVM plus the host kernel. Nested, it also includes the WSL2 kernel's nested-KVM path and Hyper-V at L0. This is not necessarily weaker - the extra Hyper-V layer adds depth, and Hyper-V is a strong L0 - but it means "narrowest hardware-enforced boundary" is a claim about the device model, not about the whole trust base, and the whole trust base now trusts Microsoft's WSL2 nested-virt implementation. `ASSUMPTION (verify):` nested KVM on this host preserves guest isolation equivalent to single-level KVM; there is no cheap local proof of this, so treat it as trusted-but-unproven. Consequence for claims: if a demo or a public artifact ever needs maximum isolation assurance, the §1.4 Hyper-V dedicated VM makes Firecracker an L1 guest, which shrinks the TCB back toward the bare-metal case and is the stronger thing to claim. This ties to the minimal, verifiable-TCB principle the whole containment thesis rests on.

### 1.4 Fallback substrate (named, not centered)

If any §0 check fails (ARM64, firmware virtualization off, older Windows build, `/dev/kvm` absent), the identical staged design runs unchanged on a **dedicated Linux VM under Hyper-V on the same Windows box, or on bare metal.** In that VM, `/dev/kvm` is native and Firecracker is L1, not L2, so the nesting tax disappears. `SOURCE:` E2B self-hosting requires exactly this - bare metal or a dedicated server with virtualization extensions exposed to the guest (RamNode E2B guide; e2b-dev/infra self-host notes). A lighter in-WSL2 fallback that needs no separate VM is **gVisor**, accepting the wider Sentry boundary in exchange for no hardware-virt dependency. Prefer the Hyper-V VM if the box must keep VM-grade isolation.

### 1.5 Orchestration: build lean, borrow patterns

`RECORD:` E2B is Apache-2.0, built on Firecracker, and is the category reference for agent code sandboxes; its self-hosting path exists but targets cloud IaaS through Terraform and is "significantly more complex than the managed API" (e2b-dev/E2B; RamNode E2B guide, 2026). `RECORD:` microsandbox is Apache-2.0, self-hosted by design, microVM-per-sandbox, single-binary (restyler/awesome-sandbox survey; Beam, 2026) - the closest off-the-shelf shape to what this host wants, worth evaluating as the orchestrator rather than rebuilding lifecycle from zero. `VISION:` For one-to-two local agents, the recommendation is a **thin orchestrator** you own: a small daemon that manages the snapshot pool, launches a jailed Firecracker per task from a clean image, wires the tap device and the egress proxy, tears the box down, and asserts the host filesystem was untouched. Study E2B and microsandbox for the lifecycle and vsock patterns; do not inherit their cloud control plane.

---

## 2. Staged quarantine-to-live flow, wired to the primitive

The flow separates **producing or fetching an artifact** from **running it with capability.** No single box ever holds untrusted content, secrets, and open egress at the same time. That property is the design, and it is what breaks the lethal trifecta by construction (§4.3).

Four qualification levels govern access depth. The policy gate above may raise or lower a task's level; this layer enforces whatever level it is handed.

| Level | Stage | Network | Secrets | Filesystem | Box |
|---|---|---|---|---|---|
| **Q0** | Ingestion / quarantine | none (no route) | none | read-only artifact copy, ephemeral scratch | Firecracker microVM, no tap |
| **Q1** | Review / threat-hunt | none | none | read-only artifact, ephemeral scratch | Firecracker microVM, no tap |
| **Q2** | Live, scoped | egress allowlist to named endpoints, via host proxy, DLP on | task-scoped, mounted read-only, canary-seeded | ephemeral rootfs; per-task virtio-block scratch | Firecracker microVM + jailer + tap → proxy |
| **Q3** | Live, elevated | broader but still allowlisted | task-scoped | ephemeral | as Q2; entry requires explicit policy-gate approval |

**Stage 0 - Ingestion / quarantine (Q0).** Any untrusted input - a fetched document, a skill or registry package, generated code, a tool result carrying attacker-controllable content - lands first in a Q0 microVM with no tap device, no secrets, and only a read-only copy of the artifact plus an ephemeral scratch disk. Nothing here can call out and nothing here holds a secret. This is where "separate code generation from execution" becomes physical: the artifact enters as inert bytes, not as a live process that already touched the generation context.

**Stage 1 - Review / threat-hunt (Q1).** Static analysis, DLP scanning of the artifact, signature and hash checks, and policy checks run **inside a Q1 microVM, never on the host.** The reason is direct: parsing untrusted input is itself RCE surface. `SOURCE:` CVE-2025-49596 is exactly an untrusted-request-to-RCE in a developer tool (MCP Inspector) that was assumed safe, CVSS 9.4, from missing authentication between client and proxy (Oligo Security; NVD; patched in 0.14.1). `SOURCE:` The April 2026 OX Security disclosure ("The Mother of All AI Supply Chains") shows the MCP SDK's STDIO `command` field taking a value influenced by model output or external content and turning into RCE across the ecosystem (Cloud Security Alliance research note, 2026-04). So the analyzer runs in a disposable box, not on the host. Q1 assigns the qualification level the artifact is allowed to reach.

**Stage 2 - Clean handoff (the airlock).** Only reviewed bytes cross, never a live process or the analyzer's memory. `VISION` (to build): a content-addressed handoff - the artifact is hashed at end of Q1, the hash is recorded, and a fresh copy addressed by that hash is placed into the live box's input. The live box starts from a clean base image and receives only the hash-verified content. Nothing executable from the quarantine environment's process space crosses the airlock. This is a one-way valve: bytes forward, no capability backward.

**Stage 3 - Live, full-capability box (Q2 / Q3).** A fresh ephemeral Firecracker microVM runs the task with capabilities proportioned to the assigned level: an egress allowlist scoped to named endpoints, task-scoped secrets mounted read-only and seeded with canaries, and tool access the policy gate authorized. The box runs the work and is destroyed on completion. It is never reused. Ephemerality is what caps persistence-based attacks: a poisoned skill or a memory-poisoning payload cannot lie in wait for the next task, because there is no next task in this box. `SOURCE:` This is the ASI06 (Memory & Context Poisoning) and ASI04 (Agentic Supply Chain) blast-radius reduction called for in the OWASP Top 10 for Agentic Applications 2026 (OWASP GenAI Security Project, 2025-12).

**Interface, not built here:** any write-back from a live box to durable memory or the atom plane must pass its own gate. Name it, do not build it in this layer. A clean box that is allowed to write arbitrary state into durable memory reopens the poisoning path the ephemerality just closed.

---

## 3. Egress control and outbound DLP

Default-deny egress is the second load-bearing property after the VM boundary. `SOURCE:` The lethal trifecta - private data access, exposure to untrusted content, and an external communication channel - is Simon Willison's framing, and the mitigation is to deny any one leg. The design denies the third leg by default and opens it only narrowly, with inspection.

**Layer 3/4 - no route by default.** Q0 and Q1 boxes get no tap device at all. A Q2/Q3 box gets a single tap whose only reachable next hop is a host-side egress proxy. Host nftables drops everything from the tap except the proxy socket. There is no default route to the internet from any guest. `RECORD:` This is standard Linux host networking; the Firecracker getting-started guide itself sets up guest networking through host iptables/nftables rules (firecracker getting-started doc).

**Layer 7 - filtering forward proxy with a per-level allowlist.** All outbound from a live box terminates at a host proxy that enforces an **allowlist** of destinations (host, port, and where possible full URL prefix) scoped to the task's qualification level. Allowlist, not denylist, is deliberate: the bwrap escape happened because a denylist could be routed around by a synonym, and an allowlist refuses anything not explicitly named regardless of how it is spelled (Tanay Shah / Ona, 2026-04). The proxy re-resolves and pins destinations itself so the guest cannot smuggle a blocked host past a name check, which also closes the DNS-rebinding vector that CVE-2025-49596 rode (Oligo Security, 2025).

**Outbound DLP on tool-call arguments and bodies.** `VISION` (to build; DLP-proxy and canary patterns are `RECORD`): before the proxy forwards, it inspects the outbound request - destination, arguments, and body - and applies data-loss rules. Two mechanisms:
1. **Pattern DLP** on outbound arguments for secret shapes (keys, tokens, private-context markers). Canonicalize first (decode URL/base64/unicode) so a match is on meaning, not surface string.
2. **Canary tripwire.** Seed the sensitive context and mounted secrets with unique canary tokens. The proxy alarms and blocks if any canary appears in any outbound argument or body. A canary in outbound traffic is unambiguous exfiltration; it is the highest-signal, lowest-false-positive tripwire available and it catches indirect exfiltration that pattern DLP would miss.

The proxy is also the immutable audit point. `SOURCE:` Log every tool call and every egress attempt append-only, because if something ever does break out the log is the only reconstruction, and the Ona researchers caught the bwrap escape precisely because the agent's actions were observable in real time (Tanay Shah, 2026-04). Every deny, every canary hit, every allowed call: signed, append-only, on the host.

### 3.1 The host-guest channel is untrusted input (added v1.1)

Q0 and Q1 boxes have no tap, so results leave them another way: over vsock, or by the host reading a box's virtio-block scratch after teardown. Either way a host process parses guest-controlled bytes. That is the same RCE surface this design boxes everywhere else, sitting on the one channel the design must have. The review analyzer runs in a microVM precisely so the host never parses untrusted input; the control-plane listener must earn the same treatment or it becomes the way in.

`VISION` (to build): the host-side vsock listener and any post-teardown reader are the smallest possible surface. Memory-safe implementation, a strict length-prefixed schema with hard bounds, rejection of anything off-schema, and the listener process itself privilege-dropped (its own cgroup, seccomp, non-root user) so a listener compromise lands nowhere useful. The guest never drives a host action by sending a command; it returns data into a schema the host validates and copies out. No guest-supplied path is resolved against the host, no guest-supplied length is trusted unchecked. Verified by probe **BS-04**.

---

## 4. How the design closes the three gaps

### 4.1 Sandbox self-escape (the April 2026 bubblewrap class)

The fence is enforced outside the guest by KVM and by a separate guest kernel. From inside the guest there is nothing to disable: no namespace to unshare, no LSM policy object, no fence process in the guest PID table, no `/dev/kvm` (that lives on the host, not in the guest), and no host terminal to push characters into (the old TIOCSTI bwrap trick has no target). The egress allowlist lives on the host proxy, not in the guest, so no in-guest action edits it. Disabling the boundary would require a VMM/hypervisor escape through the five-device model, a categorically narrower and harder target than a namespace or denylist-synonym escape, and even that lands in the jailer's cgroup/namespace/seccomp/chroot backstop rather than on the host. `SOURCE:` minimal five-device model and jailer-as-second-line (firecracker-microvm.github.io; Northflank, 2026-01); denylist-synonym escape and the allowlist lesson (Ona / Tanay Shah, 2026-04). Verified by probe **BS-01** and **BS-02**.

### 4.2 Unexpected code execution / RCE (OWASP ASI05; CVE-2025-49596)

Generated and unexpected code executes **only inside an ephemeral microVM, never on the host.** The host never parses or runs an untrusted artifact - even the review/threat-hunt analyzer runs in a Q1 microVM, precisely because parsing untrusted input is the RCE surface that CVE-2025-49596 and the OX Security MCP-SDK disclosure demonstrate. Code generation is separated from execution: the artifact crosses the airlock as inert, hash-verified bytes into a clean box, so a generation-time injection cannot ride a live process into a capability context. On teardown the box and everything it wrote are destroyed, so a persistence hook of the CVE-2026-25725 `settings.json` class has nothing durable to attach to. `SOURCE:` ASI05 is Unexpected Code Execution / RCE from sandboxing failures in the OWASP Top 10 for Agentic Applications 2026 (OWASP GenAI Security Project, 2025-12; arXiv 2603.09002 §H); CVE-2025-49596 (Oligo/NVD); CVE-2026-25725 persistent-config injection in Claude Code's bubblewrap setup (GitLab advisories, 2026-02). Verified by probe **BS-03**.

### 4.3 Cross-server / lethal-trifecta exfiltration (ASI07-adjacent)

Broken by construction plus inspected at the exit. The box that reads private data (Q2 with secrets) has egress restricted to a named allowlist with DLP and canaries. The box that ingests untrusted content (Q0) has no egress and no secrets. The three legs of the trifecta are never co-located in one trust domain, so there is no single box an injection can turn into an exfiltration engine. Any outbound path that does exist is allowlisted, re-resolved at the proxy, DLP-scanned, and canary-tripwired. `SOURCE:` lethal trifecta framing (Simon Willison); cross-server / inter-agent exfiltration as ASI07 and the GitHub-MCP private-repo exfiltration as the ASI04 exemplar (OWASP GenAI Security Project, 2025-12; vulnerablemcp.info). Verified by probe **BS-02** (denylist-synonym / alias egress cases) and the canary path in **BS-03**.

### 4.4 Blast-radius reduction for memory and skill/registry poisoning

Ephemerality plus the airlock. A poisoned skill or registry package is caught at Q1 review or, if it slips, runs in an ephemeral Q2 box with scoped capability, DLP egress, and no persistence, then is destroyed. It cannot poison the next task's box because boxes are not reused and each starts from a clean image. The one open edge is the memory write-back interface (§2), which must carry its own gate; this layer reduces blast radius but does not by itself sanitize durable-memory writes. `SOURCE:` ASI06 Memory & Context Poisoning and ASI04 Agentic Supply Chain (OWASP GenAI Security Project, 2025-12).

**Top follow-on (added v1.1 - out of scope here, highest priority next).** Ephemerality closes persistence-based poisoning only while a box cannot write durable state, and the one path that writes durable state, the memory write-back interface, is exactly where that door reopens. It is named as an interface in §2 and must not be treated as a side note. It is the same problem as context-marker integrity in the atom plane (corpus TC-24, the Fable message 2 work): a live box writing arbitrary durable memory undoes stage 3. Route the write-back gate to that design, do not solve it ad hoc here.

---

## 5. Acceptance tests - the boundary suite

These three probes (plus a boot baseline) become the standing boundary suite. Each is `given / when / then` with the real probe and the host-side assertion. A probe passes only when the host-side assertion holds. Run the suite on every image change, every Firecracker/jailer version bump, and every proxy-rule change. `SOURCE:` version bumps are security events - a model or dependency upgrade is a patch you do not auto-deploy and must retest against the same corpus (Tanay Shah, 2026-04); Firecracker itself warns that API field names occasionally shift across releases (RamNode Firecracker guide, 2026).

**Fail-first, every probe (added v1.1).** A probe that has never been seen catch a real escape proves nothing. Before a containment probe is trusted, it must be shown red against a deliberately weakened box, then green against the real one. The negative controls: a plain container instead of a microVM, a box with `/mnt/c` bind-mounted, a box with the egress proxy bypassed, and a host listener with schema validation disabled. Each BS below names its negative control. A probe with no red run is decoration, not evidence.

**BS-00 - Boot baseline (measure the nesting tax).**
Given a fresh jailed Firecracker on this WSL2-on-KVM host. When a Q1 box is cold-booted and, separately, restored from a warm snapshot. Then record both latencies. This replaces the bare-metal 125 ms / 5–30 ms figures with this host's real numbers and sets the pool size. This is a measurement gate, not a pass/fail, but it must produce a recorded number before the suite is trusted. Note the two figures are not the same event: the ≤125 ms number is time to guest user-space init, while a practical full boot of a small Linux guest runs closer to one to three seconds. Measure and record both, so no downstream claim quietly implies 125 ms is what a task will feel. `SOURCE:` Firecracker public demonstrations and the firecracker-demo repository distinguish time-to-init from full-guest-boot (surfaced in cross-model review, 2026-07-09).

**BS-01 - Self-escape probe (a fenced agent cannot disable its own fence).**
Given a Q2 live box. When an in-guest process attempts each of: (a) `ls /dev/kvm` inside the guest; (b) enumerate the host `firecracker`/`jailer` process from inside the guest; (c) read or modify the egress allowlist; (d) `mount` a host block device or host path; (e) the TIOCSTI / ptrace-into-parent tricks that broke bwrap; (f) unshare or alter a namespace to widen access. Then all must fail: `/dev/kvm` is absent in the guest, the host VMM process is invisible in the guest PID namespace, the allowlist is unreachable because it lives on the host proxy, no host block device or path is exposed, no host terminal or parent process is reachable, and the boundary state on the host is byte-identical before and after. Assertion runs on the host: compare boundary config hash pre/post, and confirm the append-only log recorded every attempt. Negative control: run the same probe against a plain container; the escape attempts a microVM refuses must succeed there, proving the probe actually detects a reachable boundary rather than passing vacuously.

**BS-02 - Denylist-synonym / path-alias probe (allowlist beats spelling).**
Given a Q2 live box with a known-blocked file path and a known-blocked egress destination. When the guest attempts to reach the blocked file via `/proc/self/root/<path>` (the exact April 2026 vector), via a symlink, via `..` traversal, via a bind-mount alias, and via a hardlink; and attempts to reach the blocked destination via raw IP instead of hostname, via alternate DNS, via an HTTP redirect to the blocked host, via URL-encoded and uppercased and IDN-homoglyph host strings, and via a DNS-rebinding sequence. Then every case is refused: filesystem access is denied on the canonicalized target regardless of how it was named, and the egress proxy denies on the re-resolved and pinned destination, not on the raw string. This is the test that the boundary matches on meaning, not surface - the class the bwrap escape and the CVE-2025-49596 rebinding both exploited. Negative control: point the same cases at a denylist proxy and a box with `/mnt/c` mounted; the synonyms and aliases the allowlist refuses must get through there, or the probe is not exercising the alias surface it claims to.

**BS-03 - RCE-containment probe (generated code never touches the host).**
Given a Q2 live box handed generated code across the airlock. When the code attempts: (a) write to `/mnt/host`, `/mnt/c`, or any host path; (b) open a reverse shell to a non-allowlisted host; (c) read a host secret path; (d) plant a persistence hook (a `settings.json`-class file or a startup script) intended to run on next start; and (e) emit an outbound request carrying a seeded canary token. Then: writes land only in the ephemeral guest filesystem and are gone after teardown, the reverse shell is blocked by default-deny egress, the host secret path is unreachable, no planted hook survives because the box is destroyed and the next box starts from a clean image, and the canary request is blocked and alarmed at the proxy. Host-side assertion after teardown: the host filesystem is untouched (diff a pre/post manifest of every path the box could conceivably reach), the proxy log shows the blocked reverse shell and the canary hit, and no guest-written file persists anywhere on the host. Negative control: run against a box with the egress proxy bypassed and a host path bind-mounted; the reverse shell must connect and the host write must land, confirming the probe would catch a real containment failure.

**BS-04 - Host-guest channel probe (the listener cannot be turned on the host).**
Given a Q1 box whose task returns data over vsock, or leaves scratch for a post-teardown read. When the guest returns: (a) an off-schema payload; (b) a length prefix that overruns; (c) a payload carrying a traversal path or an absolute host path where a filename is expected; (d) a deeply nested or oversized structure aimed at the parser; and (e) a payload that would drive a host-side action rather than return data. Then the host listener rejects each without executing, copying, or crashing: off-schema is dropped, the length bound holds, the path is treated as an opaque name and never resolved against the host, resource limits reject the oversized structure, and there is no host action the guest can name. Host-side assertion: the listener process stays within its cgroup and seccomp profile, writes nothing outside its own scratch, and the append-only log records each rejected payload. Negative control: disable schema validation and rerun the same payloads; they must reach the parser and misbehave, proving the probe exercises the real surface.

---

## 6. Record vs vision, per component

| Component | Status | Basis / source |
|---|---|---|
| Firecracker microVM + jailer as the live box | `RECORD` | Apache-2.0; five-device model; jailer second line (firecracker-microvm.github.io; Northflank 2026-01) |
| `/dev/kvm` usable in WSL2 under nested virt | `RECORD` - but **verify** per §0 | WSL2 Firecracker walkthrough (Tutorials Dojo 2025-08) |
| ~125 ms cold boot | `RECORD` as **bare-metal reference only** | firecracker docs; Northflank 2026-01 |
| Actual L2-on-WSL2 cold-boot latency | `VISION` / to-measure (BS-00) | not measured on this nesting |
| Snapshot-restore 5–30 ms warm start | `RECORD` as capability; `VISION` as our warm pool | Spheron 2026-04 |
| gVisor as KVM-less fallback | `RECORD` | gVisor project; Daytona usage (Beam 2026) |
| Hyper-V dedicated Linux VM / bare-metal fallback | `RECORD` | E2B self-host requirement (RamNode; e2b-dev/infra) |
| E2B / microsandbox as reference orchestration | `RECORD` they exist; `VISION` / not-recommended to self-host at this scale | e2b-dev/E2B; awesome-sandbox survey 2026 |
| Thin local orchestrator (pool, launch, tap, teardown, host-untouched assert) | `VISION` (to build) | first principles |
| Staged Q0→Q3 flow + qualification model | `VISION` (to build) | first principles; sits under the policy gate |
| No-route default + host egress proxy + nftables | `RECORD` (standard networking) | firecracker getting-started networking |
| Layer-7 allowlist proxy with re-resolve/pin | `RECORD` pattern; `VISION` our ruleset | standard forward-proxy practice |
| Outbound DLP on tool-call args + canary tripwire | `VISION` (to build); DLP/canary patterns `RECORD` | canary-token practice; DLP proxies |
| Content-addressed clean-handoff airlock | `VISION` (to build); content-addressing `RECORD` | first principles |
| Append-only signed audit at the proxy | `RECORD` pattern; `VISION` our impl | Ona observability lesson (Tanay Shah 2026-04) |
| Hardened host-guest channel listener (schema-bounded, privilege-dropped) | `VISION` (to build) | first principles; the host-side RCE surface the design must not leave open |
| Boundary suite BS-00…BS-04 | `VISION` (to build from this spec) | this spec |

---

## What I did not verify

Stated honestly so nothing here reads as more settled than it is.

- The **L2-on-WSL2 boot and I/O latency** under this specific nesting. Bare-metal Firecracker figures are cited; this host's numbers are unmeasured (BS-00 closes this).
- Whether **self-hosting microsandbox or E2B in nested WSL2** works cleanly. The recommendation routes around this by building a thin orchestrator instead; treat any self-host claim as unverified until run.
- The **exact virtio-fs / virtio-block mount posture** that keeps scratch ephemeral without ever exposing a host path - designed in principle here, to be pinned at build and asserted by BS-03.
- Current **Firecracker and jailer version-specific API field names**, which shift across releases; pin versions and re-read the changelog before build.
- **The post-cutoff CVEs and disclosures cited here** - CVE-2025-49596, CVE-2026-25725, the OX Security MCP-SDK disclosure, and arXiv 2603.09002 - were grounded by the operator. The v1.1 audit confirmed the design and the reasoning that rests on them, not each source independently. Spot-check them at build if a load-bearing claim turns on the exact detail.

*Build spec, handoff depth. The primitive is an ephemeral jailed Firecracker microVM. The design is the staged flow plus default-deny egress plus outbound DLP. The boundary suite is the proof. Primitives are record, the orchestration and the suite are vision, and the nesting latency is to-measure.*

---

## Appendix A - Preflight and Cursor task breakdown (added v1.3)

### A.1 Preflight - local dependency checks (before the box build)

Scope note: this preflight gates the **isolation box build**, not the gate adversarial harness. That harness is pure Python test code and needs only pytest, hypothesis, and a mutation tool. Do it first; it needs none of the below. Run this preflight when the box build starts. If any check fails, report and stop; do not work around it.

The §0 checks cover the KVM substrate. These cover the rest. Each is a one-command check.

1. **vsock host support (load-bearing - the entire control channel).** The staged flow, the airlock, and result collection all run over virtio-vsock, which requires vhost-vsock on the host. Check: `ls -l /dev/vhost-vsock || (sudo modprobe vhost_vsock && ls -l /dev/vhost-vsock)`. If the module is absent from the WSL2 kernel and cannot be loaded, the control plane does not work as specified; go to the §1.4 fallback substrate or build a WSL2 kernel with `CONFIG_VHOST_VSOCK`. Confirm this first, because everything downstream assumes it.
2. **Guest kernel and rootfs (a build dependency, not a given).** Firecracker does not boot the host kernel. It needs a purpose-built guest `vmlinux` and a root filesystem. Check: are the guest kernel and rootfs artifacts present or buildable (public Firecracker CI artifacts, firecracker-demo, or Buildroot)? Plan this as an explicit build step (B1), not an assumption.
3. **TUN/TAP and host firewall (for Q2/Q3 egress).** The egress path needs tap devices and nftables/iptables. Q0/Q1 need neither. Check: `ls /dev/net/tun` and `which nft || which iptables`.
4. **cgroup version (jailer).** The jailer manages cgroups; confirm which version is mounted so it is invoked with the right `--cgroup-version`. Check: `stat -fc %T /sys/fs/cgroup` (`cgroup2fs` = v2).
5. **Build toolchain.** Rust for the Isolation Manager and the memory-safe listener. Check: `rustc --version && cargo --version`, or plan the install. Plus `setfacl` (acl), `ip` (iproute2), and disk space for images.
6. **Firecracker + jailer binaries, pinned.** Install a pinned Firecracker release matching host arch; confirm the jailer ships with it. Check: `firecracker --version && jailer --version`. Pin the version; §5 treats a version bump as a security event to retest.
7. **Repo and clean-room fence.** Confirm the box lives in its own clean-room location, separate from the capability-gate repo, with no engagement-era client material, and name the working branch before Cursor writes anything.

Report all seven as a MATCH/MISMATCH table, then stop. A MISMATCH on item 1 or 2 changes the plan and is a report-and-stop, not a workaround.

### A.2 Cursor task breakdown (build order)

Each step reports and stops before the next. Cursor wires and reports; it does not improvise around a failed check.

- **P0 - Preflight (A.1).** Run the seven checks, report the table, stop. No build starts on a MISMATCH of items 1 or 2.
- **B1 - Golden images.** Build the quarantine and live guest images (`vmlinux` + rootfs) with virtio and vsock, and a minimal init that speaks the validated vsock protocol. Deliverable: both images boot under Firecracker; BS-00 boot numbers recorded (time-to-init and full boot, per §5).
- **B2 - Isolation Manager skeleton.** The host daemon that drives the Firecracker REST API over its unix socket, launches a jailed microVM from a clean image, and tears it down with the host-untouched assertion. Deliverable: launch and teardown of one ephemeral box, host filesystem diff clean.
- **B3 - Hardened vsock listener (the §3.1 surface).** The memory-safe, schema-bounded, privilege-dropped listener. Build this before wiring any real data path through vsock. Deliverable: BS-04 passes, including its negative control.
- **B4 - Staged flow (Q0→Q3).** Quarantine, review-in-a-box, content-addressed airlock, live scoped box, wired to the manager and the listener. Deliverable: an artifact moves Q0 to live with no process crossing the airlock.
- **B5 - Egress proxy + DLP + canary.** Default-deny nftables, the host allowlist proxy with re-resolve and pin, argument DLP, canary tripwire, append-only signed log. Deliverable: the BS-02 egress cases and the BS-03 canary path pass with their negative controls.
- **B6 - Boundary suite green.** BS-00 through BS-04, each with its negative control, run and recorded. Deliverable: the suite is green, and only now do the containment properties move from vision to record.

Nothing in B1–B6 is load-bearing until B6 is green. The order front-loads the two things a build of this shape usually gets wrong: the listener before the data path (B3 before B4), and the measurement before the claim (the BS suite gates the record status).

### A.3 Substrate provisioning - dedicated Linux VM (primary, added v1.4)

Provision a minimal Ubuntu Server LTS (24.04 or 22.04) guest, not a desktop image. At install: turn nested virtualization on in the hypervisor, install `linux-modules-extra`, load `vhost_vsock` (`sudo modprobe vhost_vsock` plus an `/etc/modules-load.d` entry so it persists), and confirm `/dev/vhost-vsock` appears. Keep the surface minimal: no GUI, key-only sshd, unattended-upgrades on, a fixed hostname or IP so the dev host can reach it. Install the pinned Firecracker and jailer inside the VM and confirm `/dev/kvm` there; the KVM group/ACL step happens inside the VM at install and never touches WSL2.

Topology - two channels, do not conflate them:
- **Inside the VM:** Isolation Manager to Firecracker over vhost-vsock. Native and local. This is the channel the WSL2 kernel could not provide.
- **Dev host to VM:** the controlled channel that hands artifacts in and pulls results out (key-only SSH, or a minimal request/response API). This is a new boundary introduced by moving to a dedicated VM, and it is untrusted-input surface. Apply the §3.1 rule to it: minimal, schema-bounded, privilege-dropped listener on the VM side, and a BS-04-class probe.

Then re-run the A.1 preflight inside the VM. Item 1 (vhost-vsock) should pass after the module load; the rest of the table is confirmed on the real build substrate before B1 starts.

**Windows edition gate (verify first, same spirit as the vhost-vsock catch).** Hyper-V Manager needs Windows 11 Pro, Enterprise, or Education. Home cannot create general Hyper-V VMs. Check Settings → System → About. Pro or better: enable Hyper-V and use it. Home: use VMware Workstation (free for personal use) or VirtualBox with nested virtualization on, or a dedicated Linux mini-PC for the strongest single-layer boundary.

**Hyper-V provisioning specifics for this host (AMD Ryzen, added v1.5).** Confirmed target: AMD Ryzen 9 7950X, 64 GB, Windows 11 Pro 25H2. `SOURCE:` Microsoft Learn states Hyper-V nested virtualization on AMD requires an AMD EPYC/Ryzen CPU, a Windows 11 or Server 2022+ host, and VM configuration version 10.0 or higher (learn.microsoft.com, enable-nested-virtualization, 2025-07). This host meets all three. Concrete steps, in order:
1. Create a Generation 2 VM at a current configuration version. New VMs on 25H2 default to a recent version; confirm with `Get-VM | Format-Table Name,Version` and raise it with `Update-VMVersion` if it is below 10.0. AMD nested virt fails on older versions.
2. Assign static memory, not Dynamic Memory. Nested virtualization does not run with Dynamic Memory. 16 to 24 GB static is ample on a 64 GB host.
3. With the VM powered off, run elevated: `Set-VMProcessor -VMName <name> -ExposeVirtualizationExtensions $true`. Without this, Firecracker inside the VM cannot reach KVM.
4. Enable MAC address spoofing on the VM's adapter so the nested guest network routes through the second virtual switch: `Get-VMNetworkAdapter -VMName <name> | Set-VMNetworkAdapter -MacAddressSpoofing On`.

A stale line in some guides says AMD does not support Hyper-V nested virtualization; it is from an old Azure Lab Services doc and is superseded by the prerequisites above. Inside the guest, proceed with the A.3 Ubuntu steps (install `linux-modules-extra`, `modprobe vhost_vsock`, confirm `/dev/vhost-vsock`), then re-run the A.1 preflight.
