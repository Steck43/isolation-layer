# B3 honesty pack — Act On (post-interrogate)

## Tip
Ships after tip `4e76cb1` (2g). Closes consensus Act On from multi-model interrogate + security review.

## What changed
1. **inspect_verdict hot path** — `vsock_inspect_reply` + `parse_verdict_line` (`deny_unknown_fields`); bare-hex removed; outcome from guest JSON.
2. **Golden rootfs** — always `copy_rootfs` (never hardlink writable disk); host snapshot hashes golden kernel+rootfs; prove prints `host_vmm_hygiene=PASS`.
3. **Seccomp arch gate** — `AUDIT_ARCH_X86_64` + reject x32 bit before allow ladder.
4. **Teardown** — removed `pkill -f`; `fresh_jail_id(prefix-nanos-pid)` for mgr/insp.
5. **Consider (bundled)** — inspect vsock reply cap + harden-after-bind; vestibule-listen defaults `--harden`; UTF-8-safe serial tails; handoff_result_message; prove tears down mgr before insp; dropbox post-handoff retrieve assert; nesting brace-count removed from enforce path.

## Explicitly still VISION
- Full BS-01/03 host filesystem manifest (scratch `/tmp` etc.)
- mprotect/mmap PROT_EXEC arg filter
- Landlock / dedicated vestibule uid
- Always-invoked brain↔box wiring (API now typed for it)
