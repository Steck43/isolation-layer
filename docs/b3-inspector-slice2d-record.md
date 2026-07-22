# B3.2d — inspect_verdict multi-outcome (claim / disposition)

## What shipped
- Guest claim schema: `schema_version:1`, `outcome` ∈ {clear,suspect,failed}, `reasons` closed enum
- Host `decide_disposition` → Advance | Hold | Drop (guest never drives advance)
- Sole parse: `parse_verdict_line`; transport returns bounded UTF-8 line (no bare-hex, no substring gate)
- Prove gates `inspector_verdict_ok` on schema_ok + host_hash_match + disposition=advance + claim=clear
- Teardown kills `firecracker.pid` inside jail_root (no `pkill -f`)

## Evidence
- `cargo test -p inspector` (11 pass)
- `isolation-manager prove` → `inspector_claim_outcome=clear` · `inspector_disposition=advance` · `host_vmm_hygiene=PASS`

## Research posture
CQ-039 Option A / IDEA-CUR-249 — claims ≠ decisions (CaMeL/AuthGraph pattern-adopt)

## Explicitly not in 2d
- Real Stage-Q1 analyzers · always-invoked · cgroup · mprotect · guest max_qualification
