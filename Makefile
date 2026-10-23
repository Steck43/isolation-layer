# One-command demos on seeded synthetic traffic.
#   make demo-all    run every scenario in demos/scenarios/, print the summary
#                    table, write out/summary.json and out/runs/
#   make demo-test   the same scenarios as cargo tests, plus seed change,
#                    determinism and one mutation check per scenario
# The demo crate (demos/sandbox-demo) is a workspace of its own; it uses the
# real vestibule, dropbox, inspector and aegis-common crates by path.
# No VM boots here: rows marked STUBBED run on a stub VM host. A real boot
# needs a host where KVM vCPU creation works and sudo for jailer-launch; see
# the BLOCKER in out/summary.json. Nothing here needs sudo.

CARGO ?= cargo
OUT ?= out
DEMO = --manifest-path demos/sandbox-demo/Cargo.toml

.PHONY: demo-all demo-test

demo-all:
	$(CARGO) run --quiet $(DEMO) -- run demos/scenarios --out $(OUT)

demo-test:
	$(CARGO) test --quiet $(DEMO)
