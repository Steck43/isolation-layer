# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Prove receipts bind to `--tool-call-id` plus `--gate-decision-sha256` and `--atoms-result-sha256`. A prove without those three is refused. `always_invoked` stays false until a receipt proves otherwise.
- Unit tests now call the real harden report, `handoff_result_message` kind gate, `read::run` never-grant, inspect-vm parse path, jailer-launch cleanup, `assert_host_vmm_hygiene`, and vsock UTF-8 reject. A cgroup skip is not a pass. `enter_listener_cgroup` `Ok(false)` with `XDG_RUNTIME_DIR` unset fails `cgroup_jail_attaches_under_user_service`.

### Removed

- Default-branch tip no longer carries the dated seat directive or `SESSION-STATE.md`. `.mailmap` keeps noreply folding and no longer names a tailnet host. Host-refuse prove strings stay.

### Changed

- README Figure 1 is the dest-true SVG. The box sits between floor and judge. Mermaid stays the sketch.
- README drops identity-as-horizon. The four planes take identity as an argument. This roof stays the box.

### Added

- `scripts/conflicting_handoff.py` launches the box only on a CONFLICTING rollup. Dry by default. `--launch` is the boot plus kill-residue path. Tests never boot.
- `scripts/kill_residue.py` fails if a Firecracker guest or VMM is still up after teardown. Anderson row 2. Not a boot. A dest-read command line that names those binaries is not residue.
- `scripts/dropbox_hash_guard.py` hashes host-held body bytes and rejects path escape. Time Chamber is not the door. `always_invoked` stays false.
- `cargo test --workspace` in floor CI. README names the MIT LICENSE versus Cargo Apache-2.0 split.
- LOOP-006 four named rows (`tests/test_loop006_named.py`). Each skips without `AEGISBOX_PROVE`. Boot/kill is not this suite.
- CITATION.cff and `.zenodo.json` so a later tag can mint. No DOI on this record yet.
- Isolation-manager `read` verb: allowlisted host-path read under observe. Receipts keep `always_invoked_claim` false.
- Repo floor: GitHub Actions (secrets, authorship, tests 3.11/3.12, ruff, craft, zizmor/actionlint), Dependabot 7-day cooldown, SECURITY.md.

### Changed

- README plane order: the box sits between floor and judge; the allowlist is only the floor beneath the atom plane; a contradiction the rollup cannot settle is the handoff. Ordering is design intent; `always_invoked_claim` stays false.
- README keeps the Firecracker lede and points the three-object restatement at aegis-atoms instead of repeating it here.

### Fixed

- First push of a new branch resolves craft BASE to the origin default, so required craft jobs do not fail on an all-zero `github.event.before`.
- Cite the Ona / Di Donato primary for the bubblewrap `/proc/self/root` escape (February to March 2026, not April) and link the story.
