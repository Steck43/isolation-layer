# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Step 12: `scripts/box_entry.py` `run` accepts `tool_call_id` and, when `BOX_LIVE_PROVE=1`, boots live `isolation-manager prove` under that id (no `skill:tool:path` invent). Unset env keeps the CI-shaped contract receipt. Fake, replay, and wrong-call-id denials still run through `accept_bound_receipt`. `tests/test_step12_box_entry_live.py` pins both paths. `always_invoked` stays false.
- `receipts/STEP-10b-2026-10-09.md`: re-prove of the Step 10 live harness on a clean isolation `main` tip (`9cdf7ee`) on the box after the scaffold checkout was moved aside (call id `step10b-20261010T025228Z`). Host HEAD and `git status` are named on the receipt. `always_invoked` stays false.
- `scripts/step10_live_harness.py` runs one write through real `Gate.evaluate` and `evaluate_tool_call`, seals gate and atoms digests through `box_entry`, and can feed those digests into live `isolation-manager prove` on the box. `tests/test_step10_live_e2e.py` fails first until those digests match recomputation. `receipts/STEP-10-2026-10-09.md` records the live call (`step10-20261010T010139Z`). `always_invoked` stays false.
- `receipts/INVENTORY-2026-10-09.md` records box and judge state (BUILT / TESTED / LIVE-PROVEN) before Step 10 wiring. `always_invoked` stays false.
- `receipts/STEP-9b-2026-10-09.md`: live jailer prove on the box against `main` tip `395319e` with call-bound digests.

### Fixed

- `scripts/public_surface_scan.py` fails closed on a tracked path that is missing from the worktree or is not a regular file, reporting it by index, instead of scanning it as empty bytes. A symbolic link is judged on its target text. `tests/test_scan_fail_closed.py` also proves that `main()` runs the canary self-check, that an error while loading the list prints only its type, and that each UTF-32 view is needed for look-alike letters beyond U+FFFF.
- The serve scripts default to the unit's socket, `/var/lib/isolation-manager/isolation-manager.sock`, and the scripts that inspect the running service default to the unit's decision chain. They had defaulted to a per-user state directory, so the socket stat check in `scripts/serve-closed-t5-t6.sh` looked at the wrong file. `tests/test_socket_path.py` checks every tracked socket default against the unit.
- `deploy/do-operator-install.sh` creates the `isolation` system account the unit runs as (own group, no login shell, home at the unit's state directory) before the sudoers grant uses it. `tests/test_installer_account.py` checks the installer against the unit file and the sudoers grant.
- The guest spot checks read a marker only from a line that is exactly that marker. The serial console echoes every typed command, so the echoed probe text used to satisfy the no-VMM check and always tripped the visible-home check. The probes now type each marker with an empty quote pair inside it, so the typed text never contains the marker the shell prints. `scripts/b1-prove.py` records the same verdicts and exits 1 when a spot check fails.
- Drop the Dependabot `pip` ecosystem on this roof. There is no `requirements.txt` or `pyproject.toml`, so the weekly pip job failed with `dependency_file_not_found` (run `37385460556`).

### Added

- `scripts/box_entry.py` accepts only prove-shaped receipts bound to this call id, ticket digest, and content hash. Fake, replayed, and wrong-call-id receipts are denied. `always_invoked` stays false.
- Prove receipts bind to `--tool-call-id` plus `--gate-decision-sha256` and `--atoms-result-sha256`. A prove without those three is refused. `always_invoked` stays false until a receipt proves otherwise.
- Unit tests now call the real harden report, `handoff_result_message` kind gate, `read::run` never-grant, inspect-vm parse path, jailer-launch cleanup, `assert_host_vmm_hygiene`, and vsock UTF-8 reject. A cgroup skip is not a pass. `enter_listener_cgroup` `Ok(false)` with `XDG_RUNTIME_DIR` unset fails `cgroup_jail_attaches_under_user_service`.

### Removed

- Default-branch tip no longer carries the dated seat directive or `SESSION-STATE.md`. `.mailmap` keeps noreply folding and no longer names a tailnet host. Host-refuse prove strings stay.

### Changed

- Public files no longer carry a host home path, a host address, a personal email, the box host name, or the private name list in any recoverable form. `scripts/public_surface_scan.py` (standard library only) scans every tracked file and file name in every encoding (UTF-8, UTF-16 and UTF-32 at every alignment, binary with NUL bytes), after decoding (percent, escapes, HTML entities, base64, hex), normalising (NFKC, zero-width and look-alike letters), and rejoining split strings and continued lines. Built-in rules cover home paths, WSL network paths, private IPv4 and IPv6 ranges, emails, user@host names, and the box host name (by hash). The private list is never stored here: it is passed as the `LEAK_DENYLIST` secret (or a local untracked file), which must hold the expected number of entries plus a canary that has to be found in all 24 planted forms. Hits print the rule and entry number, never the term, and a file name that carries a term prints as its index. The CI job that runs it from the base branch with the secret lands separately, once this scanner is on the base branch. The box host name and its trust domain left the tree: `BOX_LIVE_PROVE` and `BOX_SSH_TARGET` replace the old variable names, `scripts/sync-to-box.sh` replaces the old script, and the SPIRE issuer takes `BOX_HOSTNAME` (refuses when unset) and `BOX_TRUST_DOMAIN` (default `box.invalid`). The raw Step 12b receipt keeps its produced CRLF line endings, and its redacted digest is re-recorded. The guest home check uses the manager home resolved at runtime, and the manager unit runs as `isolation`.
- README Figure 1 is the dest-true SVG. The box sits between floor and judge. Mermaid stays the sketch.
- README drops identity-as-horizon. The four planes take identity as an argument. This roof stays the box.

### Added

- `scripts/conflicting_handoff.py` launches the box only on a CONFLICTING rollup. Dry by default. `--launch` is the boot plus kill-residue path. Tests never boot.
- `scripts/kill_residue.py` fails if a Firecracker guest or VMM is still up after teardown. Anderson row 2. Not a boot. A dest-read command line that names those binaries is not residue.
- `scripts/dropbox_hash_guard.py` hashes host-held body bytes and rejects path escape. Time Chamber is not the door. `always_invoked` stays false.
- `cargo test --workspace` in floor CI. README names the MIT LICENSE versus Cargo Apache-2.0 split.
- LOOP-006 four named rows (`tests/test_loop006_named.py`). Each skips without `BOX_LIVE_PROVE`. Boot/kill is not this suite.
- CITATION.cff and `.zenodo.json` so a later tag can mint. No DOI on this record yet.
- Isolation-manager `read` verb: allowlisted host-path read under observe. Receipts keep `always_invoked_claim` false.
- Repo floor: GitHub Actions (secrets, authorship, tests 3.11/3.12, ruff, craft, zizmor/actionlint), Dependabot 7-day cooldown, SECURITY.md.

### Changed

- README plane order: the box sits between floor and judge; the allowlist is only the floor beneath the atom plane; a contradiction the rollup cannot settle is the handoff. Ordering is design intent; `always_invoked_claim` stays false.
- README keeps the Firecracker lede and points the three-object restatement at aegis-atoms instead of repeating it here.

### Fixed

- First push of a new branch resolves craft BASE to the origin default, so required craft jobs do not fail on an all-zero `github.event.before`.
- Cite the Ona / Di Donato primary for the bubblewrap `/proc/self/root` escape (February to March 2026, not April) and link the story.
