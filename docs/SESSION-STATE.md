# Session state — 2026-07-10 (end of day)

Branch: `scaffold` on host `aegis-box` (`~/isolation-layer`).

## Latest commit

See `git log -1 --oneline` after the session-state commit below.

## Task status

| Task | Status |
|---|---|
| **B1** | **CLOSED** — Firecracker/jailer v1.16.1, golden CI image, jailed microVM boot, three isolation spot-checks pass, BS-00 recorded (direct + jailed). See `docs/b1-record.md`. |
| **B2** | Manager skeleton + `jailer-launch` helper built and committed; validation unit tests pass. End-to-end `isolation-manager prove` **BLOCKED** pending operator install of scoped sudoers rule. See `docs/b2-record.md`, `deploy/INSTALL.md`. |
| **B3** | Not started. |

## Host state (trust root)

| Item | State |
|---|---|
| Firecracker v1.16.1 | Installed at `/usr/local/bin/firecracker` |
| Jailer v1.16.1 | Installed at `/usr/local/bin/jailer` |
| `jailer-launch` helper | **Not installed** (`/usr/local/bin/jailer-launch` absent) |
| Sudoers rule | **Not installed** (`/etc/sudoers.d/aegis-jailer` absent) |
| Scoped NOPASSWD | **Not configured** — trust root untouched |

Golden image artifacts live under `artifacts/x86_64/` (gitignored; fetch via `scripts/fetch-golden-image.sh`).

## Morning resume steps

a. Operator pastes the jailer-launch helper source and the aegis-common validation it calls to Opus, for audit of three points: (i) paths are canonicalized before the allowlist check, (ii) uid comes from SUDO_UID not a caller argument, (iii) no caller input can inject extra argv into jailer/firecracker (strict jail-id pattern, bounded image paths).

b. Only after that audit passes: run `visudo -cf deploy/sudoers.d/aegis-jailer` on the repo copy FIRST, then install the helper root-owned 0755 and the sudoers rule 0440 root:root, then re-validate on the installed path.

c. Run `cargo run -p isolation-manager -- prove` for the end-to-end jailed launch, spot-checks, vsock, BS-00, and host-untouched diff. That closes B2.

d. Then request the B3 directive.

## Untracked (not committed)

- `docs/Cursor-Directive-B2-2026-07-09.md` — operator reference copy; left out of git intentionally this session.
