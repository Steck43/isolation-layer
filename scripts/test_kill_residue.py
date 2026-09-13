"""kill_residue: leftover VMM fails; clean list passes."""
from __future__ import annotations

from kill_residue import list_vmm


def main() -> int:
    if list_vmm("user 1 firecracker --api-sock x\nuser 2 grep firecracker\n"):
        if len(list_vmm("user 1 firecracker --api-sock x\nuser 2 grep firecracker\n")) != 1:
            print("FAIL grep filtered wrong")
            return 1
    else:
        print("FAIL missed vmm")
        return 1
    if list_vmm("user 1 bash\n"):
        print("FAIL clean list")
        return 1
    print("PASS test_kill_residue")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
