"""A bound receipt or box ticket is accepted once, across calls and processes.

Failure classes:
- box_entry.run built its replay set inside each call, so a live receipt
  handed back on a later call with the same id passed again.
- Real prove sends no receipt_id. The live path minted a fresh uuid for it, so
  the same prove receipt replayed on a later call got a new id and passed.
- The contract path minted a fresh id per call, so one box ticket spent on
  several calls passed each time.
- The seen set lived in one process, so a second process or a restart accepted
  a receipt the first had already spent.
"""

from __future__ import annotations

import importlib.util
import json
import multiprocessing
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "box_entry.py"


@pytest.fixture(autouse=True)
def _chain_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DECISION_CHAIN", str(tmp_path / "decision-chain.jsonl"))
    monkeypatch.delenv("BOX_LIVE_PROVE", raising=False)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ENTRY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _call(ticket: str = "t-1"):
    atoms = SimpleNamespace(
        block_message=None,
        winning_effect="allow",
        decision_digest="d" * 64,
        box_ticket=ticket,
    )
    decision = SimpleNamespace(
        verdict=SimpleNamespace(value="allow"),
        skill="s",
        tool="write_file",
        paths=["a"],
        reason="ok",
    )
    return {
        "atoms_result": atoms,
        "decision": decision,
        "tool": "write_file",
        "path": "a",
        "content": "x",
        "tool_call_id": "call-1",
    }


def _fixed_live(be, receipt_id: str | None, jail_id: str = "mgr-1"):
    def live(*, tool_call_id, gate_decision_sha256, atoms_result_sha256):
        receipt = {
            "jail_id": jail_id,
            "mode": "jailed-via-helper",
            "time_to_userspace_ms": 1.0,
            "time_to_workload_ms": 2.0,
            **{k: True for k in be._PROVE_BOOLS},
            "spot_checks": {k: True for k in be._SPOT_KEYS},
            "dropbox_hash": "e" * 64,
            "tool_call_id": tool_call_id,
            "gate_decision_sha256": gate_decision_sha256,
            "atoms_result_sha256": atoms_result_sha256,
        }
        if receipt_id is not None:
            receipt["receipt_id"] = receipt_id
        return receipt

    return live


def test_live_receipt_replayed_on_a_later_call_is_refused(monkeypatch) -> None:
    be = _load("box_entry_replay_a")
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, "r-replay-a"))
    assert be.run(**_call("t-a1")) is not None
    assert be.run(**_call("t-a2")) is None


def test_real_prove_receipt_without_receipt_id_is_refused_on_replay(
    monkeypatch,
) -> None:
    # Real prove prints no receipt_id; the jail id is the receipt's identity.
    be = _load("box_entry_replay_real")
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, None, "mgr-170-42"))
    first = be.run(**_call("t-real-1"))
    assert first is not None
    assert first["receipt_id"] == "mgr-170-42"
    assert be.run(**_call("t-real-2")) is None


def test_live_box_ticket_spent_twice_is_refused(monkeypatch) -> None:
    be = _load("box_entry_replay_live_ticket")
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, None, "mgr-1"))
    assert be.run(**_call("t-same")) is not None
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, None, "mgr-2"))
    assert be.run(**_call("t-same")) is None


def test_contract_box_ticket_spent_twice_is_refused() -> None:
    be = _load("box_entry_replay_contract_ticket")
    results = [be.run(**_call("t-contract")) for _ in range(5)]
    assert sum(r is not None for r in results) == 1


def test_receipt_spent_before_a_restart_is_refused_after_it(monkeypatch) -> None:
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    first = _load("box_entry_replay_restart_1")
    monkeypatch.setattr(first, "invoke_live_prove", _fixed_live(first, None, "mgr-r"))
    assert first.run(**_call("t-r1")) is not None
    second = _load("box_entry_replay_restart_2")  # a fresh module, empty memory
    monkeypatch.setattr(second, "invoke_live_prove", _fixed_live(second, None, "mgr-r"))
    assert second.run(**_call("t-r2")) is None


def test_parallel_calls_accept_one_copy_of_a_receipt(monkeypatch) -> None:
    be = _load("box_entry_replay_b")
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, "r-replay-b"))
    results: list = []
    start = threading.Barrier(8)

    def go(i: int) -> None:
        start.wait()
        results.append(be.run(**_call(f"t-b{i}")))

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r is not None for r in results) == 1


class _SlowSet(set):
    def __contains__(self, key) -> bool:
        time.sleep(0.005)
        return super().__contains__(key)


def test_parallel_calls_with_a_slow_lookup_accept_one_copy(monkeypatch) -> None:
    # A slow membership check widens the window between check and record, so
    # without the lock several threads see the receipt as unspent.
    be = _load("box_entry_replay_slow")
    monkeypatch.setattr(be, "_SpentKeys", _SlowSet)
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, None, "mgr-slow"))
    results: list = []
    start = threading.Barrier(8)

    def go(i: int) -> None:
        start.wait()
        results.append(be.run(**_call(f"t-slow{i}")))

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r is not None for r in results) == 1


def _spend_in_child(chain: str, barrier, out) -> None:
    import os

    os.environ["AEGIS_DECISION_CHAIN"] = chain
    os.environ["BOX_LIVE_PROVE"] = "1"
    be = _load(f"box_entry_replay_proc_{os.getpid()}")
    be._SpentKeys = _SlowSet
    be.invoke_live_prove = _fixed_live(be, None, "mgr-proc")
    barrier.wait()
    out.put(be.run(**_call(f"t-proc-{os.getpid()}")) is not None)


def test_two_processes_accept_one_copy_of_a_receipt(tmp_path) -> None:
    ctx = multiprocessing.get_context("fork")
    chain = str(tmp_path / "decision-chain.jsonl")
    barrier = ctx.Barrier(2)
    out = ctx.Queue()
    procs = [
        ctx.Process(target=_spend_in_child, args=(chain, barrier, out))
        for _ in range(2)
    ]
    for p in procs:
        p.start()
    got = [out.get(timeout=30) for _ in procs]
    for p in procs:
        p.join(timeout=30)
    assert sorted(got) == [False, True]


def test_spent_keys_expire_with_the_ticket_lifetime(monkeypatch) -> None:
    be = _load("box_entry_replay_expiry")
    assert be.run(**_call("t-exp-1")) is not None
    store = be._spent_store_path()
    assert store.is_file()
    rows = [json.loads(line) for line in store.read_text().splitlines()]
    assert rows and all(r["exp"] > time.time() for r in rows)
    later = time.time() + be.BOX_TICKET_LIFETIME_S + 1
    monkeypatch.setattr(be.time, "time", lambda: later)
    assert be.run(**_call("t-exp-2")) is not None
    keys = [json.loads(line)["key"] for line in store.read_text().splitlines()]
    assert ("ticket:" + be._sha256_text("t-exp-1")) not in keys
    assert len(keys) == 2  # the first call's keys were pruned


def test_unwritable_store_fails_closed(tmp_path, monkeypatch) -> None:
    be = _load("box_entry_replay_unwritable")
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    monkeypatch.setenv("AEGIS_DECISION_CHAIN", str(blocker / "decision-chain.jsonl"))
    assert be.run(**_call("t-unwritable")) is None


def test_fresh_receipts_keep_passing(monkeypatch) -> None:
    be = _load("box_entry_replay_c")
    assert (
        be.run(**_call("t-c1")) is not None
    )  # contract path, a fresh ticket each call
    assert be.run(**_call("t-c2")) is not None
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    for i in range(3):
        monkeypatch.setattr(
            be, "invoke_live_prove", _fixed_live(be, None, f"mgr-fresh-{i}")
        )
        assert be.run(**_call(f"t-c-live-{i}")) is not None


# Failure class: the prune rewrote the store in place (truncate, then write the
# live rows back), so a write error or a kill between the truncate and the
# fsync left the store empty or cut and a spent ticket was accepted again.


def _seed_store(be, live_tickets: list[str], filler: int = 0) -> Path:
    """Write one expired row, `filler` live filler rows and the live tickets."""
    store = be._spent_store_path()
    store.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    rows = [{"key": "ticket:expired", "exp": now - 1}]
    rows += [{"key": f"filler:{i}", "exp": now + 3600} for i in range(filler)]
    rows += [
        {"key": "ticket:" + be._sha256_text(t), "exp": now + 3600} for t in live_tickets
    ]
    store.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return store


def _store_keys(store: Path) -> list[str]:
    return [json.loads(line)["key"] for line in store.read_text().splitlines()]


def test_a_write_error_during_the_prune_keeps_the_spent_rows() -> None:
    import resource
    import signal

    be = _load("box_entry_replay_prune_efbig")
    store = _seed_store(be, ["t-live"])
    spent = "ticket:" + be._sha256_text("t-live")
    old = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, hard))
    try:
        # The prune runs, its write fails with EFBIG, and the call is refused.
        assert be.run(**_call("t-new")) is None
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
        signal.signal(signal.SIGXFSZ, old)
    assert spent in _store_keys(store)
    assert be.run(**_call("t-live")) is None


def _prune_then_hang(chain: str, ready) -> None:
    import os

    os.environ["AEGIS_DECISION_CHAIN"] = chain
    be = _load(f"box_entry_replay_kill_{os.getpid()}")
    real = be.json

    class _HangOnRow:
        # Stops the child at the first spent store row it writes, so the
        # parent kills it mid prune on every run, not by timing luck.
        def __getattr__(self, name):
            return getattr(real, name)

        @staticmethod
        def dumps(obj, *a, **kw):
            if isinstance(obj, dict) and set(obj) == {"key", "exp"}:
                ready.set()
                while True:
                    time.sleep(60)
            return real.dumps(obj, *a, **kw)

    be.json = _HangOnRow()
    be.run(**_call("t-kill-new"))


def test_a_kill_mid_prune_keeps_the_spent_rows() -> None:
    import os
    import signal

    be = _load("box_entry_replay_prune_kill")
    store = _seed_store(be, ["t-kill-live"], filler=20000)
    before = len(store.read_text().splitlines())
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    child = ctx.Process(
        target=_prune_then_hang, args=(os.environ["AEGIS_DECISION_CHAIN"], ready)
    )
    child.start()
    assert ready.wait(timeout=30), "child never reached the prune write"
    os.kill(child.pid, signal.SIGKILL)
    child.join(timeout=30)
    assert child.exitcode == -signal.SIGKILL
    assert len(store.read_text().splitlines()) == before
    assert be.run(**_call("t-kill-live")) is None


# Failure class: a spender that opens the store before it holds the lock, or
# that locks the store file itself, keeps the inode a concurrent prune then
# replaces, reads the rows from before that prune, and accepts a ticket the
# pruner has just spent.


def _prune_and_hold(chain: str, holding, go, out) -> None:
    import os

    os.environ["AEGIS_DECISION_CHAIN"] = chain
    be = _load(f"box_entry_replay_pruner_{os.getpid()}")

    class _HoldUnderLock(set):
        # The pruner stops here with the lock held and the store read, until
        # the parent has seen the spender reach its own lock call.
        def __contains__(self, key) -> bool:
            holding.set()
            go.wait(30)
            return super().__contains__(key)

    be._SpentKeys = _HoldUnderLock
    out.put(("pruner", be.run(**_call("t-race")) is not None))


def _spend_behind_the_pruner(chain: str, at_lock, out) -> None:
    import os

    os.environ["AEGIS_DECISION_CHAIN"] = chain
    be = _load(f"box_entry_replay_spender_{os.getpid()}")
    real = be.fcntl

    class _SignalAtLock:
        def __getattr__(self, name):
            return getattr(real, name)

        @staticmethod
        def flock(fd, op):
            at_lock.set()
            return real.flock(fd, op)

    be.fcntl = _SignalAtLock()
    out.put(("spender", be.run(**_call("t-race")) is not None))


def test_a_spender_behind_a_prune_reads_the_store_the_prune_wrote() -> None:
    import os

    be = _load("box_entry_replay_lock_order")
    store = _seed_store(be, [])  # one expired row, so the pruner replaces the store
    chain = os.environ["AEGIS_DECISION_CHAIN"]
    ctx = multiprocessing.get_context("fork")
    holding, go, at_lock = ctx.Event(), ctx.Event(), ctx.Event()
    out = ctx.Queue()
    pruner = ctx.Process(target=_prune_and_hold, args=(chain, holding, go, out))
    pruner.start()
    assert holding.wait(timeout=30), "pruner never held the lock"
    spender = ctx.Process(target=_spend_behind_the_pruner, args=(chain, at_lock, out))
    spender.start()
    assert at_lock.wait(timeout=30), "spender never reached its lock call"
    go.set()
    got = dict(out.get(timeout=30) for _ in range(2))
    pruner.join(timeout=30)
    spender.join(timeout=30)
    assert got == {"pruner": True, "spender": False}
    assert "ticket:" + be._sha256_text("t-race") in _store_keys(store)


# Failure class: the store or its lock opened through a symlink writes spent
# rows into, or locks, whatever file the link names.


@pytest.mark.parametrize("which", ["store", "lock"])
def test_a_symlinked_store_or_lock_is_refused(tmp_path, which) -> None:
    be = _load(f"box_entry_replay_link_{which}")
    store = be._spent_store_path()
    store.parent.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "elsewhere" / "victim"
    victim.parent.mkdir()
    victim.write_text("")
    link = store if which == "store" else store.with_name(store.name + ".lock")
    link.symlink_to(victim)
    assert be.run(**_call(f"t-link-{which}")) is None
    assert victim.read_text() == ""
    assert link.is_symlink()


# Failure class: the prune wrote through a fixed temp name opened with
# O_TRUNC, so a file planted at that name was truncated (a hard link to the
# chain), refused the prune (a symlink), or hung it under the lock (a FIFO).


@pytest.mark.parametrize("plant", ["hardlink", "symlink"])
def test_a_file_planted_at_the_old_temp_name_is_left_alone(tmp_path, plant) -> None:
    import os

    be = _load(f"box_entry_replay_plant_{plant}")
    store = _seed_store(be, ["t-plant-live"])
    victim = tmp_path / "decision-chain.jsonl"
    victim.write_text('{"row": 1}\n')
    planted = store.with_name(store.name + ".tmp")
    if plant == "hardlink":
        os.link(victim, planted)
    else:
        planted.symlink_to(victim)
    assert be.run(**_call("t-plant-new")) is not None  # the prune ran and landed
    assert victim.read_text() == '{"row": 1}\n'
    assert os.path.lexists(planted) and os.path.samefile(planted, victim)
    assert "ticket:expired" not in _store_keys(store)
    assert be.run(**_call("t-plant-live")) is None
    assert not list(store.parent.glob(store.name + ".*.tmp"))


def _prune_once(chain: str, out) -> None:
    import os

    os.environ["AEGIS_DECISION_CHAIN"] = chain
    be = _load(f"box_entry_replay_fifo_{os.getpid()}")
    out.put(be.run(**_call("t-fifo-new")) is not None)


def test_a_fifo_planted_at_the_old_temp_name_does_not_hang_the_prune() -> None:
    import os

    be = _load("box_entry_replay_plant_fifo")
    store = _seed_store(be, ["t-fifo-live"])
    planted = store.with_name(store.name + ".tmp")
    os.mkfifo(planted)
    ctx = multiprocessing.get_context("fork")
    out = ctx.Queue()
    child = ctx.Process(
        target=_prune_once, args=(os.environ["AEGIS_DECISION_CHAIN"], out)
    )
    child.start()
    child.join(timeout=10)
    hung = child.is_alive()
    if hung:
        child.kill()
        child.join(timeout=10)
    assert not hung, "the prune blocked on the planted FIFO with the lock held"
    assert out.get(timeout=5) is True
    assert "ticket:expired" not in _store_keys(store)
    assert be.run(**_call("t-fifo-live")) is None
