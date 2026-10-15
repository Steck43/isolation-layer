"""The voice lint that judges a change comes from the base, not the change.

A pull request that edits .floor/craft/voice_lint.py would otherwise judge
itself with its own copy. The craft (voice) job loads the base copy into the
runner's temp dir, fails closed when the base has none, and runs only that.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _job(name: str) -> str:
    text = (ROOT / ".github" / "workflows" / "floor.yml").read_text(encoding="utf-8")
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text
    )
    assert match, name
    return match.group(1)


def test_the_voice_job_loads_the_lint_from_the_base_into_a_temp_dir() -> None:
    job = _job("craft-voice")
    assert 'git cat-file -e "${BASE}:.floor/craft/voice_lint.py"' in job
    assert (
        'git show "${BASE}:.floor/craft/voice_lint.py" > '
        '"${RUNNER_TEMP}/voice/voice_lint.py"'
    ) in job
    assert "has no voice lint; refusing to run the pull request copy" in job


def test_the_voice_job_runs_only_the_base_copy() -> None:
    job = _job("craft-voice")
    runs = re.findall(r"^\s*python3?\b.*$", job, re.M)
    assert runs == [
        '          python3 -I "${RUNNER_TEMP}/voice/voice_lint.py" --commits '
        '--base "$BASE" --head HEAD --prose --fail-on-warn'
    ], runs
    assert "voice_lint.py missing from roof" not in job
