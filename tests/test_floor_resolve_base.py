"""The script that picks each craft job's base comes from the base, not the change.

resolve_base.sh sets BASE for the voice, changelog and comment jobs. A pull
request that edits it would otherwise choose the range it is judged on. Each
job reads it from the base commit the event names (the pull request base, the
push's previous commit, else origin's default branch) into the runner's temp
dir, fails closed when that commit has none, and never sources the change's
copy.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
JOBS = ["craft-voice", "craft-changelog", "craft-comments"]


def _job(name: str) -> str:
    text = (ROOT / ".github" / "workflows" / "floor.yml").read_text(encoding="utf-8")
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text
    )
    assert match, name
    return match.group(1)


@pytest.mark.parametrize("name", JOBS)
def test_the_job_loads_resolve_base_from_the_base(name: str) -> None:
    job = _job(name)
    assert 'git cat-file -e "${SRC}:.floor/craft/resolve_base.sh"' in job
    assert (
        'git show "${SRC}:.floor/craft/resolve_base.sh" > '
        '"${RUNNER_TEMP}/craft/resolve_base.sh"'
    ) in job
    assert '. "${RUNNER_TEMP}/craft/resolve_base.sh"' in job
    assert "has no resolve_base.sh; refusing to run the pull request copy" in job


@pytest.mark.parametrize("name", JOBS)
def test_the_job_never_sources_the_change_copy(name: str) -> None:
    job = _job(name)
    sourced = re.findall(r"(?m)(?:^|\s)\.\s+(\S*resolve_base\.sh\S*)", job)
    assert sourced == ['"${RUNNER_TEMP}/craft/resolve_base.sh"'], sourced
