"""The voice lint reads "underscore" as the character name, not as AI vocabulary.

The verb sense ("this underscores the point") stays an AI-vocabulary hit. The
noun naming the character ("split by a dash, underscore or dot") is plain text.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "voice_lint_underscore", ROOT / ".floor" / "craft" / "voice_lint.py"
)
assert _SPEC and _SPEC.loader
voice = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(voice)


def _vocab_hits(text: str) -> list[str]:
    return [
        h
        for h in voice.scan_text("t", text, fail_on_warn=True)
        if "AI-VOCAB" in h and "underscor" in h.lower()
    ]


# The sentence shape of the commit message the lint flagged in CI.
COMMIT_SENTENCE = (
    "Survivors led to tests for host names split by a dash, underscore or dot "
    "and glued to more letters."
)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(COMMIT_SENTENCE, id="commit-sentence"),
        pytest.param("Names may hold an underscore.", id="an-underscore"),
        pytest.param("Allow underscores in names.", id="plural-noun"),
        pytest.param("Replace underscores with dashes.", id="plural-object"),
        pytest.param("Strip a leading underscore from the key.", id="leading"),
        pytest.param("The underscore character separates the parts.", id="the-noun"),
        pytest.param("Underscore, dash and dot all split a name.", id="sentence-start"),
    ],
)
def test_the_character_name_is_not_ai_vocabulary(text: str) -> None:
    assert _vocab_hits(text) == []


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("This underscores the point.", id="underscores-the"),
        pytest.param("The result underscores how fragile it is.", id="underscores-how"),
        pytest.param(
            "These results underscore the importance of tests.", id="underscore-the"
        ),
        pytest.param("It underscored the need for a pin.", id="underscored"),
        pytest.param("Underscoring the need for review.", id="underscoring"),
        pytest.param("That underscores why it matters.", id="underscores-why"),
    ],
)
def test_the_verb_sense_is_still_ai_vocabulary(text: str) -> None:
    assert len(_vocab_hits(text)) == 1, voice.scan_text("t", text, fail_on_warn=True)


def test_other_ai_vocabulary_is_unchanged() -> None:
    hits = voice.scan_text("t", "We delve into a pivotal tapestry.", fail_on_warn=True)
    assert sum("AI-VOCAB" in h for h in hits) == 3
