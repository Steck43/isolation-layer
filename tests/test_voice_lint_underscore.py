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


# Every form of the word is AI vocabulary in any use, not only when an
# emphasised object follows. Only the noun naming the _ character passes.
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("It underscores security.", id="underscores-bare-noun"),
        pytest.param("We underscore it twice.", id="underscore-pronoun"),
        pytest.param(
            "The risk was underscored by the review.", id="underscored-passive"
        ),
        pytest.param("Underscoring trust, the team shipped.", id="underscoring-bare"),
        pytest.param("That is what it underscores.", id="underscores-final"),
        pytest.param(
            "Reviewers underscore risks daily.", id="underscore-plural-object"
        ),
        pytest.param("An underscored warning followed.", id="underscored-adjective"),
        pytest.param("They kept underscoring it.", id="underscoring-pronoun"),
        pytest.param('It "underscored" the risk.', id="underscored-quoted"),
    ],
)
def test_every_form_of_the_word_is_ai_vocabulary(text: str) -> None:
    assert len(_vocab_hits(text)) == 1, voice.scan_text("t", text, fail_on_warn=True)


# The commit message that introduced the character-name reading must itself
# pass, since the commit scan reads every message on the branch.
CHARACTER_NAME_COMMIT = (
    "Read underscore as the character name in the voice lint\n\n"
    'The word list flagged "underscore" wherever it appeared, including where it\n'
    "names the _ character."
)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(CHARACTER_NAME_COMMIT, id="character-name-commit"),
        pytest.param("Split on the underscore (`_`).", id="code-span-glyph"),
        pytest.param("Split on an underscore (_).", id="bare-glyph"),
        pytest.param("Names hold letters, digits and underscores.", id="list-tail"),
        pytest.param("A double underscore marks a private name.", id="double"),
        pytest.param("Keys drop trailing underscores.", id="trailing-plural"),
        pytest.param("The underscores in a name are kept.", id="the-plural"),
        pytest.param("Use underscores between words.", id="plural-between"),
        pytest.param("A dash or underscore splits the host.", id="list-or"),
    ],
)
def test_the_character_name_in_more_shapes_passes(text: str) -> None:
    assert _vocab_hits(text) == [], voice.scan_text("t", text, fail_on_warn=True)
