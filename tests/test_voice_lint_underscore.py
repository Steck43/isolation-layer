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


# A verb use fails whatever stands around it: a quantifier subject, a list of
# character names before it, quotes around it, or a preposition after it.
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("All three underscore the point.", id="quantifier-three"),
        pytest.param("Both underscore the risk.", id="quantifier-both"),
        pytest.param("Many underscore it.", id="quantifier-many"),
        pytest.param("Several underscore the need for a pin.", id="quantifier-several"),
        pytest.param("Each underscores the point.", id="quantifier-each"),
        pytest.param("One underscores the risk early.", id="quantifier-one"),
        pytest.param("The pin, the number, underscore the risk.", id="list-subject"),
        pytest.param("A dot and a dash underscore the gap.", id="and-list-subject"),
        pytest.param("The checks underscore, dash and all, the risk.", id="list-after"),
        pytest.param('This "underscores" the point.', id="quoted-plural"),
        pytest.param('They "underscore" the need.', id="quoted-singular"),
        pytest.param("It 'underscores' the risk.", id="single-quoted"),
        pytest.param("It underscores in practice how weak it is.", id="prep-in"),
        pytest.param("This underscores with clarity.", id="prep-with"),
        pytest.param("Results underscore in every run.", id="plural-prep-in"),
        pytest.param("That underscores within a day.", id="prep-within"),
        pytest.param("The runs underscore character flaws.", id="before-character"),
    ],
)
def test_a_verb_use_in_every_shape_is_ai_vocabulary(text: str) -> None:
    assert len(_vocab_hits(text)) == 1, voice.scan_text("t", text, fail_on_warn=True)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Split names on underscores.", id="after-on"),
        pytest.param("Names written with underscores pass.", id="after-with"),
        pytest.param("Two underscores mark a private name.", id="two-plural"),
        pytest.param("Each underscore is kept.", id="each-singular"),
        pytest.param('The term "underscore" is the name.', id="quoted-name"),
        pytest.param("Join the parts by underscore, dash or dot.", id="list-after-by"),
        pytest.param("Keep the underscore character.", id="the-character"),
        pytest.param("Use an underscore separator.", id="an-separator"),
    ],
)
def test_the_character_name_in_its_tight_shapes_passes(text: str) -> None:
    assert _vocab_hits(text) == [], voice.scan_text("t", text, fail_on_warn=True)


# A word on the left that can start a subject ("this", "that", "these",
# "first", a quantity, or a verb form that is also a plural noun such as
# "uses") never exempts the word by itself: agreement and what follows decide.
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Results that underscore the risk.", id="that-relative"),
        pytest.param("Findings that underscore how weak it is.", id="that-how"),
        pytest.param("That underscores the gap.", id="that-subject"),
        pytest.param("We first underscore the need for pins.", id="first-adverb"),
        pytest.param("We last underscore the point.", id="last-adverb"),
        pytest.param("This underscores, in short, the risk.", id="this-comma"),
        pytest.param("These underscore the risk.", id="these-subject"),
        pytest.param("Those underscore it.", id="those-subject"),
        pytest.param("Some underscore the cost.", id="some-subject"),
        pytest.param("Few underscore it.", id="few-subject"),
        pytest.param("All underscore the need.", id="all-subject"),
        pytest.param("Each of these underscores the point.", id="each-of-these"),
        pytest.param("Both uses underscore the risk.", id="uses-noun-subject"),
        pytest.param("The matches underscore the gap.", id="matches-noun-subject"),
    ],
)
def test_a_subject_word_on_the_left_never_exempts_a_verb(text: str) -> None:
    assert len(_vocab_hits(text)) == 1, voice.scan_text("t", text, fail_on_warn=True)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("Underscores are stripped from keys.", id="sentence-start-are"),
        pytest.param("Underscores in keys are kept.", id="sentence-start-in"),
        pytest.param(
            "Python treats underscore-prefixed names as private.", id="compound-after"
        ),
        pytest.param("Rename the double-underscore methods.", id="compound-before"),
        pytest.param("Drop that underscore.", id="that-end"),
        pytest.param("This underscore is ignored.", id="this-singular"),
        pytest.param("These underscores in names are kept.", id="these-plural"),
        pytest.param("Keep the last underscore.", id="the-last"),
        pytest.param("Split at the first underscore in the key.", id="the-first"),
        pytest.param("Python uses underscores for private names.", id="uses-object"),
        pytest.param("Its underscores were dropped.", id="its-plural"),
        pytest.param("Their underscore was stripped.", id="their-singular"),
    ],
)
def test_the_noun_after_a_subject_word_passes(text: str) -> None:
    assert _vocab_hits(text) == [], voice.scan_text("t", text, fail_on_warn=True)


# A determiner and an ordinal, or a verb at the end of a clause, on the left
# never exempt a verb: an object after the word decides.


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("This first underscores the risk.", id="determiner-ordinal"),
        pytest.param("The tests we added underscore the gap.", id="after-a-clause"),
        pytest.param("The checks we used underscore this gap.", id="clause-this"),
        pytest.param("Each last underscores its point.", id="ordinal-possessive"),
        pytest.param("Underscore the point before you merge.", id="sentence-start"),
        pytest.param("Underscores the need for review.", id="sentence-start-plural"),
        pytest.param("It 'underscores' the need.", id="single-quoted-verb"),
    ],
)
def test_a_verb_after_an_ordinal_a_clause_or_at_the_start_is_caught(
    text: str,
) -> None:
    assert len(_vocab_hits(text)) == 1, voice.scan_text("t", text, fail_on_warn=True)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("The first underscore is dropped.", id="ordinal-end"),
        pytest.param("This first underscore in the key is kept.", id="ordinal-prep"),
        pytest.param("The first underscore that appears is kept.", id="ordinal-that"),
        pytest.param("Tests we added use underscores in names.", id="clause-prep"),
        pytest.param("We added underscores to the keys.", id="added-prep"),
        pytest.param("Names allowed underscores.", id="verb-end"),
        pytest.param("The 'underscore' is the separator.", id="single-quoted-noun"),
    ],
)
def test_the_noun_after_an_ordinal_or_a_verb_still_passes(text: str) -> None:
    assert _vocab_hits(text) == [], voice.scan_text("t", text, fail_on_warn=True)


# "it" or "that" as the object, and a verb after before/after/above/below used
# as an adverb at the end of a clause.


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("This first underscores it.", id="ordinal-it"),
        pytest.param("The tests we added underscore it.", id="clause-it"),
        pytest.param(
            "The tests we added underscore that point.", id="clause-that-noun"
        ),
        pytest.param("The last underscores that risk.", id="ordinal-that-noun"),
        pytest.param("The run before underscores the risk.", id="before-verb"),
        pytest.param("The check after underscores it.", id="after-verb-it"),
        pytest.param("The table above underscores the point.", id="above-verb"),
        pytest.param("The note below underscores that gap.", id="below-verb-that"),
        pytest.param("Read it before underscoring the point.", id="before-ing"),
    ],
)
def test_an_it_or_that_object_or_an_adverb_on_the_left_is_caught(text: str) -> None:
    assert len(_vocab_hits(text)) == 1, voice.scan_text("t", text, fail_on_warn=True)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "We added underscores that were missing.", id="verb-that-relative"
        ),
        pytest.param(
            "The first underscore that appears is kept.", id="ordinal-relative"
        ),
        pytest.param("We allowed underscores that separate words.", id="that-separate"),
        pytest.param("Put a dash before underscores in names.", id="before-noun-prep"),
        pytest.param("The digit after underscore is kept.", id="after-noun-is"),
        pytest.param("The underscore above is a separator.", id="determiner-above"),
        pytest.param("Strip spaces before underscores.", id="before-noun-end"),
    ],
)
def test_the_noun_before_a_relative_clause_or_after_a_preposition_passes(
    text: str,
) -> None:
    assert _vocab_hits(text) == [], voice.scan_text("t", text, fail_on_warn=True)
