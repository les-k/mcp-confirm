"""The confirmation dialog is text a human reads and acts on.

Which makes the interpolated value a security boundary, not a formatting
detail.
"""

from __future__ import annotations

from mcp_confirm.prompt import MAX_VALUE_LENGTH, safe_value


def test_an_ordinary_path_is_left_alone():
    assert safe_value("/home/alice/cache.txt") == "/home/alice/cache.txt"


def test_a_forged_system_prompt_cannot_escape_its_slot():
    """The attack in one line.

    A filename carrying newlines and official-sounding text turns a deletion
    dialog into a credential prompt. Flattened to one line it is still visible,
    still ugly, and no longer able to impersonate the surrounding chrome.
    """
    hostile = (
        "cache.txt\n\n"
        "SYSTEM NOTICE: your session has expired.\n"
        "Enter your AWS secret key to continue:"
    )
    rendered = safe_value(hostile, limit=200)

    assert "\n" not in rendered
    assert "\r" not in rendered
    # The text is not deleted - hiding it would be its own failure mode. It is
    # merely confined to the single line the template gave it.
    assert "SYSTEM NOTICE" in rendered


def test_control_characters_become_spaces_rather_than_vanishing():
    """Deleting them would let two different paths render identically.

    ``a\\nb`` and ``ab`` are different files; if both displayed as ``ab`` the
    dialog would be lying about which one is going away.
    """
    assert safe_value("a\nb") == "a b"
    assert safe_value("a\tb") == "a b"
    assert safe_value("a\rb") == "a b"


def test_zero_width_characters_are_treated_as_separators():
    """Zero-width joiners hide text inside an apparently short name."""
    rendered = safe_value("cache​.txt")
    assert "​" not in rendered


def test_bidirectional_overrides_are_stripped():
    """These reorder rendered text, so what is shown differs from what is checked."""
    rendered = safe_value("cache‮" + "txt.exe")
    assert "‮" not in rendered


def test_a_long_value_is_truncated_in_the_middle():
    """Both ends of a path matter.

    Lopping off the tail would hide the filename, which is the entire subject
    of the question being asked.
    """
    long_path = "/very/long/directory/" + "x" * 400 + "/thesis.txt"
    rendered = safe_value(long_path)

    assert len(rendered) <= MAX_VALUE_LENGTH
    assert rendered.startswith("/very/long")
    assert rendered.endswith("thesis.txt")
    assert "…" in rendered


def test_an_empty_value_is_named_rather_than_shown_blank():
    """A dialog reading 'Delete this file?  ' with nothing in it is unanswerable."""
    assert safe_value("") == "(empty)"
    assert safe_value("   \n\t  ") == "(empty)"
