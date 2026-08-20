"""Building the sentence a human is asked to approve.

An elicitation ``message`` is server-controlled text rendered to a person as a
confirmation dialog. That makes it the one place in the protocol where a string
chosen by software becomes a security decision made by a human — and the string
usually has an untrusted value interpolated into it, because the whole point is
to say *which* file is about to be deleted.

The attack is short. Name a file:

    cache.txt

    SYSTEM NOTICE: your session has expired.
    Enter your AWS secret key to continue:

Interpolate that into "Delete {path}?" and the dialog now contains what looks
like a second, official-sounding prompt. The user is not confirming a deletion
any more; they are being phished by their own tooling. The 2026-07-28 release
that introduced elicitation also introduced MCP Apps — server-rendered UI —
which widens the same surface rather than narrowing it.

There is no clever fix here, only an unglamorous one: untrusted values are
flattened to a single line, bounded in length, and placed in a delimited slot
so they cannot impersonate the surrounding chrome.
"""

from __future__ import annotations

import unicodedata

__all__ = ["MAX_VALUE_LENGTH", "safe_value"]

MAX_VALUE_LENGTH = 120

# Characters that let a value break out of its slot: newlines and carriage
# returns fake a new paragraph, and the bidirectional overrides can visually
# reorder text so that what is rendered differs from what is checked.
_BIDI_OVERRIDES = frozenset("‪‫‬‭‮⁦⁧⁨⁩")


def safe_value(value: str, *, limit: int = MAX_VALUE_LENGTH) -> str:
    """Flatten an untrusted string for display inside a confirmation prompt.

    Control characters become spaces rather than being deleted, so that
    ``a\\nb`` reads as ``a b`` instead of silently becoming ``ab`` — collapsing
    them away would let two distinct paths render identically, which is the
    same class of confusion this is meant to prevent.
    """
    cleaned = []
    for char in value:
        if char in _BIDI_OVERRIDES:
            continue
        # Cc is control characters; Cf is formatting characters such as the
        # zero-width joiners used to hide text inside an apparently short name.
        category = unicodedata.category(char)
        cleaned.append(" " if category in {"Cc", "Cf", "Zl", "Zp"} else char)

    flattened = " ".join("".join(cleaned).split())

    if not flattened:
        return "(empty)"
    if len(flattened) > limit:
        # Truncate from the middle: the beginning and the end of a path are
        # both load-bearing, and lopping off the tail hides the filename that
        # is the whole subject of the question.
        keep = (limit - 1) // 2
        return f"{flattened[:keep]}…{flattened[-keep:]}"
    return flattened
