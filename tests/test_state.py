"""Attacks against the confirmation state, run directly against the guard.

These need no MCP client, no transport and no agent, because ``state.py``
imports none of those. Every rule the specification states as a MUST or SHOULD
has a test here that makes it fire.
"""

from __future__ import annotations

import secrets

import pytest

from mcp_confirm.state import ConfirmationState, Rejected, params_digest

NOW = 1_760_000_000
PARAMS = {"path": "/tmp/cache.txt"}


@pytest.fixture
def states(secret: bytes) -> ConfirmationState:
    return ConfirmationState(secret, ttl_seconds=300)


def issue(states: ConfirmationState, **overrides) -> str:
    kwargs = {"principal": "alice", "method": "delete_file", "params": PARAMS, "now": NOW}
    kwargs.update(overrides)
    return states.issue(**kwargs)


def verify(states: ConfirmationState, state: str, **overrides):
    kwargs = {
        "principal": "alice",
        "method": "delete_file",
        "params": PARAMS,
        "now": NOW + 1,
    }
    kwargs.update(overrides)
    return states.verify(state, **kwargs)


# -- the happy path ------------------------------------------------------


def test_a_freshly_issued_state_verifies(states: ConfirmationState):
    claims = verify(states, issue(states))
    assert claims.principal == "alice"
    assert claims.method == "delete_file"
    assert claims.digest == params_digest(PARAMS)


def test_argument_key_order_does_not_matter(states: ConfirmationState):
    """Canonical JSON, so two equal dicts hash equal however they were built."""
    state = issue(states, params={"a": 1, "b": 2})
    claims = verify(states, state, params={"b": 2, "a": 1})
    assert claims.digest == params_digest({"a": 1, "b": 2})


# -- the attack this module exists for -----------------------------------


def test_a_confirmation_for_one_file_is_refused_for_another(states: ConfirmationState):
    """Confirm A, execute B.

    The user was asked about cache.txt and said yes. That approval is then
    presented against thesis.txt. A server checking only the signature would
    see a genuine token it issued moments ago and proceed.

    This is the specification's own SHOULD: bind "an identifier for the
    originating request, e.g. the method name and a digest of its salient
    parameters, rejecting state presented on a request that does not match".
    """
    approved = issue(states, params={"path": "/tmp/cache.txt"})

    with pytest.raises(Rejected, match="different arguments"):
        verify(states, approved, params={"path": "/home/alice/thesis.txt"})


def test_the_signature_alone_would_have_accepted_that_call(states: ConfirmationState):
    """The counterfactual, made explicit.

    The token in the previous test is not forged - it is a real, correctly
    signed state this server issued. Verifying it against the arguments it was
    actually granted for succeeds. Only the parameter binding separates the two
    outcomes, which is why a bare HMAC is not enough.
    """
    approved = issue(states, params={"path": "/tmp/cache.txt"})
    claims = verify(states, approved, params={"path": "/tmp/cache.txt"})
    assert claims.digest == params_digest({"path": "/tmp/cache.txt"})


# -- integrity -----------------------------------------------------------


def test_a_tampered_payload_is_refused(states: ConfirmationState):
    version, body, signature = issue(states).split(".")
    forged = f"{version}.{body[:-4]}AAAA.{signature}"
    with pytest.raises(Rejected, match="signature does not verify|not readable"):
        verify(states, forged)


def test_a_tampered_signature_is_refused(states: ConfirmationState):
    version, body, signature = issue(states).split(".")
    with pytest.raises(Rejected, match="signature does not verify"):
        verify(states, f"{version}.{body}.{signature[:-4]}AAAA")


def test_a_state_signed_with_a_different_key_is_refused(secret: bytes):
    """Key rotation, or another tenant's signing key."""
    issuer = ConfirmationState(secret, ttl_seconds=300)
    verifier = ConfirmationState(secrets.token_bytes(32), ttl_seconds=300)
    with pytest.raises(Rejected, match="signature does not verify"):
        verify(verifier, issue(issuer))


def test_the_sdk_documentation_example_string_is_refused(states: ConfirmationState):
    """A constant, unsigned state.

    The Python SDK's own multi-round-trip example passes
    ``request_state="delete-v1"``. That is harmless in a snippet whose state
    carries no meaning, and the specification permits omitting integrity
    protection exactly then - but it is the shape people copy, and it stops
    being harmless the moment the blob encodes anything a decision depends on.
    """
    with pytest.raises(Rejected, match="malformed"):
        verify(states, "delete-v1")


@pytest.mark.parametrize(
    "state",
    ["", "a.b", "a.b.c.d", "v9.abc.def", "v1..", "v1.!!!.???"],
    ids=["empty", "too-few-parts", "too-many-parts", "bad-version", "empty-parts", "bad-base64"],
)
def test_malformed_states_are_refused_without_crashing(states: ConfirmationState, state: str):
    with pytest.raises(Rejected):
        verify(states, state)


# -- binding -------------------------------------------------------------


def test_another_principal_cannot_present_your_confirmation(states: ConfirmationState):
    with pytest.raises(Rejected, match="different principal"):
        verify(states, issue(states, principal="alice"), principal="bob")


def test_a_confirmation_for_one_method_is_refused_for_another(states: ConfirmationState):
    with pytest.raises(Rejected, match="issued for 'delete_file'"):
        verify(states, issue(states), method="send_email")


def test_an_empty_principal_is_refused_at_issue(states: ConfirmationState):
    with pytest.raises(Rejected, match="empty principal"):
        issue(states, principal="")


# -- expiry --------------------------------------------------------------


def test_an_expired_confirmation_is_refused(states: ConfirmationState):
    with pytest.raises(Rejected, match="expired"):
        verify(states, issue(states), now=NOW + 301)


def test_expiry_is_exclusive_at_the_boundary(states: ConfirmationState):
    """At exactly expires_at the state is already dead.

    Chosen deliberately rather than by accident: a confirmation valid for one
    final instant is a race, and the safe side of a boundary in a security
    check is the strict one.
    """
    verify(states, issue(states), now=NOW + 299)  # still good
    with pytest.raises(Rejected, match="expired"):
        verify(states, issue(states), now=NOW + 300)


# -- single use ----------------------------------------------------------


def test_a_confirmation_cannot_be_used_twice(states: ConfirmationState):
    state = issue(states)
    verify(states, state)
    with pytest.raises(Rejected, match="already been used"):
        verify(states, state)


def test_verification_can_be_rehearsed_without_spending_it(states: ConfirmationState):
    state = issue(states)
    verify(states, state, consume=False)
    verify(states, state, consume=False)
    verify(states, state)  # still spendable exactly once
    with pytest.raises(Rejected, match="already been used"):
        verify(states, state)


def test_spent_nonces_do_not_accumulate_forever(states: ConfirmationState):
    """Retention is bounded by the TTL, not by count.

    A spent nonce only needs remembering until the state it refers to would
    have expired anyway; keeping it longer grows memory without buying any
    protection.
    """
    for index in range(5):
        params = {"path": f"/tmp/{index}"}
        verify(states, issue(states, params=params), params=params)
    assert len(states._spent) == 5

    # One verification well past every expiry sweeps the rest.
    late = issue(states, now=NOW + 1000)
    verify(states, late, now=NOW + 1001)
    assert len(states._spent) == 1


# -- construction --------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 16, 31])
def test_a_weak_signing_secret_is_refused_at_construction(size: int):
    """Fail at startup, not at first attack."""
    with pytest.raises(Rejected, match="at least 32 bytes"):
        ConfirmationState(b"x" * size)


@pytest.mark.parametrize("ttl", [0, -1, -300])
def test_a_non_positive_ttl_is_refused(secret: bytes, ttl: int):
    with pytest.raises(Rejected, match="ttl_seconds must be positive"):
        ConfirmationState(secret, ttl_seconds=ttl)
