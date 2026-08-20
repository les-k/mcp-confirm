"""The gap the SDK leaves: an approval that can be spent more than once.

The Python SDK already protects `requestState` properly, and does it better
than hand-rolled code would. `RequestStateBoundary` — installed by default on
every `MCPServer` — seals the state under AES-256-GCM and binds it to the
method, the target, a digest of the arguments, the audience and the
authenticated principal, with a TTL. A confirmation granted for one call is
refused on any other. None of that needs reimplementing, and this module does
not attempt it.

What the boundary does *not* do is **spend** the state. Within its TTL, the
same approval verifies as many times as it is presented. The specification is
explicit that this is deliberate and that the remainder is the server's job:

    Note that these measures bound the replay window and prevent cross-user
    and cross-request reuse, but do not by themselves guarantee single-use.
    Servers for which a given `requestState` must be consumed at most once
    (e.g., one-time redemptions) MUST enforce that invariant server-side.

For "delete this file" the consequence is mild — the second deletion finds
nothing. For "transfer this money" it is the whole problem. This module is that
invariant, and nothing more.

Because the boundary guarantees a handler only ever sees plaintext the server
itself minted, there is no signature to check here and no crypto in this file.
The nonce needs to be unguessable only so that two concurrent confirmations
cannot collide; its integrity is already someone else's solved problem.
"""

from __future__ import annotations

import secrets

__all__ = ["Rejected", "SingleUseLedger"]


class Rejected(Exception):
    """A confirmation was refused.

    Carries the reason as prose because the immediate caller is a language
    model, and "denied" alone gives it nothing to correct.
    """


class SingleUseLedger:
    """Tracks which confirmations are outstanding, and spends them exactly once.

    Outstanding rather than spent: the ledger records what it issued and
    removes an entry on redemption. One structure then answers both questions
    that matter — "has this already been used?" and "did this process issue it
    at all?" — where a set of *spent* nonces would answer only the first.

    The second question is not hypothetical. The SDK supports sharing signing
    keys across replicas (`RequestStateSecurity(keys=[...])`), and under that
    configuration a state minted by another instance arrives here perfectly
    valid, correctly bound, and unknown to this ledger.

    **This is in-memory, so it is correct for one process and wrong behind a
    load balancer.** Under shared keys, replica B will reject a confirmation
    issued by replica A — failing closed, which is the safe direction, but it
    will read to a user as a confirmation that inexplicably stopped working. A
    multi-process deployment needs a shared store with an atomic
    compare-and-delete: Redis, or a database row. Stated here rather than
    discovered in production.
    """

    def __init__(self, *, ttl_seconds: int = 300) -> None:
        if ttl_seconds <= 0:
            raise Rejected(f"ttl_seconds must be positive, got {ttl_seconds}")
        self._ttl = ttl_seconds
        self._outstanding: dict[str, int] = {}

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def issue(self, *, now: int) -> str:
        """Mint a nonce and record it as outstanding.

        ``now`` is a parameter and never read from a clock in here. A test that
        depends on the second it runs in is a test that starts failing on its
        own.
        """
        self._forget_expired(now=now)
        nonce = f"c-{secrets.token_urlsafe(12)}"
        self._outstanding[nonce] = now + self._ttl
        return nonce

    def spend(self, nonce: str, *, now: int) -> None:
        """Redeem a confirmation exactly once, or refuse.

        The SDK has already established that this nonce is authentic and was
        bound to this exact call. The only remaining question is whether it is
        still unspent.
        """
        if not nonce:
            raise Rejected("no confirmation was supplied")

        self._forget_expired(now=now)

        expires_at = self._outstanding.pop(nonce, None)
        if expires_at is None:
            raise Rejected(
                "this confirmation has already been used, or was issued by a different "
                "server process; ask the user again"
            )
        if now >= expires_at:
            # Belt and braces. _forget_expired should have removed it, and the
            # SDK's own TTL should have rejected it before this code ran at
            # all - but a ledger that trusts two other layers to have done its
            # job is a ledger with a hole in it.
            raise Rejected(f"confirmation expired {now - expires_at}s ago; ask the user again")

    def outstanding(self) -> int:
        """How many confirmations are currently unspent. For tests and metrics."""
        return len(self._outstanding)

    def _forget_expired(self, *, now: int) -> None:
        """Drop entries that can no longer be redeemed anyway.

        Bounded by the TTL rather than by count: an entry is only useful until
        the state it refers to would expire on its own, so retaining it past
        that point grows memory without buying any protection.
        """
        if not self._outstanding:
            return
        dead = [nonce for nonce, expiry in self._outstanding.items() if now >= expiry]
        for nonce in dead:
            del self._outstanding[nonce]
