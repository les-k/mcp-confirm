"""The part that says no.

Everything security-relevant about this server lives here, and none of it
imports MCP. The protocol layer is a thin translation; the rules that decide
whether a confirmation is genuine can be tested directly, without a client, a
transport or an agent in the loop.

Background: the 2026-07-28 MCP specification introduced Multi Round-Trip
Requests. A server that needs confirmation answers ``tools/call`` with an
``InputRequiredResult`` carrying an opaque ``requestState`` string; the client
collects the user's answer and re-issues the call, echoing that state back.

The state therefore makes a round trip *through the client*, and the
specification is blunt about what that means:

    Servers MUST treat ``requestState`` as an attacker-controlled input. If
    ``requestState`` influences authorization, resource access, or business
    logic, servers MUST protect its integrity (e.g. HMAC or AEAD) and MUST
    reject state that fails verification.

and, for replay, that servers SHOULD bind into the protected payload:

    the authenticated principal ... a short expiry (TTL) ... an identifier for
    the originating request, e.g. the method name and a digest of its salient
    parameters, rejecting state presented on a request that does not match.

That last clause is the one that matters most, and it is the reason this module
exists rather than a bare HMAC. A signature alone proves the server issued
*some* approval. It does not prove the approval was for *this* call. Without a
parameter digest, a user who confirms "delete /tmp/cache" hands back a token
that authorises deleting anything at all — the confirmation dialog becomes
theatre, which is worse than having no dialog, because the user believes they
were asked.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

__all__ = ["Claims", "ConfirmationState", "Rejected", "params_digest"]

_VERSION = "v1"
_MIN_SECRET_BYTES = 32


class Rejected(Exception):
    """A confirmation was refused.

    Carries the reason as prose because the immediate caller is a language
    model, and "denied" alone gives it nothing to correct. Every raise site
    states which rule fired.

    The reasons are deliberately specific to the *class* of failure and never
    quote the attacker-supplied value back, so an attacker probing the endpoint
    learns which rule they tripped but not how close they were to a valid
    signature.
    """


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def params_digest(params: dict[str, Any]) -> str:
    """A stable digest of the arguments a confirmation was granted for.

    Canonical JSON — sorted keys, no incidental whitespace — so that two
    dictionaries which mean the same thing hash the same way. Without the
    canonicalisation, ``{"a": 1, "b": 2}`` and ``{"b": 2, "a": 1}`` would
    produce different digests and identical calls would be spuriously refused.
    """
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Claims:
    """What an issued state asserts, once its signature has been verified."""

    principal: str
    method: str
    digest: str
    nonce: str
    issued_at: int
    expires_at: int


class ConfirmationState:
    """Issues and verifies the opaque ``requestState`` blob.

    Single-use is enforced through an in-memory set of spent nonces. That is
    correct for one process and **not** correct behind a load balancer: the
    specification's own warning is that TTL and binding bound the replay window
    without guaranteeing single use, and that servers needing at-most-once
    redemption must enforce it themselves. A multi-process deployment needs a
    shared store here — Redis, a database, anything with a compare-and-set.
    This is stated rather than hidden because an in-memory set that silently
    does nothing across workers is the kind of defect that looks fine in tests
    and fails in production.
    """

    def __init__(self, secret: bytes, *, ttl_seconds: int = 300) -> None:
        if len(secret) < _MIN_SECRET_BYTES:
            # Refused at construction rather than at first use. A server that
            # starts with a weak key and only fails when someone attacks it has
            # already shipped the vulnerability.
            raise Rejected(
                f"signing secret must be at least {_MIN_SECRET_BYTES} bytes, got {len(secret)}"
            )
        if ttl_seconds <= 0:
            raise Rejected(f"ttl_seconds must be positive, got {ttl_seconds}")

        self._secret = secret
        self._ttl = ttl_seconds
        self._spent: dict[str, int] = {}

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    # -- issuing -----------------------------------------------------------

    def issue(self, *, principal: str, method: str, params: dict[str, Any], now: int) -> str:
        """Mint a state blob binding this principal, method and arguments.

        ``now`` is a parameter and never read from the clock in here. A test
        that depends on the second it runs in is a test that starts failing on
        its own.
        """
        if not principal:
            raise Rejected("refusing to issue confirmation state for an empty principal")

        payload = {
            "p": principal,
            "m": method,
            "d": params_digest(params),
            "n": secrets.token_urlsafe(12),
            "iat": now,
            "exp": now + self._ttl,
        }
        body = _b64e(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signed = f"{_VERSION}.{body}"
        signature = hmac.new(self._secret, signed.encode("ascii"), hashlib.sha256).digest()
        return f"{signed}.{_b64e(signature)}"

    # -- verifying ---------------------------------------------------------

    def verify(
        self,
        state: str,
        *,
        principal: str,
        method: str,
        params: dict[str, Any],
        now: int,
        consume: bool = True,
    ) -> Claims:
        """Check a state blob against the call actually being made.

        The order here is deliberate: the signature is checked **before** the
        payload is parsed. Parsing attacker-controlled JSON and then deciding
        whether to trust it inverts the dependency — every parser bug becomes
        reachable by an unauthenticated caller.
        """
        if not state:
            raise Rejected("no confirmation state was supplied")

        parts = state.split(".")
        if len(parts) != 3:
            raise Rejected("confirmation state is malformed")

        version, body, signature = parts
        if version != _VERSION:
            raise Rejected(f"confirmation state version {version!r} is not supported")

        expected = hmac.new(
            self._secret, f"{version}.{body}".encode("ascii"), hashlib.sha256
        ).digest()
        try:
            supplied = _b64d(signature)
        except Exception as exc:  # noqa: BLE001 - any decode failure is a rejection
            raise Rejected("confirmation state signature is not decodable") from exc

        # Constant-time: a byte-by-byte early return leaks how much of a forged
        # signature was correct, which is enough to construct one a byte at a time.
        if not hmac.compare_digest(expected, supplied):
            raise Rejected("confirmation state signature does not verify")

        try:
            payload = json.loads(_b64d(body))
        except Exception as exc:  # noqa: BLE001
            raise Rejected("confirmation state payload is not readable") from exc
        if not isinstance(payload, dict):
            raise Rejected("confirmation state payload is not an object")

        try:
            claims = Claims(
                principal=str(payload["p"]),
                method=str(payload["m"]),
                digest=str(payload["d"]),
                nonce=str(payload["n"]),
                issued_at=int(payload["iat"]),
                expires_at=int(payload["exp"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise Rejected("confirmation state payload is missing required fields") from exc

        if now >= claims.expires_at:
            raise Rejected(
                f"confirmation expired {now - claims.expires_at}s ago; ask the user again"
            )

        if not hmac.compare_digest(claims.principal, principal):
            raise Rejected("confirmation was issued to a different principal")

        if not hmac.compare_digest(claims.method, method):
            raise Rejected(
                f"confirmation was issued for {claims.method!r}, not {method!r}"
            )

        # The clause the whole module exists for. A valid signature proves the
        # server approved something; only this proves it approved *this*.
        if not hmac.compare_digest(claims.digest, params_digest(params)):
            raise Rejected(
                "confirmation was issued for different arguments than the ones now supplied; "
                "the user approved a different call"
            )

        if consume:
            self._consume(claims, now=now)

        return claims

    # -- single use --------------------------------------------------------

    def _consume(self, claims: Claims, *, now: int) -> None:
        self._forget_expired(now=now)
        if claims.nonce in self._spent:
            raise Rejected("this confirmation has already been used")
        self._spent[claims.nonce] = claims.expires_at

    def _forget_expired(self, *, now: int) -> None:
        """Drop spent nonces that can no longer be replayed anyway.

        Bounded by the TTL rather than by count: an entry is only useful until
        the state it refers to would expire on its own, so retaining it past
        that point grows memory without buying any protection.
        """
        if not self._spent:
            return
        dead = [nonce for nonce, expiry in self._spent.items() if now >= expiry]
        for nonce in dead:
            del self._spent[nonce]
