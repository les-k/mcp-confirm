"""Every test runs through the SDK's real request-state boundary.

Each one names which layer refuses the attack, because that distinction is the
entire content of this project. `MCPError` means the SDK's boundary refused
before this code ran; `ToolError` means the handler here did.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import InputRequiredResult

from conftest import Wire, text_of
from mcp_confirm import build_server

NOW = 1_760_000_000


def make(workspace: Path, *, now: int = NOW, ttl: int = 300):
    clock = {"t": now}
    server = build_server([workspace], ttl_seconds=ttl, clock=lambda: clock["t"])
    return Wire(server), clock


# -- the flow ------------------------------------------------------------


async def test_round_one_asks_and_touches_nothing(workspace: Path):
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"

    result = await wire.round_one_result(cache)

    assert isinstance(result, InputRequiredResult)
    assert result.request_state
    assert list(result.input_requests) == ["confirm"]
    assert "cache.txt" in result.input_requests["confirm"].params.message
    assert cache.exists(), "round one must not delete anything"


async def test_the_state_is_sealed_on_the_wire(workspace: Path):
    """What the client sees is the SDK's envelope, not our nonce.

    Asserted so that a change removing the boundary would fail loudly here
    rather than silently downgrading every other test in this file.
    """
    wire, _ = make(workspace)

    plain = (await wire.round_one_result(workspace / "cache.txt")).request_state
    sealed = await wire.round_one(workspace / "cache.txt")

    assert sealed.startswith("v1.")
    assert plain not in sealed, "the inner nonce must not be readable on the wire"


async def test_an_accepted_confirmation_deletes_the_file(workspace: Path):
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"

    sealed = await wire.round_one(cache)
    result = await wire.round_two(cache, sealed)

    assert "Deleted" in text_of(result)
    assert not cache.exists()


@pytest.mark.parametrize(
    ("action", "confirmed"),
    [("decline", False), ("cancel", False), ("accept", False)],
    ids=["declined", "cancelled", "accepted-but-unchecked"],
)
async def test_anything_short_of_a_yes_deletes_nothing(
    workspace: Path, action: str, confirmed: bool
):
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"

    sealed = await wire.round_one(cache)
    result = await wire.round_two(cache, sealed, action=action, confirmed=confirmed)

    assert "Cancelled" in text_of(result)
    assert cache.exists()


# -- what the SDK already covers ----------------------------------------


async def test_the_sdk_refuses_a_confirmation_replayed_onto_another_file(workspace: Path):
    """Confirm A, execute B — refused by the SDK, not by this project.

    Asserted here deliberately. This repository originally hand-rolled a guard
    for exactly this and shipped it as the headline feature; the SDK's
    `RequestStateBoundary` binds a digest of the call's arguments into the
    sealed envelope and had been doing it all along.

    Keeping the test documents that behaviour and would catch a regression in
    it — but the refusal is `MCPError`, from the middleware, and no code in
    this package participates.
    """
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"
    thesis = workspace / "thesis.txt"

    sealed = await wire.round_one(cache)

    with pytest.raises(MCPError, match="Invalid or expired requestState"):
        await wire.round_two(thesis, sealed)

    assert thesis.exists(), "the file the user never approved must survive"
    assert thesis.read_text(encoding="utf-8") == "years of work"


async def test_the_sdk_refuses_a_forged_state(workspace: Path):
    """A state sealed under a different key. Also the boundary's work, not ours."""
    wire, _ = make(workspace)
    other, _ = make(workspace)  # different random key
    cache = workspace / "cache.txt"

    stolen = await other.round_one(cache)

    with pytest.raises(MCPError, match="Invalid or expired requestState"):
        await wire.round_two(cache, stolen)

    assert cache.exists()


# -- the gap this project exists to close --------------------------------


async def test_a_confirmation_cannot_be_spent_twice(workspace: Path):
    """The SDK binds and expires; it does not consume.

    Presenting the same sealed state a second time, on the same call, inside
    its TTL, passes every check the boundary makes. Only the ledger here stops
    it — note the `ToolError`, meaning this package refused rather than the
    middleware.

    For "delete a file" the second attempt finds nothing anyway. For a tool
    that moves money it is the entire problem, and the specification says
    plainly that at-most-once redemption is the server's job.
    """
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"

    sealed = await wire.round_one(cache)
    await wire.round_two(cache, sealed)
    cache.write_text("recreated", encoding="utf-8")

    with pytest.raises(ToolError, match="already been used"):
        await wire.round_two(cache, sealed)

    assert cache.exists(), "the replayed approval must not delete the recreated file"


async def test_a_state_this_process_never_issued_is_refused(workspace: Path):
    """Correctly sealed, correctly bound, unknown to the ledger.

    Not hypothetical: the SDK supports sharing signing keys across replicas, so
    under `RequestStateSecurity(keys=[...])` a state minted by another instance
    arrives here perfectly valid. The ledger is per-process, so it fails
    closed — the safe direction, and the reason the limitation is documented
    rather than buried.
    """
    key = os.urandom(32)
    minting = Wire(build_server([workspace], clock=lambda: NOW), key=key)
    redeeming = Wire(build_server([workspace], clock=lambda: NOW), key=key)

    cache = workspace / "cache.txt"
    sealed = await minting.round_one(cache)

    with pytest.raises(ToolError, match="already been used, or was issued by a different"):
        await redeeming.round_two(cache, sealed)

    assert cache.exists()


async def test_a_retry_with_no_state_at_all_is_refused(workspace: Path):
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"
    await wire.round_one(cache)

    with pytest.raises(ToolError, match="no confirmation was supplied"):
        await wire.round_two(cache, None)

    assert cache.exists()


# -- containment ---------------------------------------------------------


async def test_a_path_outside_the_roots_is_refused_before_asking(
    workspace: Path, outside: Path
):
    """Refused in round one: the user is never shown the question."""
    wire, _ = make(workspace)
    victim = outside / "secrets.txt"

    with pytest.raises(ToolError, match="outside the allowed roots"):
        await wire.round_one_result(victim)

    assert victim.exists()


async def test_traversal_out_of_a_root_is_refused(workspace: Path, outside: Path):
    wire, _ = make(workspace)
    traversal = workspace / ".." / "not-yours" / "secrets.txt"

    with pytest.raises(ToolError, match="outside the allowed roots"):
        await wire.round_one_result(traversal)

    assert (outside / "secrets.txt").exists()


async def test_a_directory_is_refused(workspace: Path):
    wire, _ = make(workspace)
    with pytest.raises(ToolError, match="is a directory"):
        await wire.round_one_result(workspace)


# -- the gap between asking and acting -----------------------------------


async def test_a_file_swapped_for_a_link_after_confirmation_is_refused(
    workspace: Path, outside: Path, symlinks_allowed: bool
):
    """The window the re-check exists for, aimed outside the root."""
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")

    wire, _ = make(workspace)
    cache = workspace / "cache.txt"
    treasure = outside / "secrets.txt"

    sealed = await wire.round_one(cache)

    cache.unlink()
    os.symlink(treasure, cache)

    with pytest.raises(ToolError, match="is a link"):
        await wire.round_two(cache, sealed)

    assert treasure.exists(), "the guard must not have followed the link"
    assert treasure.read_text(encoding="utf-8") == "not for you"


async def test_a_swap_aimed_inside_the_root_is_refused(
    workspace: Path, symlinks_allowed: bool
):
    """The variant the outside-the-root test does not exercise.

    That one is caught by containment during path resolution, before the link
    check is consulted — the right outcome, reached by luck. Aimed at another
    real file *inside* the root, containment resolves it, finds the destination
    in-bounds, and hands back that resolved path. A link check running
    afterwards would see an ordinary file and approve deleting something the
    user never agreed to.

    CI caught precisely this on the first version of this repository.
    """
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")

    wire, _ = make(workspace)
    cache = workspace / "cache.txt"
    thesis = workspace / "thesis.txt"

    sealed = await wire.round_one(cache)

    cache.unlink()
    os.symlink(thesis, cache)

    with pytest.raises(ToolError, match="is a link"):
        await wire.round_two(cache, sealed)

    assert thesis.exists(), "the guard must not have deleted the file it was swapped for"
    assert thesis.read_text(encoding="utf-8") == "years of work"


async def test_a_file_deleted_between_rounds_is_reported_not_crashed(workspace: Path):
    wire, _ = make(workspace)
    cache = workspace / "cache.txt"

    sealed = await wire.round_one(cache)
    cache.unlink()

    with pytest.raises(ToolError, match="no longer exists"):
        await wire.round_two(cache, sealed)
