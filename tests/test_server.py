"""The same attacks, driven through a real ``tools/call`` rather than the guard.

A guard that refuses correctly in isolation is worth nothing if the server
forgets to consult it, or consults it with the wrong arguments. These tests go
through ``MCPServer.call_tool`` with the protocol's own ``Context`` and
``ElicitResult`` types, so a wiring mistake fails here even when every unit
test still passes.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import InputRequiredResult

from conftest import first_round, retry
from mcp_confirm import build_server

NOW = 1_760_000_000


def make_server(workspace: Path, secret: bytes, *, now: int = NOW, ttl: int = 300):
    clock = {"t": now}
    server = build_server([workspace], secret=secret, ttl_seconds=ttl, clock=lambda: clock["t"])
    return server, clock


async def ask(server, path: Path) -> InputRequiredResult:
    """Round one: get a confirmation request and its state."""
    result = await server.call_tool("delete_file", {"path": str(path)}, first_round())
    assert isinstance(result, InputRequiredResult)
    return result


def text_of(result) -> str:
    return result.content[0].text if getattr(result, "content", None) else str(result)


# -- the flow ------------------------------------------------------------


async def test_round_one_asks_and_touches_nothing(workspace: Path, secret: bytes):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    result = await ask(server, cache)

    assert result.request_state
    assert list(result.input_requests) == ["confirm"]
    assert "delete" in result.input_requests["confirm"].params.message.lower()
    assert cache.exists(), "round one must not delete anything"


async def test_an_accepted_confirmation_deletes_the_file(workspace: Path, secret: bytes):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    asked = await ask(server, cache)
    result = await server.call_tool(
        "delete_file", {"path": str(cache)}, retry(asked.request_state)
    )

    assert "Deleted" in text_of(result)
    assert not cache.exists()


@pytest.mark.parametrize(
    ("action", "confirmed"),
    [("decline", False), ("cancel", False), ("accept", False)],
    ids=["declined", "cancelled", "accepted-but-unchecked"],
)
async def test_anything_short_of_a_yes_deletes_nothing(
    workspace: Path, secret: bytes, action: str, confirmed: bool
):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    asked = await ask(server, cache)
    result = await server.call_tool(
        "delete_file",
        {"path": str(cache)},
        retry(asked.request_state, action=action, confirmed=confirmed),
    )

    assert "Cancelled" in text_of(result)
    assert cache.exists()


# -- the attack --------------------------------------------------------


async def test_a_confirmation_for_one_file_cannot_delete_another(
    workspace: Path, secret: bytes
):
    """Confirm A, execute B, end to end.

    The user is shown cache.txt and approves it. The approval - a genuine,
    correctly signed state this server issued seconds earlier - is then
    presented against thesis.txt.
    """
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"
    thesis = workspace / "thesis.txt"

    asked = await ask(server, cache)
    assert "cache.txt" in asked.input_requests["confirm"].params.message

    with pytest.raises(ToolError, match="different arguments"):
        await server.call_tool(
            "delete_file", {"path": str(thesis)}, retry(asked.request_state)
        )

    assert thesis.exists(), "the file the user never approved must survive"
    assert thesis.read_text(encoding="utf-8") == "years of work"


async def test_the_same_confirmation_works_for_the_file_it_named(
    workspace: Path, secret: bytes
):
    """The control for the previous test: that state is valid, just not for thesis.txt."""
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    asked = await ask(server, cache)
    result = await server.call_tool(
        "delete_file", {"path": str(cache)}, retry(asked.request_state)
    )

    assert "Deleted" in text_of(result)


async def test_a_confirmation_cannot_be_replayed(workspace: Path, secret: bytes):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    asked = await ask(server, cache)
    await server.call_tool("delete_file", {"path": str(cache)}, retry(asked.request_state))
    cache.write_text("recreated", encoding="utf-8")

    with pytest.raises(ToolError, match="already been used"):
        await server.call_tool(
            "delete_file", {"path": str(cache)}, retry(asked.request_state)
        )

    assert cache.exists()


async def test_a_confirmation_expires(workspace: Path, secret: bytes):
    server, clock = make_server(workspace, secret, ttl=60)
    cache = workspace / "cache.txt"

    asked = await ask(server, cache)
    clock["t"] += 61

    with pytest.raises(ToolError, match="expired"):
        await server.call_tool(
            "delete_file", {"path": str(cache)}, retry(asked.request_state)
        )

    assert cache.exists()


async def test_a_forged_state_is_refused(workspace: Path, secret: bytes):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    other = build_server(
        [workspace], secret=secrets.token_bytes(32), clock=lambda: NOW
    )
    stolen = await ask(other, cache)

    with pytest.raises(ToolError, match="signature does not verify"):
        await server.call_tool(
            "delete_file", {"path": str(cache)}, retry(stolen.request_state)
        )

    assert cache.exists()


async def test_a_retry_with_no_state_at_all_is_refused(workspace: Path, secret: bytes):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"
    await ask(server, cache)

    with pytest.raises(ToolError, match="no confirmation state"):
        await server.call_tool("delete_file", {"path": str(cache)}, retry(None))

    assert cache.exists()


# -- containment -------------------------------------------------------


async def test_a_path_outside_the_roots_is_refused_before_asking(
    workspace: Path, outside: Path, secret: bytes
):
    """Refused in round one: the user is never even shown the question."""
    server, _ = make_server(workspace, secret)
    victim = outside / "secrets.txt"

    with pytest.raises(ToolError, match="outside the allowed roots"):
        await server.call_tool("delete_file", {"path": str(victim)}, first_round())

    assert victim.exists()


async def test_traversal_out_of_a_root_is_refused(
    workspace: Path, outside: Path, secret: bytes
):
    server, _ = make_server(workspace, secret)
    traversal = str(workspace / ".." / "not-yours" / "secrets.txt")

    with pytest.raises(ToolError, match="outside the allowed roots"):
        await server.call_tool("delete_file", {"path": traversal}, first_round())

    assert (outside / "secrets.txt").exists()


async def test_a_directory_is_refused(workspace: Path, secret: bytes):
    server, _ = make_server(workspace, secret)
    with pytest.raises(ToolError, match="is a directory"):
        await server.call_tool("delete_file", {"path": str(workspace)}, first_round())


# -- the gap between asking and acting ---------------------------------


async def test_a_file_swapped_for_a_link_after_confirmation_is_refused(
    workspace: Path, outside: Path, secret: bytes, symlinks_allowed: bool
):
    """The window the re-check exists for.

    The user is asked about a real file and says yes. While they were thinking,
    that file is replaced by a link pointing somewhere that matters. A server
    trusting what was true when it asked would follow the link.
    """
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")

    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"
    treasure = outside / "secrets.txt"

    asked = await ask(server, cache)

    cache.unlink()
    os.symlink(treasure, cache)

    with pytest.raises(ToolError, match="is a link"):
        await server.call_tool(
            "delete_file", {"path": str(cache)}, retry(asked.request_state)
        )

    assert treasure.exists(), "the guard must not have followed the link"
    assert treasure.read_text(encoding="utf-8") == "not for you"


async def test_a_swap_aimed_inside_the_root_is_refused(
    workspace: Path, secret: bytes, symlinks_allowed: bool
):
    """The swap the previous test does not actually exercise.

    That one aims its replacement link *outside* the allowed root, where
    containment refuses it during path resolution before the link check is ever
    consulted - the right outcome, reached by luck, because resolve() happened
    to land somewhere already forbidden.

    Here the link points at a second real file that is legitimately inside the
    same root. Containment resolves it, finds the destination in-bounds, and
    hands back that resolved path - so a link check running afterwards would
    inspect the destination, see an ordinary file, and approve deleting the
    file the user never agreed to.

    CI caught exactly this on the first push. It is the reason _refuse_if_link
    runs on the unresolved path before containment.
    """
    if not symlinks_allowed:
        pytest.skip("this process cannot create symlinks")

    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"
    thesis = workspace / "thesis.txt"

    asked = await ask(server, cache)

    cache.unlink()
    os.symlink(thesis, cache)

    with pytest.raises(ToolError, match="is a link"):
        await server.call_tool(
            "delete_file", {"path": str(cache)}, retry(asked.request_state)
        )

    assert thesis.exists(), "the guard must not have deleted the file it was swapped for"
    assert thesis.read_text(encoding="utf-8") == "years of work"


async def test_a_file_deleted_between_rounds_is_reported_not_crashed(
    workspace: Path, secret: bytes
):
    server, _ = make_server(workspace, secret)
    cache = workspace / "cache.txt"

    asked = await ask(server, cache)
    cache.unlink()

    with pytest.raises(ToolError, match="no longer exists"):
        await server.call_tool(
            "delete_file", {"path": str(cache)}, retry(asked.request_state)
        )
