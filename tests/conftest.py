"""A harness that runs calls through the SDK's real request-state boundary.

The first version of this repository tested by calling `MCPServer.call_tool()`
directly. That path goes straight to the tool manager and **bypasses the
middleware chain entirely**, so the SDK's `RequestStateBoundary` never ran. The
consequence was not a flaky test: it hid the fact that the SDK already provided
the protection this project had hand-rolled, for an entire build cycle.

So the harness here drives the genuine `RequestStateBoundary` — the same class
`MCPServer` installs on itself — with a pinned key, sealing round one's output
and unsealing round two's input exactly as the wire would. Tests can then
distinguish *which layer* refuses a given attack, which is the whole point of
the rebuilt project.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any

import pytest
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.request_state import RequestStateBoundary, RequestStateSecurity
from mcp.types import ElicitResult, InputResponseRequestParams

AUDIENCE = "mcp-confirm"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """An allowed root holding two files: one junk, one that matters."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "cache.txt").write_text("regenerable junk", encoding="utf-8")
    (root / "thesis.txt").write_text("years of work", encoding="utf-8")
    return root


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    other = tmp_path / "not-yours"
    other.mkdir()
    (other / "secrets.txt").write_text("not for you", encoding="utf-8")
    return other


class Wire:
    """Drives a tool call the way a real client and the real middleware would.

    `round_one` returns the **sealed** state, as it would appear on the wire.
    `round_two` unseals it through the boundary first, so a state presented on
    the wrong call is refused by the SDK exactly as it would be in production.
    """

    def __init__(self, server: MCPServer, *, key: bytes | None = None) -> None:
        self.server = server
        self.boundary = RequestStateBoundary(
            RequestStateSecurity(
                keys=[key or os.urandom(32)],
                ttl=600.0,
                # No authenticated principal exists over stdio; binding to one
                # would make every token principal-drift-reject in these tests.
                bind_principal=None,
            ),
            default_audience=AUDIENCE,
        )

    def _ctx(
        self, args: dict[str, Any], state: str | None = None
    ) -> ServerRequestContext[Any, Any]:
        params: dict[str, Any] = {"name": "delete_file", "arguments": args}
        if state is not None:
            params["requestState"] = state
        return ServerRequestContext(
            session=None,  # type: ignore[arg-type]  # unused here
            lifespan_context=None,
            protocol_version="2026-07-28",
            method="tools/call",
            params=params,
        )

    async def round_one(self, path: Path | str) -> str:
        """Ask. Returns the sealed request state, as the client would receive it."""
        args = {"path": str(path)}

        async def handler(_ctx: Any) -> Any:
            result = await self.server.call_tool("delete_file", args, Context())
            return {
                "resultType": "input_required",
                "requestState": result.request_state,
                "inputRequests": result.input_requests,
            }

        sealed = await self.boundary(self._ctx(args), handler)
        return sealed["requestState"]  # type: ignore[index]

    async def round_one_result(self, path: Path | str) -> Any:
        """Round one without sealing, for asserting on the question itself."""
        return await self.server.call_tool("delete_file", {"path": str(path)}, Context())

    async def round_two(
        self,
        path: Path | str,
        sealed: str | None,
        *,
        action: str = "accept",
        confirmed: bool = True,
    ) -> Any:
        """Answer. The boundary unseals first; an MCPError here is the SDK refusing."""
        args = {"path": str(path)}

        async def handler(ctx: Any) -> Any:
            plaintext = ctx.params.get("requestState")
            context = Context(
                input_params=InputResponseRequestParams(
                    input_responses={
                        "confirm": ElicitResult(
                            action=action,  # type: ignore[arg-type]
                            content={"confirmed": confirmed} if action == "accept" else None,
                        )
                    },
                    request_state=plaintext,
                )
            )
            return await self.server.call_tool("delete_file", args, context)

        return await self.boundary(self._ctx(args, sealed), handler)


def text_of(result: Any) -> str:
    return result.content[0].text if getattr(result, "content", None) else str(result)


def can_symlink(tmp_path: Path) -> bool:
    """Whether this process may create symlinks.

    On Windows this needs developer mode or admin, and a sandbox often has
    neither. Tests that need one skip rather than silently passing, because a
    symlink test that quietly does nothing is worse than no symlink test.
    """
    probe = tmp_path / "_probe"
    target = tmp_path / "_probe_target"
    target.mkdir(exist_ok=True)
    try:
        os.symlink(target, probe, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        if probe.is_symlink() or probe.exists():
            with contextlib.suppress(OSError):
                probe.unlink()
    return True


@pytest.fixture
def symlinks_allowed(tmp_path: Path) -> bool:
    return can_symlink(tmp_path)
