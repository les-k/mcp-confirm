"""The protocol layer: a thin translation over ``state`` and ``prompt``.

The demonstration tool deletes a file. It was chosen because deletion is
irreversible, which is the only category of action where a confirmation dialog
is load-bearing rather than decorative — if getting it wrong merely meant an
error message, none of the machinery in ``state.py`` would be worth writing.

The full round trip:

1. ``delete_file(path)`` arrives with no input responses. The server checks the
   path is inside an allowed root, builds a sanitised question, mints a state
   blob bound to *this* principal, *this* method and *these* arguments, and
   answers ``InputRequiredResult``.
2. The client shows the question, collects an answer, and re-issues the call
   with ``inputResponses`` and the echoed ``requestState``.
3. The server verifies the state against the arguments of *the retry*, checks
   the user actually accepted, re-checks the file on disk, and only then
   deletes.

Step 3 verifies against the retry's arguments rather than remembering the
first call's. That is the entire point: the server keeps no memory between
rounds, so the only thing tying the approval to the action is the digest
sealed inside the state.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import (
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
    ToolAnnotations,
)

from .prompt import safe_value
from .state import ConfirmationState, Rejected

__all__ = ["build_server", "main"]

DEFAULT_TTL_SECONDS = 300
_CONFIRM_KEY = "confirm"
_METHOD = "delete_file"

_CONFIRM_SCHEMA = {
    "type": "object",
    "properties": {
        "confirmed": {
            "type": "boolean",
            "description": "True to delete the file, false to cancel.",
        }
    },
    "required": ["confirmed"],
}


def _resolve_roots(roots: Sequence[Path | str]) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for root in roots:
        path = Path(root).expanduser()
        if path.is_symlink():
            raise Rejected(f"root is a link, refusing to use it as an allowlist entry: {path}")
        path = path.resolve(strict=False)
        if not path.is_dir():
            raise Rejected(f"root does not exist or is not a directory: {path}")
        resolved.append(path)
    return tuple(resolved)


def _contain(path: str, roots: tuple[Path, ...]) -> Path:
    """Resolve a path and confirm it sits inside an allowed root."""
    if not roots:
        raise Rejected(
            "no roots are configured, so every path is outside the allowlist; "
            "start the server with at least one --root"
        )
    candidate = Path(path).expanduser().resolve(strict=False)
    for root in roots:
        if candidate == root or candidate.is_relative_to(root):
            return candidate
    allowed = ", ".join(str(root) for root in roots)
    raise Rejected(f"{candidate} is outside the allowed roots ({allowed})")


def _principal(ctx: Context) -> str:
    """Best available identity for the caller.

    Over stdio there is no authenticated principal at all, so this collapses to
    a constant and the principal binding in ``state`` becomes vestigial. That
    is stated plainly rather than papered over: the binding is meaningful for
    an HTTP deployment carrying a verified token, and is dead weight for a
    local single-user process. The code path stays identical either way so the
    HTTP case is not an untested afterthought.
    """
    try:
        request = ctx.request_context
    except (ValueError, AttributeError):
        # `request_context` raises rather than returning None when there is no
        # active request, so this cannot be a getattr default.
        return "local-stdio"

    for attribute in ("user", "principal", "client_id"):
        value = getattr(request, attribute, None)
        if isinstance(value, str) and value:
            return value
    return "local-stdio"


def build_server(
    roots: Sequence[Path | str],
    *,
    secret: bytes,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> MCPServer:
    """Wire the tool up. ``clock`` is injected so expiry is testable."""
    allowed = _resolve_roots(roots)
    states = ConfirmationState(secret, ttl_seconds=ttl_seconds)

    server = MCPServer(
        name="mcp-confirm",
        instructions=(
            "Deletes a file, but only after the user has confirmed that exact "
            "deletion. Confirmations are cryptographically bound to the path "
            "they were granted for, so an approval for one file cannot be "
            "replayed against another."
        ),
    )

    @server.tool(
        name=_METHOD,
        description=(
            "Delete a single file inside the server's configured roots. Asks the "
            "user to confirm first and will not proceed without that answer. The "
            "confirmation is bound to this exact path: it cannot be reused for a "
            "different file, by a different caller, or after it expires."
        ),
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    async def delete_file(path: str, ctx: Context) -> str:
        now = clock()
        principal = _principal(ctx)
        params = {"path": path}

        target = _contain(path, allowed)

        responses = ctx.input_responses or {}
        answer = responses.get(_CONFIRM_KEY)

        if answer is None:
            # Round one. Nothing is touched; we only ask.
            if not target.exists():
                raise Rejected(f"{target} does not exist")
            if target.is_dir():
                raise Rejected(f"{target} is a directory; this tool deletes single files")

            question = (
                f"Permanently delete this file?\n\n"
                f"    {safe_value(str(target))}\n\n"
                f"This cannot be undone."
            )
            return InputRequiredResult(  # type: ignore[return-value]
                input_requests={
                    _CONFIRM_KEY: ElicitRequest(
                        method="elicitation/create",
                        params=ElicitRequestFormParams(
                            mode="form",
                            message=question,
                            requested_schema=_CONFIRM_SCHEMA,
                        ),
                    )
                },
                request_state=states.issue(
                    principal=principal, method=_METHOD, params=params, now=now
                ),
            )

        # Round two. Verify the approval before believing any of it.
        if not isinstance(answer, ElicitResult):
            raise Rejected("confirmation response was not an elicitation result")

        # Deliberately verified against the arguments of *this* call, not the
        # ones the first round happened to carry.
        states.verify(
            ctx.request_state or "",
            principal=principal,
            method=_METHOD,
            params=params,
            now=now,
        )

        if answer.action != "accept":
            return f"Cancelled: the user answered {answer.action!r}. Nothing was deleted."
        if not (answer.content or {}).get("confirmed"):
            return "Cancelled: the user did not confirm. Nothing was deleted."

        # Re-check the filesystem now, rather than trusting what was true when
        # the question was asked. The user thought about it in between, and
        # anything could have replaced the target in that window.
        if target.is_symlink():
            raise Rejected(f"{target} is now a link; it was a regular file when confirmed")
        if not target.exists():
            raise Rejected(f"{target} no longer exists")
        if not target.is_file():
            raise Rejected(f"{target} is no longer a regular file")

        # The filesystem can still refuse after every check has passed: the file
        # may be read-only, held open by another process, or on a mount that
        # went away. Reported as a refusal with the operating system's reason
        # attached, rather than allowed to surface as a bare OSError - the
        # caller is a language model deciding what to do next, and "permission
        # denied" is actionable where a traceback is not.
        try:
            size = target.stat().st_size
            target.unlink()
        except OSError as exc:
            raise Rejected(f"the filesystem refused to delete {target}: {exc}") from exc

        return f"Deleted {target} ({size} bytes)."

    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-confirm",
        description="MCP server demonstrating a confirmation that cannot be replayed.",
    )
    parser.add_argument(
        "--root",
        dest="roots",
        action="append",
        metavar="DIR",
        help=(
            "A directory the server is allowed to delete inside. Repeatable. "
            "Required: with no roots the server refuses every request."
        ),
    )
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    args = parser.parse_args(argv)

    if not args.roots:
        parser.error("at least one --root is required; this server will not default to /")

    # A per-process random secret. Confirmations therefore do not survive a
    # restart, which is the safe default: a state blob minted by a previous
    # process refers to a decision this one never witnessed. Set
    # MCP_CONFIRM_SECRET to share signing across replicas, and read the note in
    # state.ConfirmationState about single-use enforcement before doing so.
    env_secret = os.environ.get("MCP_CONFIRM_SECRET")
    secret = env_secret.encode("utf-8") if env_secret else secrets.token_bytes(32)

    try:
        server = build_server(args.roots, secret=secret, ttl_seconds=args.ttl_seconds)
    except Rejected as exc:
        parser.error(str(exc))
        return 2

    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
