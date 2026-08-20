"""The protocol layer: three controls the SDK's own boundary does not provide.

The demonstration tool deletes a file. Deletion was chosen because it is
irreversible, which is the only category of action where a confirmation is
load-bearing rather than decorative.

**What this file does not do.** It does not sign, encrypt, or bind the
confirmation state. `RequestStateBoundary` — installed by default on every
`MCPServer` — already seals it under AES-256-GCM and binds it to the method,
target, argument digest, audience and principal. Verified empirically, not
inferred: present a state sealed for `delete_file(cache.txt)` on a call to
`delete_file(thesis.txt)` and the SDK answers "Invalid or expired
requestState" before this module runs at all. Reimplementing that by hand
would be worse code guarding an already-closed hole.

**What it does do**, because the boundary does not and in two cases cannot:

1. **Spends the confirmation.** The boundary binds and expires state; it never
   consumes it. Inside the TTL the same approval verifies repeatedly. See
   `singleuse.py`.
2. **Sanitises the question.** The elicitation message is text a human reads
   and acts on, with an untrusted value interpolated into it. See `prompt.py`.
3. **Re-checks the target at execution time.** The user thought about it in
   between, and the filesystem can change in that window. No protocol layer
   can know what "unchanged" means for a given tool.
"""

from __future__ import annotations

import argparse
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
from .singleuse import Rejected, SingleUseLedger

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


def _refuse_if_link(path: str) -> None:
    """Reject a symlink, judged on the path as written.

    This must run *before* `_contain`, and the ordering is the whole point.
    `_contain` calls `Path.resolve()`, which follows a symlink to its
    destination and returns that — so a link check afterwards inspects wherever
    the link points, not the link itself. A swap aimed at another real file
    inside an allowed root would resolve cleanly, pass containment, and be
    deleted as though it were the file the user approved.

    CI caught exactly this on the first version of this repository.
    """
    raw = Path(path).expanduser()
    try:
        if raw.is_symlink():
            raise Rejected(f"{raw} is a link; this tool refuses to act through one")
    except OSError as exc:
        raise Rejected(f"cannot inspect {raw}: {exc}") from exc


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


def build_server(
    roots: Sequence[Path | str],
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> MCPServer:
    """Wire the tool up. `clock` is injected so expiry is testable.

    No signing key is taken, because none is needed: `MCPServer` installs
    `RequestStateBoundary` with an ephemeral key of its own. Pass
    `request_state_security=` to `MCPServer` if you need shared keys across
    replicas — and read the note in `singleuse.py` before you do, because the
    ledger here is per-process.
    """
    allowed = _resolve_roots(roots)
    ledger = SingleUseLedger(ttl_seconds=ttl_seconds)

    server = MCPServer(
        name="mcp-confirm",
        instructions=(
            "Deletes a file, but only after the user has confirmed that exact "
            "deletion. The confirmation is single-use and is re-checked against "
            "the filesystem at the moment of deletion."
        ),
    )

    @server.tool(
        name=_METHOD,
        description=(
            "Delete a single file inside the server's configured roots. Asks the "
            "user to confirm first and will not proceed without that answer. Each "
            "confirmation can be redeemed once."
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

        _refuse_if_link(path)
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
                # Sealed by RequestStateBoundary on the way out and unsealed on
                # the retry, so what arrives back is plaintext this process
                # minted, bound to this exact call.
                request_state=ledger.issue(now=now),
            )

        # Round two.
        if not isinstance(answer, ElicitResult):
            raise Rejected("confirmation response was not an elicitation result")

        # By the time this runs, the SDK has already established the state is
        # authentic, unexpired, and bound to this exact call. The only question
        # left is whether it has been spent — and spending it is what stops the
        # same approval being redeemed twice.
        ledger.spend(ctx.request_state or "", now=now)

        if answer.action != "accept":
            return f"Cancelled: the user answered {answer.action!r}. Nothing was deleted."
        if not (answer.content or {}).get("confirmed"):
            return "Cancelled: the user did not confirm. Nothing was deleted."

        # Re-check the filesystem now, rather than trusting what was true when
        # the question was asked.
        if not target.exists():
            raise Rejected(f"{target} no longer exists")
        if not target.is_file():
            raise Rejected(f"{target} is no longer a regular file")

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
        description="An MCP server closing the three gaps the SDK's request-state boundary leaves.",
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

    try:
        server = build_server(args.roots, ttl_seconds=args.ttl_seconds)
    except Rejected as exc:
        parser.error(str(exc))
        return 2

    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
