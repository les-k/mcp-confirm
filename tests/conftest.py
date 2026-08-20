"""Fixtures that build real files and drive the real protocol types.

Nothing here is mocked. A mocked ``Context`` would pass every test in this
suite while the server still deleted the wrong file, which is the specific
failure this project exists to rule out.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path

import pytest
from mcp.server.mcpserver import Context
from mcp.types import ElicitResult, InputResponseRequestParams


@pytest.fixture
def secret() -> bytes:
    return secrets.token_bytes(32)


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


def first_round() -> Context:
    """A context as it arrives on the initial call: no responses, no state."""
    return Context()


def retry(state: str | None, *, action: str = "accept", confirmed: bool = True) -> Context:
    """A context as it arrives on the client's retry."""
    return Context(
        input_params=InputResponseRequestParams(
            input_responses={
                "confirm": ElicitResult(
                    action=action,  # type: ignore[arg-type]
                    content={"confirmed": confirmed} if action == "accept" else None,
                )
            },
            request_state=state,
        )
    )


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
