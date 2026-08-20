"""An MCP server whose confirmation dialog cannot be replayed against a different call."""

from __future__ import annotations

from .prompt import safe_value
from .server import build_server, main
from .state import Claims, ConfirmationState, Rejected, params_digest

__version__ = "0.1.0"

__all__ = [
    "Claims",
    "ConfirmationState",
    "Rejected",
    "__version__",
    "build_server",
    "main",
    "params_digest",
    "safe_value",
]
