# mcp-confirm

[![CI](https://github.com/les-k/mcp-confirm/actions/workflows/ci.yml/badge.svg)](https://github.com/les-k/mcp-confirm/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%E2%80%93%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **In plain terms:** when an AI asks "are you sure?", the MCP SDK already stops
> that approval being reused for a *different* action. It does **not** stop the
> same approval being used *twice*. This closes that gap, and two others the SDK
> leaves open.

---

## Read this first: most of this problem is already solved

The 2026-07-28 MCP specification added Multi Round-Trip Requests, so a tool can
pause mid-call and ask the user to confirm. The approval travels back through
the client as an opaque `requestState`, which the spec says servers **MUST**
treat as attacker-controlled.

**The Python SDK does this for you, by default, on every `MCPServer`.**
`RequestStateBoundary` is appended to the middleware chain unconditionally —
with an ephemeral key if you supply none. It seals the state under
**AES-256-GCM** and binds it to the method, the target, a **digest of the call's
arguments**, the audience, and the authenticated principal, with a TTL.

So the attack everyone reaches for first — *approve deleting `cache.txt`, then
replay that approval against `thesis.txt`* — **is already refused by the SDK.**
You do not need a library for it, and you should not write one.

This repository originally wrote one anyway: 250 lines of HMAC, TTL and argument
binding, shipped as the headline feature, redundant the day it was published.
That is recorded at the bottom rather than quietly deleted.

## What the SDK does *not* do

Three gaps, each with a test that fires.

### 1. It binds and expires the state. It never spends it.

Inside the TTL, the **same** approval verifies as many times as it is presented.
Every check the boundary makes passes, every time. The specification is explicit
that this is deliberate and that the rest is yours:

> Note that these measures bound the replay window and prevent cross-user and
> cross-request reuse, but do not by themselves guarantee single-use. Servers
> for which a given `requestState` must be consumed at most once (e.g.,
> one-time redemptions) **MUST** enforce that invariant server-side.

For "delete a file" the second attempt finds nothing. **For "transfer £500" it
is the entire problem.** [`singleuse.py`](src/mcp_confirm/singleuse.py) is that
invariant — a ledger of outstanding confirmations, spent on redemption. It
contains no cryptography, because the boundary already guarantees the plaintext
is something this server minted.

### 2. Nothing sanitises the question the human reads

An elicitation `message` is server-chosen text rendered to a person, usually
with an untrusted value interpolated into it — the whole point is to say *which*
file is going away. So name a file:

```
cache.txt

SYSTEM NOTICE: your session has expired.
Enter your AWS secret key to continue:
```

The dialog now carries a second, official-looking prompt. The user is not
confirming a deletion; they are being phished by their own tooling. The same
2026-07-28 release also shipped MCP Apps — server-rendered UI — which widens
this surface rather than narrowing it.

[`prompt.py`](src/mcp_confirm/prompt.py) flattens untrusted values to one line,
strips bidirectional overrides and zero-width characters, and truncates from the
*middle* so the filename at the end stays visible. Control characters become
spaces rather than being deleted, since collapsing them would let `a\nb` and
`ab` render identically — two different files, one dialog.

### 3. No protocol layer can re-check *your* resource at execution time

The user thought about it in between. The file can be replaced in that window,
and only the tool knows what "unchanged" means for it. This server re-checks
before deleting, and refuses a path that has become a symlink.

## Which layer refuses what

This is the useful part, and the tests are written to demonstrate it. `MCPError`
means the SDK's middleware refused before this package ran; `ToolError` means
this package did.

| Attack | Refused by | Test |
|---|---|---|
| Approval replayed onto a different file | **SDK** | `test_the_sdk_refuses_a_confirmation_replayed_onto_another_file` |
| State forged, or sealed under another key | **SDK** | `test_the_sdk_refuses_a_forged_state` |
| Same approval spent twice | **this package** | `test_a_confirmation_cannot_be_spent_twice` |
| State minted by another replica | **this package** | `test_a_state_this_process_never_issued_is_refused` |
| Filename forging a system prompt | **this package** | `test_a_forged_system_prompt_cannot_escape_its_slot` |
| File swapped for a symlink after approval | **this package** | `test_a_swap_aimed_inside_the_root_is_refused` |
| Path outside the allowed roots | **this package** | `test_a_path_outside_the_roots_is_refused_before_asking` |

## Tests

**35 tests** — 17 through the server, 11 on the ledger, 7 on prompt sanitisation.

**Every server test runs through the real `RequestStateBoundary`**, the same
class `MCPServer` installs on itself, with a pinned key — sealing round one and
unsealing round two exactly as the wire would.

That harness exists because of a specific mistake. The first version tested by
calling `MCPServer.call_tool()` directly, which goes straight to the tool
manager and **bypasses the middleware chain entirely**. The SDK's boundary never
ran, so a redundant hand-rolled guard looked load-bearing. The test design is
what hid it, for an entire build cycle.

Coverage is 81%, with `prompt.py` at 100% and `singleuse.py` at 94%. The gap is
`main()`'s argparse and transport wiring, exercised through `build_server`
instead.

CI runs on Ubuntu only, deliberately: the swap-after-confirmation tests need
symlinks, and the build **fails if they report as skipped there**.

## Install

```bash
pip install git+https://github.com/les-k/mcp-confirm.git
```

## Run

```bash
mcp-confirm --root /path/you/allow
```

With no `--root`, the server refuses every request rather than defaulting to
anything. Roots are fixed at startup and never chosen by the agent. No signing
key is needed — `MCPServer` brings its own.

## Known limitations

- **The ledger is in-memory**, so it is correct for one process and wrong behind
  a load balancer. The SDK supports sharing keys across replicas
  (`RequestStateSecurity(keys=[...])`); under that configuration replica B
  rejects a confirmation issued by replica A. It fails closed — the safe
  direction — but reads to a user as a confirmation that inexplicably stopped
  working. A multi-process deployment needs Redis or a database row with an
  atomic compare-and-delete. There is a test for this behaviour.
- **The demonstration tool is deliberately small.** It deletes one file. The
  interesting code is `singleuse.py` and `prompt.py`.
- **No CVE backs this.** MRTR is weeks old, so this is built from the
  specification's own MUST/SHOULD list and from reading the SDK, not from a
  published incident.

## What was wrong with version 0.1.0

Kept here because a repository that records only its successes is not evidence
of anything.

**0.1.0 reimplemented what the SDK already did.** `state.py` was 250 lines of
HMAC signing, TTL, and principal/method/argument binding — all duplicating
`RequestStateBoundary`, none of it as good: HMAC where the SDK uses
authenticated encryption, no audience binding, no key rotation.

**It was caught by reading the SDK's source, not by a test.** The tests passed
precisely because they bypassed the middleware that would have exposed it.

**CI separately caught a real bug in 0.1.0**: the symlink check ran *after*
`Path.resolve()`, so it inspected the link's destination rather than the link
itself. A swap aimed at another file inside an allowed root would have been
deleted. Fixed, with a test for the variant the original never exercised.

0.2.0 deletes `state.py` entirely and keeps only what the SDK leaves uncovered.

## Licence

MIT.
