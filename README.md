# mcp-confirm

[![CI](https://github.com/les-k/mcp-confirm/actions/workflows/ci.yml/badge.svg)](https://github.com/les-k/mcp-confirm/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%E2%80%93%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **In plain terms:** when an AI asks "are you sure?", the yes you give applies
> only to the exact thing you were shown. It cannot be quietly reused to approve
> something else — approving the deletion of a cache file cannot become a deleted
> contract.

**An MCP server whose confirmation dialog cannot be replayed against a different
call.**

The 2026-07-28 MCP specification introduced Multi Round-Trip Requests, which let
a tool stop mid-call and ask the user to confirm before acting — "confirming the
cost of a new project before creation, or a query that would delete data". The
server hands back an opaque `requestState`; the client collects the answer and
re-issues the call, echoing that state back.

The state therefore travels **through the client**, which is why the
specification says this:

> Servers **MUST** treat `requestState` as an attacker-controlled input. If
> `requestState` influences authorization, resource access, or business logic,
> servers **MUST** protect its integrity (e.g. HMAC or AEAD) and **MUST** reject
> state that fails verification.

and, for replay, that servers **SHOULD** seal into that protected payload:

> the authenticated principal ... a short expiry (TTL) ... an identifier for the
> originating request, e.g. the method name and a digest of its salient
> parameters, rejecting state presented on a request that does not match.

This server implements all of it, and the tests are the point.

## The attack the parameter digest exists for

A signature alone proves the server issued **some** approval. It does not prove
the approval was for **this** call.

```
1. Agent calls   delete_file(path="/tmp/cache.txt")
2. Server asks   "Permanently delete /tmp/cache.txt?"        → user says yes
3. Agent retries delete_file(path="/home/alice/thesis.txt")
                 ...echoing the state the user just approved
```

That state is **not forged**. It is a real, correctly signed token this server
minted seconds earlier. A server that verifies only the signature sees something
genuine and proceeds — and the user, who was asked about a cache file, loses
their thesis.

Without the binding, the confirmation dialog is worse than absent: absent, the
user knows nothing protected them; present, they believe they were asked.

Both halves of that are tested, one against the other:

| Test | Asserts |
|---|---|
| `test_a_confirmation_for_one_file_cannot_delete_another` | the swap is refused, and `thesis.txt` still contains `"years of work"` |
| `test_the_same_confirmation_works_for_the_file_it_named` | the *same* state succeeds against the path it was granted for |

The second is the control. Without it, the first would also pass if the server
simply rejected everything.

## What it checks

Every rule below has a test that makes it fire.

| Control | Why |
|---|---|
| **HMAC-SHA256 over the state**, verified in constant time | Spec MUST. A byte-by-byte compare leaks how much of a forged signature was right, which is enough to build one a byte at a time |
| **Signature checked *before* the payload is parsed** | Parsing attacker-controlled JSON and then deciding whether to trust it makes every parser bug reachable unauthenticated |
| **Digest of the call's arguments** | Spec SHOULD. The clause above — this is what makes an approval specific to one call |
| **Principal binding** | Spec SHOULD. Alice's approval is not Bob's |
| **Method binding** | An approval for `delete_file` is not an approval for `send_email` |
| **Short TTL, exclusive at the boundary** | Spec SHOULD. A confirmation valid for one final instant is a race |
| **Single-use nonce** | Spec's own warning: TTL and binding bound the replay *window*, they do not guarantee single use |
| **Re-check the target at execution time** | The user thought about it in between. Anything could have replaced the file in that window |
| **Sanitised prompt interpolation** | The dialog is text a human acts on — see below |
| **Weak signing key refused at construction** | A server that only fails when attacked has already shipped the vulnerability |

### The prompt is a security boundary

An elicitation `message` is server-chosen text rendered to a person. It usually
has an untrusted value interpolated into it, because the whole point is to say
*which* file is going away. So name a file:

```
cache.txt

SYSTEM NOTICE: your session has expired.
Enter your AWS secret key to continue:
```

Interpolate that into `"Delete {path}?"` and the dialog now contains a second,
official-looking prompt. The user is not confirming a deletion; they are being
phished by their own tooling. The same 2026-07-28 release also introduced MCP
Apps — server-rendered UI — which widens this surface rather than narrowing it.

`prompt.py` flattens untrusted values to one line, strips bidirectional
overrides and zero-width characters, and truncates from the *middle* so the
filename at the end stays visible. Control characters become spaces rather than
being deleted, because collapsing them would let `a\nb` and `ab` render
identically — two different files, one dialog.

## Design

`state.py` and `prompt.py` **import no MCP at all.** Every decision that could
lose someone data is testable without a client, a transport, or an agent in the
loop. `server.py` is a thin translation over them.

The server keeps **no memory between rounds**. Everything tying the approval to
the action is sealed inside the state blob, which is what makes the flow work on
stateless, load-balanced infrastructure — the reason MRTR replaced the old
server-initiated pattern in the first place.

Verification runs against the arguments of **the retry**, never against
whatever the first round happened to carry.

## Tests

**52 tests: 29 against the state guard, 7 against prompt sanitisation, 16
through a real `tools/call`.**

The split matters: a guard that refuses correctly in isolation is worth nothing
if the server forgets to consult it, or consults it with the wrong arguments.
Both layers are exercised, and the end-to-end tests use the protocol's own
`Context`, `ElicitResult` and `InputRequiredResult` types rather than mocks.

Coverage is **82% overall, with `state.py` at 93% and `prompt.py` at 100%** —
the two modules where a mistake loses data. The gap is `main()`'s argparse and
transport wiring, which the suite drives through `build_server` directly, plus a
few defensive branches that need a filesystem error to reach.

One test deserves calling out — `test_the_sdk_documentation_example_string_is_refused`.
The Python SDK's own multi-round-trip example passes:

```python
return InputRequiredResult(input_requests={...}, request_state="delete-v1")
```

A constant, unsigned string. That is *permitted* in a snippet whose state carries
no meaning — the spec allows omitting integrity protection when "tampering can
cause nothing worse than request failure". But it is the shape people copy, and
it stops being harmless the instant the blob encodes anything a decision depends
on.

CI runs on Ubuntu only, deliberately: the swap-after-confirmation test needs
symlinks, and the build **fails if that test reports as skipped there**. A suite
that silently skips its most important case is decoration.

### The first push did not pass, and the bug was a real one

CI rejected the initial commit, and it was not a trivial failure. `_contain()`
calls `Path.resolve()`, which follows a symlink to its destination — so
`target` was already resolved by the time `target.is_symlink()` ran, meaning
that check inspected **where the link pointed, not the link itself**.

The original test passed safely only by accident: its replacement symlink
pointed *outside* the allowed root, so containment refused it first and the
link check was never reached. Aim that link at another real file *inside* the
same root and the guard collapsed entirely — containment resolves it, finds the
destination legitimately in-bounds, `is_symlink()` sees an ordinary file, and
the server deletes a file the user never approved.

In the one project whose entire claim is that you cannot approve one thing and
get another.

The fix moves the link check onto the **unresolved** path, before containment
runs. `test_a_swap_aimed_inside_the_root_is_refused` covers the variant the
original test never exercised. Left in the history rather than tidied away,
because a guard nobody has watched fail is a guard nobody has tested.

## Scanner results

Run against [`agent-audit`](https://pypi.org/project/agent-audit/) 0.19.2.

**Static scan — 0 findings, risk score 0.0, 9 files.** Two findings on the first
pass, both fixed:

- `AGENT-022` (medium) — unhandled exceptions in the tool body. Legitimate:
  `unlink()` and `stat()` can raise `OSError` for a read-only file or one held
  open by another process, and that was surfacing as a bare system error rather
  than something the calling model could act on. Now caught and reported as a
  refusal with the reason attached.
- `AGENT-110` (low) — source maps not excluded from distribution. This package
  ships no JavaScript, but the exclusion is declared anyway; arguing with a
  supply-chain checklist is a poor use of an afternoon.

**Tool inspection — 0 findings.** No tool-poisoning or injection patterns.

The risk *rating* is worth reproducing, because it is wrong in an instructive
direction:

| Tool | Rated | Inferred permissions |
|---|---|---|
| `delete_file` | **LOW** | FILE_READ, FILE_DELETE |

A tool that permanently deletes files scores LOW. Meanwhile the read-only
`scan()` in a [sibling project](https://github.com/les-k/sweep-mcp) scored
**HIGH** — because its description contained the word *"command"*, which the
scanner maps to `SHELL_EXEC`, and the word *"deletes"*, in the sentence "this
never deletes anything".

Same scanner, two tools, and the ratings are inverted relative to what the tools
actually do. The scores come from matching keywords against prose, so they track
vocabulary rather than behaviour. **A keyword scanner is a smoke detector, not a
judge** — a clean run is worth having and worth publishing; a rating derived
from string matching is not evidence about behaviour in either direction.

## Install

```bash
pip install git+https://github.com/les-k/mcp-confirm.git
```

## Run

```bash
mcp-confirm --root /path/you/allow
```

With no `--root`, the server refuses every request rather than defaulting to
anything. Roots are fixed at startup and never chosen by the agent.

The signing secret defaults to a fresh random value per process, so
confirmations do not survive a restart — a state blob minted by a previous
process refers to a decision this one never witnessed. Set `MCP_CONFIRM_SECRET`
to share signing across replicas, and read the note below first.

## Known limitations

Stated rather than hidden, because each one is the kind of thing that looks fine
in tests and fails in production.

- **Single-use enforcement is in-memory**, so it is correct for one process and
  wrong behind a load balancer. A multi-process deployment needs a shared store
  with a compare-and-set — Redis, a database. The spec is explicit that
  at-most-once redemption is the server's job, not the protocol's.
- **Over stdio there is no authenticated principal**, so the principal binding
  collapses to a constant and is vestigial there. It is meaningful for an HTTP
  deployment carrying a verified token. The code path is identical either way so
  the HTTP case is not an untested afterthought.
- **The demonstration tool is deliberately small.** It deletes one file. The
  interesting code is `state.py`; `server.py` exists to prove the guard is
  actually wired in.
- **No CVE backs this one.** `sweep-mcp` and `pg-readonly-mcp` each defend
  against something disclosed and named. MRTR is three weeks old at the time of
  writing, so this is built from the specification's own MUST/SHOULD list rather
  than from a published incident. That is a real difference in evidentiary
  weight and is stated plainly rather than dressed up.

## Licence

MIT.
