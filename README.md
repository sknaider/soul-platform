# SOUL Platform

The contained runtime and multi-agent operating layer for
[`soul-framework`](https://pypi.org/project/soul-framework/).

SOUL Core provides persistent identity and memory. Platform adds the parts that
act: a tool runtime, durable team coordination, signed receipts and an external
container boundary for dangerous tools. Agency is disabled unless a `Limit` is
provided.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install soul-platform
soul-platform --serve                    # local API on 127.0.0.1:8890
```

Optional integrations:

```bash
.venv/bin/pip install 'soul-platform[postgres]'
.venv/bin/pip install 'soul-platform[desktop]'
```

The installer never uses sudo or configures PostgreSQL. It can install Python
extras inside its venv and prints the DBA-owned server steps.

## Architecture

- **F1 — scale memory:** `soul-framework[postgres,embeddings]`, PostgreSQL +
  pgvector, published as Core v0.3.0.
- **F2 — runtime + tools:** `soul_platform.runtime.AgentRuntime`. Allowlist,
  effect scopes, atomic durable budgets, timeout, bounded output and durable audit.
- **F3 — multi-agent:** `soul_platform.coordination.Coordinator`. Durable task
  state, fenced leases, request-bound idempotency, handoffs, tenant-scoped
  team/DM channels and chained receipts.
- **F4 — containment:** `soul_platform.sandbox.DockerSandbox` and Ed25519
  receipts. Untrusted tools run with network `none`, read-only root, all Linux
  capabilities dropped, `no-new-privileges`, resource ceilings and an external
  kill-switch.
- **F4 — bounded autonomy:** `soul_platform.autonomy.AutonomyController` turns
  durable schedules into pending coordinator tasks. Schedules never run a host
  command; execution still requires a fresh fenced claim, a `Limit` and a
  sealed `DockerTool`.

## Security boundary

An in-process Python allowlist is not an OS sandbox. `ToolSpec` therefore accepts
only the sealed `DockerTool` adapter—even a nominally "pure" tool cannot run as a
host Python callable. `DockerSandbox` defaults to no network, read-only root,
non-root UID and bounded resources; images must be both pinned by SHA-256 and in
an operator allowlist. Verifier public keys come from an operator trust store—no
trust root or private key is shipped in the package.

The model adapter follows the same rule: `AgentRuntime` accepts the built-in
`SubprocessLLMProvider`, which exchanges canonical JSON over stdin/stdout and
kills/reaps the provider process group at deadline. An arbitrary in-process
coroutine cannot suppress cancellation and accumulate hidden model work.

Signed receipt chains detect payload or link tampering. To detect deletion of a
valid suffix, persist the last accepted receipt hash independently and pass it as
`expected_head` to `ReceiptVerifier.verify_chain()`.

The coordinator expects the API boundary to authenticate the actor. It resolves
membership and role from its durable store rather than accepting a role from a
request payload. The included channel API does this with short-lived Ed25519
bearer tokens: tenant and actor are read only from the verified token, never
from the message body. Operator-owned environment configuration supplies the
authentication public keys, coordinator signing key, state DB and separate
checkpoint DB; if any are absent, multi-agent routes return `503` fail-closed.

Coordinator receipts first commit atomically with a durable checkpoint outbox.
If the independent head store is unavailable, the accepted operation remains
truthfully committed/pending and all later mutations stop until
`reconcile_checkpoints()` succeeds; a sidecar error is never misreported as
"the operation did not happen".

## Open formats / anti-lock-in

SOUL memories remain in the open Core schemas. Platform tasks and events are
ordinary SQLite tables; receipts are canonical JSON containing SHA-256 hashes
and Ed25519 signatures. Export does not require a proprietary service.

## Verify

```bash
python -m pytest -q
python -m build
python -m twine check dist/*
```

The test suite includes concurrent budget attacks, restart persistence,
concurrent task claims, handoff/restart, receipt tampering, a real Core API
round-trip, a resistant container kill and inspection of the Docker security
envelope.

## Release discipline

Nothing is published from the SEAL monorepo. A release is exported to a clean
tree, scanned for secrets/internal paths, rebuilt, independently reviewed and
then requires William's explicit publication approval.
