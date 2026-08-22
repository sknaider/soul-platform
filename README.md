# SOUL Platform

The contained runtime and multi-agent operating layer for
[`soul-framework`](https://pypi.org/project/soul-framework/).

SOUL Core provides persistent identity and memory. Platform adds the parts that
act: a tool runtime, durable team coordination, signed receipts and an external
container boundary for dangerous tools. Agency is disabled unless a `Limit` is
provided.

## Install

```bash
cd bundle
./soul-install.sh --model gemma3:1b-it-qat
```

The supported public install is a release bundle containing Platform 0.5.8,
Core 0.4.3 and SHA-256 files. `soul-install.sh` auto-discovers and verifies
those wheels when they sit beside the script. The package is not currently
published on PyPI, so a bare `pip install soul-platform` is intentionally not
documented as a working path.
The release builder emits deterministic Windows ZIP and Linux/macOS `tar.gz`
archives; the latter extracts to the documented `bundle/` directory.

## AutoWire 0.5

On Windows the installer leaves SOUL hot-ready: it inventories fixed local
model surfaces without changing the active brain and registers a
least-privilege per-user watcher. Codex CLI and Claude Code are connected
through their official local stdio MCP configuration when present. Discovery
is not trust: raw HTTP model listeners remain memory-blocked (including
Ollama), cloud providers require a separate consent/egress contract, and the
BGE-M3 embedding identity is never auto-swapped. Codex and Claude retrieve
authorized SOUL context through MCP, outside the replaceable model endpoint.
An owner-authorized deployment may pass `-TrustCurrentOllama`; that one-time
enrollment binds the live Windows listener to its owner and executable hash.

Optional integrations:

```bash
.venv/bin/pip install 'soul-platform[postgres]'
.venv/bin/pip install 'soul-platform[desktop]'
```

The installer never uses sudo or configures PostgreSQL. It can install Python
extras inside its venv and prints the DBA-owned server steps.

## Persistent machine soul (local proxy)

> The brain can change; the soul, memory and identity remain.

SOUL Platform can expose one authenticated, OpenAI-compatible endpoint on the
loopback interface. Applications talk to that endpoint instead of directly to
Ollama or LM Studio. The proxy injects the same identity and recalled memories
on every request, while the configured upstream model remains replaceable.

After installing the package in a dedicated virtual environment, initialize a
machine soul (no administrator privileges are used):

```bash
soul-machine init --model gemma3:1b-it-qat
```

Novice installers are included for both families of desktop systems. They
create an isolated virtual environment, install only inside it, detect a local
Ollama model when available, and then run the same verified bootstrap:

The downloadable Windows bundle includes the exact wheel and its SHA-256 next
to the installer. Extract the ZIP and double-click
`Instalar-SOUL-Windows.bat`; the PowerShell installer verifies the wheel before
installing it into `%LOCALAPPDATA%\SOUL\venv`.

```powershell
# Windows PowerShell
.\installer\Install-Soul.ps1
```

```bash
# Linux / macOS
./installer/soul-install.sh
```

This creates private per-user state, a stable machine-soul UUID, an SQLite soul
database, an authentication token and an OS-native per-user autostart
descriptor. Re-running the command is idempotent and preserves the existing
identity and memories. The generated proxy listens only on
`127.0.0.1:11435`.

### SOUL Tray (cero terminal)

The desktop extra installs a native tray control surface. It reports whether
the soul and current brain are ready, discovers local Ollama models, switches
the brain without changing `machine_soul_id` or the memory database, starts or
stops the managed proxy, and copies the authenticated endpoint. Closing the
tray leaves the soul running.

```bash
python -m pip install 'soul-platform[desktop]'
soul-tray --headless-check
soul-tray --install-autostart
soul-tray
```

Windows uses two least-privilege per-user Scheduled Tasks: one for the proxy
and one for the tray. Neither runs as Administrator or SYSTEM. Linux uses the
verified user systemd proxy plus an XDG tray entry; macOS uses per-user
LaunchAgents. `soul-tray --remove-autostart` removes only the tray launcher and
preserves the machine soul, token, configuration and memories.

To point the same soul at another local OpenAI-compatible brain:

```bash
soul-machine switch-brain \
  --config ~/.local/share/soul/proxy.toml \
  --kind lm-studio \
  --base-url http://127.0.0.1:1234/v1 \
  --model local-model
```

`machine_soul_id`, database path, token and baseline hash are checked before
and after the switch. On Windows the default config lives under
`%LOCALAPPDATA%\SOUL`; on macOS it lives under
`~/Library/Application Support/SOUL`.

The client must send the generated token as `Authorization: Bearer <token>`.
Recall is read-only by default. `X-Soul-Remember: true` persists the raw user
prompt plus a response digest in a separate hash-linked conversation ledger;
it never promotes the question or prompt into semantic memory. A trusted client promotes a reviewed
declarative fact explicitly with
`"soul_memory":{"content":"...","importance":1..10}`. Questions are
rejected as facts. The response reports `X-Soul-Store` as `ledger`,
`fact-stored`, `ledger+fact`, `ledger-failed+fact-stored`,
`ledger+fact-failed`, `disabled` or `failed` without exposing content.
The ledger and agency audit each keep a private, atomic head sidecar, so editing,
reordering or deleting a valid suffix from the SQLite file fails closed on
reopen. Because the sidecar shares the user's OS account, high-assurance
deployments still checkpoint that head in an operator-owned external witness.
The v1 proxy accepts OpenAI-compatible SSE when `stream=true`, preserves SOUL
evidence headers and enforces the response-size ceiling before returning the
bounded event stream. It does not yet provide token-by-token low-latency
forwarding. Remote upstreams are disabled in proxy v1. The one
supported credential name is `SOUL_PROXY_UPSTREAM_API_KEY`; its value is read
from the environment and never stored in the TOML file.

To remove only the autostart descriptor while preserving the soul:

```bash
soul-machine disable-autostart
```

`soul-machine uninstall` stops and removes the per-user runtime integration but
also preserves the soul database, identity and token. Running `init` again
recovers the same soul. Purging those persistent files is intentionally not an
installer operation; it requires an explicit, separately reviewed deletion.

The current release renders and activates native Linux, Windows and macOS
per-user startup descriptors and is covered by cross-platform contract tests.
Disabling autostart stops the managed proxy but preserves identity, token,
configuration and memory data. Live model-switch verification has
been completed with two Ollama models; LM Studio remains a compatible endpoint
contract but must be verified on a host where LM Studio is running.

## Architecture

- **F1 — scale memory:** Core 0.4.3 with BGE-M3/1024, HNSW/pgvector and a
  reversible, byte-checked migration from legacy 128-dimensional embeddings.
- **F2 — runtime + tools:** `soul_platform.agency.AgentRuntime`. Allowlist,
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

The model adapter follows the same rule: host subprocess execution is outside
the release profile and is denied twice by default. An operator must explicitly
set both `allow_host_execution=True` and `allow_uncontained_model=True` for an
experimental trusted adapter; even then it receives a scrubbed environment, canonical JSON
over stdin/stdout and a hard-cancelable process group. Untrusted models belong
behind a contained adapter rather than in the host process.

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
