# T5 production cutover

T5 protects the boundary where retrieved SOUL memories enter a model prompt.
It does not trust prompt text, `soul_memory` metadata, or the local device token
as an interlocutor identity. The device token remains required, but production
multi-user access additionally requires a short-lived Ed25519 principal token
  whose signature covers tenant, actor, session ID and the exact machine SOUL
  audience. A token issued for one SOUL is rejected by every other SOUL even if
  an operator accidentally reuses the same authentication key.

## Compatibility contract

- A legacy config without `[memory_egress]` loads in `locked` mode. Chat still
  reaches the configured brain, but boot, recall and semantic writes are
  withheld. This is deliberately fail-closed.
- New local single-owner installs declare `compatibility-single-owner`. At
  startup, the sidecar binds every existing active memory to the one configured
  owner in one atomic transaction. It never updates or deletes the Core DB.
- Multi-user deployments use `enforce`. They must supply a private, owner-only
  Ed25519 public-key trust store and signed principal tokens containing a
  non-empty `session_id` and `audience = machine_soul_id`.
- The T5 SQLite sidecar stores only IDs, trusted ownership/scope and budget
  counters. It stores no memory content.
- File ownership is not a boundary against a hostile process running under the
  same OS UID. Such deployments must run the proxy/sidecar under a dedicated
  service identity or put provenance behind an equivalent database-role
  boundary.
- MCP consent and candidate review are cooperative controls, not a sandbox for
  a coding agent that already has arbitrary shell access as the owner. TTY
  confirmation blocks accidental/headless calls but is not cryptographic user
  presence: a hostile same-UID process can synthesize a pseudo-terminal. Do not
  claim prompt-injection-resistant custody without a dedicated broker identity
  plus independent owner presence (for example Windows Hello/FIDO-backed UI).

## Safe cutover

1. Stop the proxy through its normal service controller and confirm no writer
   remains. Back up the Core SQLite DB together with any `-wal`/`-shm` files and
   the T5 sidecar if it already exists.
2. For a genuinely single-owner database, add:

   ```toml
   [memory_egress]
   mode = "compatibility-single-owner"
   tenant = "local-machine"
   owner_subject = "local-owner:<machine_soul_id>"
   state_db = "/absolute/canonical/SOUL/root/MachineSoul.t5-egress.sqlite3"
   ```

   Do not use this mode for a database containing more than one person's
   private memories. Split or classify that data first.
3. Start once in compatibility mode. Confirm the proxy is ready, the sidecar is
   private, and the count in `t5_memory_provenance_v1` equals the count of active
   Core memories. A 54,750-row synthetic migration completed idempotently in
   0.271 seconds on the release host; the count equality is still the gate that
   matters.
4. Before switching to `enforce`, provision a private JSON trust store mapping
   key IDs to base64-encoded raw Ed25519 public keys. Configure the same tenant
   and owner, add `principal_keys_file`, and make the authenticating front end
   issue signed tokens with a unique session ID and the exact target
   `machine_soul_id` as audience. Never accept actor/session/audience values
   from unsigned headers or request JSON.
5. Canary with two signed subjects: the owner must recall an exact seeded fact;
   the other subject must receive zero memory IDs and the seeded bytes must be
   absent from the forwarded system message. Repeat after a process restart and
   with two concurrent workers.

## Rollback

If any count, authentication or disclosure canary fails, stop the proxy and set
the mode to `locked`. This immediately withholds boot, recall and semantic
writes while leaving the Core DB untouched. Preserve the T5 sidecar for audit;
do not delete it. Restore the backed-up files only after comparing exact counts
and hashes. A return to compatibility mode is allowed only for the same explicit
single owner; changing the owner conflicts with immutable provenance and aborts.

No live service activation is part of this change. Deployment requires an
independent byte-bound review and an operator-controlled restart window.
