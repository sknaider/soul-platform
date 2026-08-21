# SOUL real-model container lab

Acceptance lab for William's "race car with the engine running" invariant:
one persistent SOUL record is consumed by three real brains without placing
provider credentials in the test containers.

Real providers exercised:

- Codex CLI: `gpt-5.6-sol` through the host's authenticated ChatGPT session.
- Claude Code: `opus` through the host's authenticated subscription.
- Ollama: `gemma3:1b-it-qat` (1 GB), fully local.

The provider broker runs host-side and exposes only an authenticated Unix
socket.  Both SOUL probe containers run as a non-root UID with `--network
none`, a read-only root filesystem, all capabilities dropped and no provider
credentials in their environment.  The first container switches across all
three brains; a newly-created second container reopens the same SQLite soul and
proves recall after restart.

Run the hermetic boundary tests:

```bash
python3 -m pytest -q soul-platform/labs/real_models/test_real_models_lab.py
```

Run the real acceptance test (uses the already-authenticated local CLIs and
Ollama, and therefore consumes normal provider quota):

```bash
python3 soul-platform/labs/real_models/run_lab.py \
  --receipt /tmp/soul-real-models-receipt.json
```

The runner removes only containers whose exact names include its own PID and
deletes only the private temporary directory it created.  It never copies a
Codex/Claude credential into Docker.
