# SOUL AutoAttach

The trusted `SessionStart` hook injects the local MachineSoul before the first
model response. Treat that context as already loaded; do not search for
`soul_boot_context`, run shell commands, or launch alternate Codex binaries.

1. Use `soul_memory_search` when prior context matters.
2. Stage only explicit declarative facts with `soul_memory_propose`; canonical memory
   changes only after local-owner review with an exact digest.
3. If SessionStart explicitly reports failure, report `SOUL_UNAVAILABLE` and
   the startup error; do not pretend that persistent memory is connected.

SOUL is the persistent identity and memory layer. The model is the replaceable brain.
