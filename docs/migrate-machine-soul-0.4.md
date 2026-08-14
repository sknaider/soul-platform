# MachineSoul 0.3 → 0.4: migración reversible

SOUL Platform 0.4.1 fija `soul-framework==0.4.3` y usa BGE-M3 local
(1024 dimensiones) con `vector_index="auto"`. Platform instala USearch como
motor ANN binario portable en Windows, Linux x86_64 y Linux ARM64; Core conserva
la búsqueda exacta como fallback fail-safe. El instalador detecta automáticamente una
configuración 0.3, detiene el autostart, crea un candidato separado, lo verifica
y recién entonces conmuta la configuración al candidato bajo locks SQLite. La
base original, una copia serializada y la configuración anterior se conservan;
no se borran ni se renombran bajo un WAL activo.

Requisitos antes del upgrade:

```powershell
ollama pull bge-m3
```

El flujo ejecutable que usa el instalador es:

```text
soul-machine disable-autostart --config %LOCALAPPDATA%\SOUL\proxy.toml
soul-machine-embedding-cutover migrate MachineSoul.db --candidate MachineSoul.bge-m3.candidate.db --checkpoint MachineSoul.bge-m3.checkpoint.json
soul-machine-embedding-cutover verify MachineSoul.bge-m3.checkpoint.json
soul-machine-embedding-cutover activate proxy.toml MachineSoul.bge-m3.checkpoint.json
```

`activate` falla cerrado si Ollama/BGE-M3 no responde con exactamente 1024
valores finitos, si SQLite sigue abierto, si hay symlinks/reparse points, si el
candidato mezcla dimensiones o si cambia el contenido lógico de cualquier
generación. El UUID y el baseline del alma no cambian al cambiar el archivo
activo.

Para volver a la base 128d preservada (que Platform 0.4 mantiene compatible):

```text
soul-machine-embedding-cutover rollback proxy.toml MachineSoul.bge-m3.checkpoint.json
soul-machine init --kind ollama --base-url http://127.0.0.1:11434/v1 --model MODELO
```

El rollback se niega si hubo una escritura lógica nueva en el candidato: nunca
descarta un recuerdo para aparentar éxito. El candidato BGE-M3 queda retenido.
Si candidate y
checkpoint no existen juntos, el instalador deja un `HOLD` explícito y no
adivina qué archivo es canónico.
