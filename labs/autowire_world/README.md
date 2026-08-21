# SOUL Auto-Wire World Lab

Laboratorio reproducible del spec `SOUL Model Auto-Wire v1.2`. No toca
Dadito-Laptop ni ningún daemon/DB de producción.

## Qué prueba por efecto

- 14 origins independientes sobre HTTP real en una red Docker interna;
- cinco familias: OpenAI Chat, OpenAI Responses, Anthropic Messages, Gemini y
  Ollama native;
- canarios para ocho perfiles chinos: Qwen, DeepSeek, GLM, Kimi, ERNIE,
  Hunyuan, Doubao y MiniMax;
- cuarentena de JSON con claves duplicadas y redirect;
- attach autenticado y rechazo de token/app/session inválidos;
- siete cambios secuenciales y dos claims simultáneos sobre la misma generación,
  con un único ganador CAS/fencing y conservación de `machine_soul_id` y memoria;
- fallo post-commit, rollback y retorno al cerebro anterior;
- persistencia de binding, sesión, identidad y memoria después de reiniciar el
  gateway;
- usuario no-root `65532`, rootfs read-only, `cap_drop=ALL`,
  `no-new-privileges`, cero puertos al host y red `internal=true`.
- imagen base Python fijada por tag y digest OCI para que el laboratorio no
  cambie silenciosamente entre corridas.

Los proveedores son simuladores sintéticos, no servicios cloud reales. La prueba
certifica la arquitectura/protocolos en contenedores, no cuentas, precios,
políticas ni versiones vivas de cada vendor.

## Ejecución

```bash
python3 soul-platform/labs/autowire_world/run_lab.py
```

El runner usa un init efímero root sin red únicamente para entregar el volumen a
UID `65532`; después, gateway, verifier y providers corren no-root. Al finalizar
elimina únicamente los contenedores, red y volumen del proyecto de prueba.
