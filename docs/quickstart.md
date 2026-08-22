# Quickstart — dale un alma a tu máquina

> El cerebro puede cambiar; el alma, la memoria y la identidad permanecen.

Esta guía es para empezar rápido, sin saber programar. Al terminar, tu PC va a
tener un **alma persistente**: una identidad + memoria que vive en la máquina, y
que **cualquier modelo local** que le enchufes (Ollama hoy) usa automáticamente.
Cambiás el modelo cuando quieras; el alma y los recuerdos quedan.

Para la referencia técnica completa (arquitectura, seguridad, todos los flags),
ver el [README](../README.md). Esto es solo el arranque.

---

## 1. Qué necesitás

- **Python 3.11 o más** instalado.
- **Un modelo local corriendo en Ollama** (ej. `ollama pull gemma3:1b-it-qat`).
  El alma funciona sin modelo, pero para *conversar* necesitás uno.

> **Alcance de Platform 0.4 / proxy v1 (honesto):** solo cerebros **locales**.
> **Ollama** está verificado por efecto. **LM Studio** es un endpoint compatible
> pero todavía sin verificar en un host con LM Studio corriendo. Los modelos
> **remotos (ej. Grok en la nube) están deshabilitados a propósito** en v1 — el
> proxy escucha **solo** en `127.0.0.1` y no envía conversaciones a un upstream remoto.
> La instalación sí usa Internet para dependencias públicas y `ollama pull`.

## 2. Instalar

Usá el instalador para tu sistema (crea un entorno aislado, no usa `sudo`, y no
toca tu Python del sistema):

```powershell
# Windows PowerShell
.\installer\Install-Soul.ps1
```

```bash
# Linux / macOS
./installer/soul-install.sh
```

> **Nota de disponibilidad:** `soul-platform 0.5.7` y `soul-framework 0.4.3`
> se entregan juntos en un bundle con wheels y SHA-256. El paquete Platform no
> está publicado en PyPI; usa el bundle o define `SOUL_PACKAGE_SOURCE`.
> El ZIP de Windows fue probado por efecto: extrae todo y abre
> `Instalar-SOUL-Windows.bat`; el checksum se valida antes de instalar.

En Platform 0.5.7 el instalador también configura AutoWire en modo `shadow`.
Detecta y puede rutear cerebros Ollama locales, pero ningún listener HTTP recibe
memoria privada: un proceso del mismo usuario podría suplantar el puerto.
Codex CLI y Claude Code se cablean por MCP stdio local; una entrada `soul-local`
previa y distinta produce `HOLD` en vez de ser sobrescrita. La detección de una
API o listener compatible nunca equivale a consentimiento ni activa egreso
cloud.

El despliegue administrado puede añadir `-TrustCurrentOllama` al instalador.
Ese switch es explícito: liga el listener Ollama vivo al usuario y al hash de
su ejecutable; no confía automáticamente en otros listeners ni proveedores.

## 3. Arrancar el alma de tu máquina

```bash
soul-machine init --model gemma3:1b-it-qat
```

Esto crea, **por única vez y de forma idempotente** (si lo corrés de nuevo,
conserva tu identidad y memorias):

- un **identificador de alma** estable para la máquina,
- una base **SQLite** con la identidad + memorias,
- un **token** de acceso local,
- un **autostart**: el alma arranca sola con tu sesión,
- el **proxy** escuchando en `127.0.0.1:11435`.

En Windows también queda **SOUL Tray** en la bandeja: muestra el estado, permite
prender o detener el proxy y cambiar entre modelos Ollama locales sin alterar
la identidad ni la base de recuerdos. Cerrar el icono no apaga el alma.

## 4. Enchufarle tu app / modelo

Tus aplicaciones (o una interfaz de chat) le hablan al **proxy**
(`http://127.0.0.1:11435/v1`) en vez de a Ollama directo. El proxy le inyecta la
identidad + los recuerdos a **cada** pedido, y por debajo usa el modelo local que
configuraste. El cliente manda el token así:

```
Authorization: Bearer <tu-token>
```

Para apuntar la **misma alma** a otro cerebro local (sin perder nada):

```bash
soul-machine switch-brain \
  --config <ruta a proxy.toml> \
  --kind ollama \
  --base-url http://127.0.0.1:11434/v1 \
  --model otro-modelo-local
```

## 5. Probar que de verdad recuerda (la prueba estrella)

1. Un cliente confiable guarda la conversación con `X-Soul-Remember: true` y
   promueve el hecho revisado con
   `"soul_memory":{"content":"La comida favorita del usuario es ...","importance":8}`.
   La conversación y el hecho son capas separadas: una pregunta nunca se vuelve
   un hecho por sí sola.
2. Cambiá de cerebro con `switch-brain` (o reiniciá la máquina).
3. Volvé a preguntar: **lo sigue sabiendo.** El cerebro cambió; el alma no.

## 6. Comandos útiles

```bash
soul-machine disable-autostart   # el alma deja de arrancar sola, pero se conserva
soul-machine uninstall           # saca la integración por-usuario; identidad, token y memorias QUEDAN
```

Borrar los datos del alma **no** es una operación del instalador: requiere una
eliminación explícita y aparte, a propósito, para que nunca pierdas tu alma por
accidente.

## Límites honestos de v1

- El proxy **solo** escucha en `127.0.0.1` (no accesible desde la red).
- **Requiere token** (`Authorization: Bearer`); sin él, rechaza.
- Acepta `stream=true` de clientes OpenAI-compatible y entrega SSE acotado por
  tamaño. El proxy v1 lo bufferiza antes de exponerlo para poder fallar cerrado ante
  una respuesta excesiva; prioriza seguridad sobre latencia token-a-token.
- Cerebros **remotos deshabilitados** en v1 (solo locales).
