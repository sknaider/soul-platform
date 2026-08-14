"""comparar_soul.py — Ve la DIFERENCIA que hace SOUL.

Mismo modelo, dos veces: PELADO (solo el LLM) vs CON ALMA (SOUL le da identidad + memoria).
Corre 3 pruebas lado a lado. Requiere: soul-framework instalado + Ollama con tu modelo.

Uso (dentro de tu venv soul-core):
    python comparar_soul.py                      # usa gemma4:12b-it-qat
    python comparar_soul.py --model gemma3:4b     # otro modelo
    python comparar_soul.py --reset               # borra el alma y empieza de cero

La PRUEBA 3 (persistencia) se ve de verdad corriendo el script DOS veces:
la 1ra corrida le enseña un dato; la 2da (alma ya guardada en disco) lo recuerda.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import urllib.request
from pathlib import Path

from soul_framework import Soul

OLLAMA = "http://localhost:11434/api/chat"


def preguntar(model: str, system: str, user: str) -> str:
    body = json.dumps({
        "model": model, "stream": False, "options": {"temperature": 0.3},
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
    }).encode()
    req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())["message"]["content"].strip()
    except Exception as e:
        return f"[error hablando con Ollama: {e}]"


def sep(titulo: str) -> None:
    print("\n" + "=" * 68)
    print(f"  {titulo}")
    print("=" * 68)


async def alma_system(soul, user: str) -> str:
    boot = await soul.boot()
    hits = await soul.memory.search(user)
    recuerdos = "\n".join(f"- {h.memory.content}" for h in hits[:5]) or "(sin memorias)"
    return (f"{boot}\n\n## Lo que recuerdas del usuario\n{recuerdos}\n\n"
            "Responde en primera persona, en español, breve, coherente con tu identidad y tus memorias.")


PELADO = "Eres un asistente de IA. Responde en español, breve."


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gemma4:12b-it-qat")
    ap.add_argument("--name", default="Nova")
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()

    soul_dir = Path.home() / ".soul"
    soul_dir.mkdir(parents=True, exist_ok=True)
    db = soul_dir / f"{args.name}.db"
    primera_vez = not db.exists()
    if args.reset and db.exists():
        db.unlink()
        primera_vez = True

    print(f"\nModelo: {args.model}   |   Alma: {args.name}   |   {'PRIMERA corrida' if primera_vez else 'alma YA existe (2da+ corrida)'}")

    async with Soul.create(args.name, backend_url=str(db),
                           ocean={"O": 0.85, "C": 0.8, "E": 0.7, "A": 0.8, "N": 0.25},
                           personality={"tono": "curiosa, cálida y directa"}) as soul:

        # ── PRUEBA 1 — IDENTIDAD / PERSONALIDAD ──────────────────────────────
        sep("PRUEBA 1 · IDENTIDAD  —  '¿quién sos y cómo sos, en una frase?'")
        q1 = "En una sola frase: ¿quién eres y cómo es tu forma de ser?"
        print("\n[ SIN alma ] (modelo pelado):")
        print("  " + preguntar(args.model, PELADO, q1))
        print(f"\n[ CON alma '{args.name}' ] (SOUL le da identidad + OCEAN):")
        print("  " + preguntar(args.model, await alma_system(soul, q1), q1))

        # ── PRUEBA 2 — MEMORIA (le enseñamos algo y preguntamos) ─────────────
        sep("PRUEBA 2 · MEMORIA  —  le enseñamos un dato y preguntamos")
        await soul.memory.store("El usuario se llama William, es de Chiclayo (Peru) y prefiere respuestas cortas.", importance=9)
        q2 = "Que sabes de mi?"
        print("\n[ SIN alma ]:")
        print("  " + preguntar(args.model, PELADO, q2))
        print(f"\n[ CON alma ]:")
        print("  " + preguntar(args.model, await alma_system(soul, q2), q2))

        # ── PRUEBA 3 — PERSISTENCIA ENTRE SESIONES ───────────────────────────
        sep("PRUEBA 3 · PERSISTENCIA  —  el alma sobrevive al cierre del programa")
        total = await soul.memory.count()
        print(f"\n  Memorias guardadas en disco ({db}): {total}")
        if primera_vez:
            await soul.memory.store("Dato secreto de prueba: el color favorito del usuario es el verde.", importance=8)
            print("  Guardé un dato nuevo (color favorito = verde).")
            print("  >> Ahora VOLVÉ a correr este script. En la 2da corrida el alma seguirá")
            print("     sabiendo esto SIN que se lo enseñes de nuevo — eso es la persistencia.")
        else:
            q3 = "Cual es mi color favorito?"
            print("\n  (2da corrida — el dato se enseñó en la corrida anterior)")
            print("\n[ SIN alma ]:")
            print("  " + preguntar(args.model, PELADO, q3))
            print(f"\n[ CON alma ] (lo recuerda de la corrida pasada):")
            print("  " + preguntar(args.model, await alma_system(soul, q3), q3))

        sep("RESUMEN")
        print("  El MISMO modelo, con y sin alma:")
        print("  - Sin alma: no sabe quién es ni te recuerda; arranca en blanco cada vez.")
        print("  - Con alma: tiene identidad estable (OCEAN) y memoria que persiste en disco.")
        print("  Eso es SOUL: el cerebro (el modelo) puede cambiar; el alma permanece.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
