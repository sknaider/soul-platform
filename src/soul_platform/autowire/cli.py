from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from soul_platform.autowire.manager import AutoWireManager
from soul_platform.autowire.discovery import discover_ollama
from soul_platform.autowire.service import install_autowire_autostart
from soul_platform.bootstrap import default_root
from soul_platform.proxy import ProxySettings
from soul_platform.runtime_attestation import trust_current_ollama


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soul-autowire")
    parser.add_argument("--root", type=Path, default=default_root())
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("reconcile")
    actions.add_parser("status")
    actions.add_parser("trust-current-ollama")
    install = actions.add_parser("install-autostart")
    install.add_argument("--interval", type=float, default=30.0)
    watch = actions.add_parser("watch")
    watch.add_argument("--interval", type=float, default=30.0)
    activate = actions.add_parser("activate")
    activate.add_argument("provider_id")
    activate.add_argument("--expected-generation", type=int, required=True)
    args = parser.parse_args(argv)
    manager = AutoWireManager(args.root)
    if args.action == "reconcile":
        payload = manager.reconcile()
    elif args.action == "status":
        payload = manager.status()
    elif args.action == "activate":
        payload = manager.activate(
            args.provider_id, expected_generation=args.expected_generation
        )
    elif args.action == "trust-current-ollama":
        if not discover_ollama():
            raise RuntimeError("Ollama native endpoint has no usable chat model")
        settings = ProxySettings.from_toml(args.root / "proxy.toml")
        payload = trust_current_ollama(
            args.root.resolve(), machine_soul_id=settings.machine_soul_id
        )
    elif args.action == "install-autostart":
        target = install_autowire_autostart(
            root=args.root, interval=args.interval
        )
        payload = {"installed": True, "target": str(target)}
    else:
        if not 5 <= args.interval <= 3600:
            parser.error("watch interval must be between 5 and 3600 seconds")
        while True:
            try:
                manager.reconcile()
            except Exception:
                # Fail closed: discovery failures never alter the active brain.
                pass
            time.sleep(args.interval)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
