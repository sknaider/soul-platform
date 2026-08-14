"""SOUL Platform command line."""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "proxy":
        proxy = argparse.ArgumentParser(prog="soul-platform proxy")
        proxy.add_argument("--config", required=True)
        args = proxy.parse_args(sys.argv[2:])
        from soul_platform.proxy import ProxySettings, run_proxy

        settings = ProxySettings.from_toml(args.config)
        run_proxy(settings)
        return
    parser = argparse.ArgumentParser(prog="soul-platform")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()
    if args.version:
        from soul_platform import __version__

        print(__version__)
        return
    parser.error("use 'soul-platform proxy --config <file>'; the unauthenticated legacy --serve route was removed")


if __name__ == "__main__":
    main()
