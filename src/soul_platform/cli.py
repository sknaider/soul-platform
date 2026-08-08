"""SOUL Platform command line."""

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="soul-platform")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8890)
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    if args.version:
        from soul_platform import __version__

        print(__version__)
        return
    if not args.serve:
        parser.error("use --serve to start the local API")
    import uvicorn

    uvicorn.run("soul_platform.api:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
