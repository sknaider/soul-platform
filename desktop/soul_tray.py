#!/usr/bin/env python3
"""Compatibility launcher for the package-native SOUL Tray.

The implementation lives in :mod:`soul_platform.tray` so the wheel, installer,
tests and ``soul-tray`` console command all execute the same reviewed code.
"""

from soul_platform.tray import main


if __name__ == "__main__":
    raise SystemExit(main())
