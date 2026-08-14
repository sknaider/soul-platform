"""Test the current source tree, never a stale installed wheel."""

from __future__ import annotations

import sys
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "src"
source_text = str(SOURCE)
if source_text not in sys.path:
    sys.path.insert(0, source_text)
