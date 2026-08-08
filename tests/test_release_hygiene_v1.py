from __future__ import annotations

import re
import tomllib
from importlib.metadata import version
from pathlib import Path

import soul_platform


ROOT = Path(__file__).resolve().parents[1]


def test_version_contract_and_packaged_source_layout():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["version"] == soul_platform.__version__ == version("soul-platform")
    assert (ROOT / "src/soul_platform/agency.py").is_file()


def test_release_surface_has_no_seal_internals_or_secret_forms():
    patterns = {
        "home_path": re.compile("/home/" + "dadito"),
        "monorepo": re.compile("proyecto-" + "seal"),
        "internal_role": re.compile("mcp_runtime_(?:" + "ada|alice|jarvis|nexus|fable)"),
        "lan_ip": re.compile(r"\b192\.168\." + r"68\.\d+\b"),
        "credentialed_dsn": re.compile(r"postgres(?:ql)?://[^\s:/]+:[^\s@]+@"),
        "private_key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    }
    files = [ROOT / "README.md", ROOT / "pyproject.toml", ROOT / "installer/soul-install.sh"]
    files.extend(path for path in (ROOT / "src").rglob("*.py") if path.is_file())
    files.extend(path for path in (ROOT / "tests").rglob("*.py") if path.is_file())
    offenders = []
    for path in files:
        content = path.read_text(encoding="utf-8")
        for name, pattern in patterns.items():
            if pattern.search(content):
                offenders.append(f"{name}:{path.relative_to(ROOT)}")
    assert offenders == []
