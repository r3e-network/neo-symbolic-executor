from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"


def configure_repo_root() -> Path:
    for path in (SRC_ROOT, REPO_ROOT):
        root = str(path)
        if root not in sys.path:
            sys.path.insert(0, root)
    return REPO_ROOT
