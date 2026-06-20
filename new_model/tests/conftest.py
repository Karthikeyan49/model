"""Make the baseline/retrieval/engine packages importable from tests."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
for sub in ("baseline", "retrieval", "engine", "training", "tools", "advanced"):
    sys.path.insert(0, os.path.join(ROOT, sub))
