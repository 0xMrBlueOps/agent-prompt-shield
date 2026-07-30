"""Compatibility entry point for the repository's benchmark regression gate."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

BENCHMARK_RUNNER = Path(__file__).resolve().parents[1] / "benchmarks" / "run_benchmarks.py"

if __name__ == "__main__":
    sys.argv = [str(BENCHMARK_RUNNER), "--check"]
    runpy.run_path(str(BENCHMARK_RUNNER), run_name="__main__")
