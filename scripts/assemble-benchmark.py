#!/usr/bin/env python3
"""Emit a standalone benchmark for installation or frozen A/B captures."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bench'))
from taygabench.common import benchmark_source
print(benchmark_source(Path(__file__).resolve().parents[1] / 'bench/clat/benchmark-clat.sh'), end='')
