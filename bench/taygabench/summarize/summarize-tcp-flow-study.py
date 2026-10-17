#!/usr/bin/env python3
"""Compatibility entrypoint; implementation lives in an importable module."""
from pathlib import Path
import runpy
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
globals().update(runpy.run_path(str(Path(__file__).with_name('summarize_tcp_flow_study.py')),
                              run_name='__main__' if __name__ == '__main__' else __name__))
