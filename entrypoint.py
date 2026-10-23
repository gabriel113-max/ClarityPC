#!/usr/bin/env python3
"""ClarityPC Entrypoint for Standalone Executable and Direct Execution.
Ensures clarity package hierarchy is cleanly imported with full relative resolution.
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

# Redirect stdout and stderr if None (prevents AttributeError in --windowed PyInstaller)
if sys.stderr is None:
    sys.stderr = io.StringIO()
if sys.stdout is None:
    sys.stdout = io.StringIO()

# Resolve base directories
if getattr(sys, "frozen", False):
    base_dir = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    base_dir = Path(__file__).resolve().parent

src_dir = base_dir / "src"
if src_dir.exists() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
if str(base_dir) not in sys.path:
    sys.path.insert(0, str(base_dir))

from clarity.ui.gui.app import launch_gui

if __name__ == "__main__":
    launch_gui()
