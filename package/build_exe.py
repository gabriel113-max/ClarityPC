#!/usr/bin/env python3
"""Build script for ClarityPC Standalone Windows Executable using PyInstaller.
Embeds UAC manifest with requireAdministrator and all web UI assets.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"
    web_dir = src_dir / "clarity" / "ui" / "gui" / "web"
    manifest_file = repo_root / "package" / "clarity.exe.manifest"
    dist_dir = repo_root / "dist"
    build_dir = repo_root / "build"

    print("==================================================")
    print(" ClarityPC — Compilación de Binario Nativo Windows ")
    print("==================================================")

    if not web_dir.exists():
        print(f"Error: No se encontró el directorio web: {web_dir}")
        sys.exit(1)

    # PyInstaller arguments
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name=ClarityPC",
        "--onedir",
        "--windowed", # No console window on launch
        f"--add-data={web_dir};clarity/ui/gui/web",
        f"--manifest={manifest_file}",
        f"--paths={src_dir}",
        "--collect-all=clarity",
        str(repo_root / "entrypoint.py")
    ]

    print("Ejecutando comando PyInstaller:")
    print(" ".join(cmd))
    print("--------------------------------------------------")

    res = subprocess.run(cmd, cwd=str(repo_root))
    if res.returncode == 0:
        exe_path = dist_dir / "ClarityPC" / "ClarityPC.exe"
        print("--------------------------------------------------")
        print("¡COMPILACIÓN EXITOSA!")
        print(f"Ejecutable generado en: {exe_path}")
        print("Para generar el instalador final (.exe), compila package/installer.iss con Inno Setup.")
    else:
        print(f"Error en la compilación (código {res.returncode})")
        sys.exit(res.returncode)

if __name__ == "__main__":
    main()
