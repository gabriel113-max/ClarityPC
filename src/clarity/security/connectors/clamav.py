from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

@dataclass
class ClamAVScanResult:
    target_path: str
    is_infected: bool
    virus_name: Optional[str]
    engine_available: bool
    scan_time_sec: float
    message: str

class ClamAVConnector:
    """Open-Source Connector for local ClamAV Antivirus Engine.
    Executes signatures scan asynchronously with lowest CPU footprint.
    """

    KNOWN_PATHS = [
        Path(r"C:\Program Files\ClamAV\clamscan.exe"),
        Path(r"C:\Program Files (x86)\ClamAV\clamscan.exe"),
        Path(r"C:\ProgramData\chocolatey\bin\clamscan.exe"),
    ]

    @classmethod
    def get_binary_path(cls) -> Optional[Path]:
        for p in cls.KNOWN_PATHS:
            if p.exists():
                return p
        which = shutil.which("clamscan")
        return Path(which) if which else None

    @classmethod
    def is_installed(cls) -> bool:
        return cls.get_binary_path() is not None

    @classmethod
    def scan_file(cls, file_path: str | Path, timeout_sec: int = 30) -> ClamAVScanResult:
        p = Path(file_path).resolve()
        bin_path = cls.get_binary_path()

        if not bin_path:
            return ClamAVScanResult(
                target_path=str(p),
                is_infected=False,
                virus_name=None,
                engine_available=False,
                scan_time_sec=0.0,
                message="Motor ClamAV no encontrado. Puedes instalarlo con 'winget install ClamAV.ClamAV'."
            )

        if not p.exists():
            return ClamAVScanResult(
                target_path=str(p),
                is_infected=False,
                virus_name=None,
                engine_available=True,
                scan_time_sec=0.0,
                message="Archivo objetivo no existe."
            )

        import time
        t0 = time.perf_counter()
        try:
            # Run clamscan with low CPU priority
            proc = subprocess.run(
                [str(bin_path), "--no-summary", "--stdout", str(p)],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                creationflags=NO_WINDOW
            )
            elapsed = time.perf_counter() - t0

            # Exit code 0: No virus found
            # Exit code 1: Virus found
            output = proc.stdout.strip()
            if proc.returncode == 1 or "FOUND" in output:
                # Example output: "C:\path\malware.exe: Win.Test.EICAR_HDB-1 FOUND"
                virus_name = "Desconocido"
                if "FOUND" in output and ":" in output:
                    parts = output.split(":")
                    if len(parts) >= 2:
                        virus_name = parts[1].replace("FOUND", "").strip()

                return ClamAVScanResult(
                    target_path=str(p),
                    is_infected=True,
                    virus_name=virus_name,
                    engine_available=True,
                    scan_time_sec=round(elapsed, 2),
                    message=f"¡Amenaza detectada por ClamAV: {virus_name}!"
                )
            else:
                return ClamAVScanResult(
                    target_path=str(p),
                    is_infected=False,
                    virus_name=None,
                    engine_available=True,
                    scan_time_sec=round(elapsed, 2),
                    message="Archivo analizado sin coincidencias en base de firmas de ClamAV."
                )

        except Exception as e:
            elapsed = time.perf_counter() - t0
            return ClamAVScanResult(
                target_path=str(p),
                is_infected=False,
                virus_name=None,
                engine_available=True,
                scan_time_sec=round(elapsed, 2),
                message=f"Error al invocar ClamAV: {e}"
            )
