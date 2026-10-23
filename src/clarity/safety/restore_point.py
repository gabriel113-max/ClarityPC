from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Tuple

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

@dataclass(slots=True)
class RestorePointResult:
    created: bool
    message: str
    details: str

class RestorePointManager:
    @staticmethod
    def is_system_restore_enabled() -> bool:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "(Get-ComputerRestorePoint).Count -ge 0"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10, creationflags=NO_WINDOW)
            return res.returncode == 0
        except Exception:
            return False

    @staticmethod
    def create_restore_point(description: str = "ClarityPC SafePoint") -> RestorePointResult:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=45, creationflags=NO_WINDOW)
            if res.returncode == 0:
                return RestorePointResult(
                    created=True,
                    message="Punto de restauración creado con éxito.",
                    details="Restore point created via Windows System Restore (VSS)."
                )
            error_msg = res.stderr.strip() or res.stdout.strip()
            return RestorePointResult(
                created=False,
                message="No se pudo crear el punto de restauración.",
                details=error_msg or "Permission denied or System Restore is disabled on OS drive."
            )
        except subprocess.TimeoutExpired:
            return RestorePointResult(
                created=False,
                message="Tiempo de espera agotado al invocar VSS.",
                details="Timeout expired while creating restore point."
            )
        except Exception as e:
            return RestorePointResult(
                created=False,
                message="Error inesperado al crear punto de restauración.",
                details=str(e)
            )
