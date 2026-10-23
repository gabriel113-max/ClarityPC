from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import time
import winreg
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Win32 Constants
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
THREAD_TERMINATE = 0x0001

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

@dataclass
class RemediationActionRecord:
    target_path: str
    action_type: str  # TERMINATED_PROCESS, SCHEDULED_BOOT_DELETE, QUARANTINED, REGISTRY_RESTORED, HOSTS_CLEANED
    success: bool
    message: str
    timestamp: float

class SafeRemediationEngine:
    """Enterprise Safe-Brute-Force Remediation Engine.
    Unlocks active malware files, safely terminates process/thread trees,
    stages quarantine backups, and executes boot-time root deletions via MoveFileExW.
    """

    DEFAULT_QUARANTINE_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ClarityPC" / "quarantine"

    @classmethod
    def terminate_process_safe(cls, pid: int) -> bool:
        """Terminates process and all child threads safely using native Win32 APIs."""
        if os.name != "nt" or pid <= 4:
            return False

        kernel32 = ctypes.windll.kernel32
        h_process = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h_process:
            # Fallback to taskkill /F /PID
            try:
                res = subprocess.run(
                    ["taskkill.exe", "/F", "/PID", str(pid), "/T"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=NO_WINDOW
                )
                return res.returncode == 0
            except Exception:
                return False

        try:
            success = kernel32.TerminateProcess(h_process, 1)
            return bool(success)
        finally:
            kernel32.CloseHandle(h_process)

    @classmethod
    def schedule_boot_deletion(cls, file_path: str | Path) -> bool:
        """Schedules permanent file deletion at next Windows boot via MoveFileExW.
        The Windows NT Kernel Session Manager (smss.exe) executes this before any user-mode code runs.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            return True

        if os.name != "nt":
            try:
                p.unlink(missing_ok=True)
                return True
            except Exception:
                return False

        try:
            kernel32 = ctypes.windll.kernel32
            # MoveFileExW(lpExistingFileName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)
            res = kernel32.MoveFileExW(
                str(p),
                None,
                MOVEFILE_DELAY_UNTIL_REBOOT
            )
            return bool(res)
        except Exception:
            return False

    @classmethod
    def quarantine_file(cls, file_path: str | Path, reason: str = "Suspected Malware") -> RemediationActionRecord:
        """Isolates and encrypts/renames a malicious file into the secure quarantine vault."""
        p = Path(file_path).resolve()
        now = time.time()
        cls.DEFAULT_QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

        if not p.exists():
            return RemediationActionRecord(
                target_path=str(p),
                action_type="QUARANTINED",
                success=False,
                message="El archivo objetivo no existe en el disco.",
                timestamp=now
            )

        vault_name = f"{p.name}_{int(now)}.clarity_quarantine"
        vault_path = cls.DEFAULT_QUARANTINE_DIR / vault_name
        meta_path = cls.DEFAULT_QUARANTINE_DIR / f"{vault_name}.meta.json"

        try:
            # Copy to quarantine vault
            shutil.copy2(p, vault_path)

            # Save metadata
            meta = {
                "original_path": str(p),
                "quarantine_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason,
                "file_size": p.stat().st_size
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            # Attempt immediate deletion
            deleted = False
            try:
                # Remove read-only or hidden attributes if present
                if os.name == "nt":
                    ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x80)  # FILE_ATTRIBUTE_NORMAL
                p.unlink()
                deleted = True
            except (PermissionError, OSError):
                # File is locked by a running process or rootkit -> Schedule boot deletion!
                scheduled = cls.schedule_boot_deletion(p)
                return RemediationActionRecord(
                    target_path=str(p),
                    action_type="SCHEDULED_BOOT_DELETE",
                    success=scheduled,
                    message="Archivo protegido en memoria. Bloqueado en cuarentena y programado para eliminación raíz al reiniciar.",
                    timestamp=now
                )

            return RemediationActionRecord(
                target_path=str(p),
                action_type="QUARANTINED",
                success=True,
                message=f"Archivo aislado en cuarentena de forma exitosa: {vault_name}",
                timestamp=now
            )
        except Exception as e:
            return RemediationActionRecord(
                target_path=str(p),
                action_type="QUARANTINED",
                success=False,
                message=f"Error durante el proceso de cuarentena: {e}",
                timestamp=now
            )

    @classmethod
    def clean_hosts_file(cls) -> RemediationActionRecord:
        """Restores the Windows hosts file to a clean, default Microsoft state."""
        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
        now = time.time()
        if not hosts_path.exists():
            return RemediationActionRecord(str(hosts_path), "HOSTS_CLEANED", True, "Hosts no existe", now)

        clean_hosts_template = (
            "# Copyright (c) 1993-2009 Microsoft Corp.\n"
            "# Archivo Hosts restaurado por ClarityPC Safe Remediation Engine\n"
            "127.0.0.1       localhost\n"
            "::1             localhost\n"
        )

        try:
            # Backup hosts before modifying
            backup_path = cls.DEFAULT_QUARANTINE_DIR / f"hosts_backup_{int(now)}.bak"
            cls.DEFAULT_QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(hosts_path, backup_path)

            # Rewrite clean hosts file
            with open(hosts_path, "w", encoding="utf-8") as f:
                f.write(clean_hosts_template)

            return RemediationActionRecord(
                target_path=str(hosts_path),
                action_type="HOSTS_CLEANED",
                success=True,
                message="Archivo hosts limpiado exitosamente. Se eliminaron desvíos maliciosos a dominios de seguridad.",
                timestamp=now
            )
        except Exception as e:
            return RemediationActionRecord(
                target_path=str(hosts_path),
                action_type="HOSTS_CLEANED",
                success=False,
                message=f"No se pudo limpiar el archivo hosts (requiere permisos elevados): {e}",
                timestamp=now
            )

    @classmethod
    def restore_winlogon_defaults(cls) -> RemediationActionRecord:
        """Restores Winlogon Shell (explorer.exe) and Userinit (userinit.exe,) to defaults."""
        now = time.time()
        winlogon_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, winlogon_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "Shell", 0, winreg.REG_SZ, "explorer.exe")
                winreg.SetValueEx(key, "Userinit", 0, winreg.REG_SZ, r"C:\Windows\system32\userinit.exe,")
            return RemediationActionRecord(
                target_path=winlogon_path,
                action_type="REGISTRY_RESTORED",
                success=True,
                message="Valores de Winlogon (Shell y Userinit) restaurados a los originales de fábrica de Windows.",
                timestamp=now
            )
        except Exception as e:
            return RemediationActionRecord(
                target_path=winlogon_path,
                action_type="REGISTRY_RESTORED",
                success=False,
                message=f"Error al restaurar claves de Winlogon: {e}",
                timestamp=now
            )
