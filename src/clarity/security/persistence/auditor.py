from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import winreg
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from ...core.signature import AuthenticodeVerifier

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

@dataclass
class PersistenceItem:
    location_type: str  # REGISTRY, SCHEDULED_TASK, WINLOGON, IFEO, HOSTS
    name: str
    target: str
    is_suspicious: bool
    risk_level: str     # LOW, MEDIUM, CRITICAL
    reason: str
    is_signed: bool
    signature_status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class PersistenceAuditor:
    """Comprehensive Windows Persistence Hunter.
    Audits Run/RunOnce keys, Winlogon Shell/Userinit hijacking,
    IFEO debugger injection, Scheduled Tasks, and hosts file redirects.
    """

    HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")

    @classmethod
    def audit_all(cls) -> List[PersistenceItem]:
        items: List[PersistenceItem] = []
        items.extend(cls._audit_registry_run())
        items.extend(cls._audit_winlogon_hijacks())
        items.extend(cls._audit_ifeo_hijacks())
        items.extend(cls._audit_scheduled_tasks())
        items.extend(cls._audit_hosts_file())
        return items

    @classmethod
    def _audit_registry_run(cls) -> List[PersistenceItem]:
        items: List[PersistenceItem] = []
        hives = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        ]

        for root, subkey, label in hives:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, val, _ = winreg.EnumValue(key, i)
                        val_str = str(val).strip('"').strip()
                        raw_path = val_str.split(" ")[0].strip('"')

                        # Analyze target
                        is_suspicious = False
                        reason = "Entrada estándar de inicio"
                        risk_level = "LOW"

                        val_lower = val_str.lower()
                        if "temp" in val_lower or "appdata" in val_lower or "public" in val_lower:
                            is_suspicious = True
                            risk_level = "CRITICAL"
                            reason = f"Ejecutable persistente alojado en directorio no confiable ({val_str})"
                        elif "powershell" in val_lower or "cmd.exe" in val_lower or "wscript" in val_lower or "mshta" in val_lower:
                            is_suspicious = True
                            risk_level = "CRITICAL"
                            reason = f"Intérprete de scripts ejecutándose al inicio: {val_str}"

                        sig = AuthenticodeVerifier.verify_file(raw_path) if os.path.exists(raw_path) else {"is_signed": False, "status": "FILE_NOT_FOUND"}
                        if is_suspicious and not sig["is_signed"]:
                            reason += " (Sin firma digital válida)"

                        items.append(PersistenceItem(
                            location_type="REGISTRY",
                            name=f"{label}: {name}",
                            target=val_str,
                            is_suspicious=is_suspicious,
                            risk_level=risk_level,
                            reason=reason,
                            is_signed=sig["is_signed"],
                            signature_status=sig["status"]
                        ))
            except Exception:
                pass
        return items

    @classmethod
    def _audit_winlogon_hijacks(cls) -> List[PersistenceItem]:
        """Audits Userinit and Shell keys in Winlogon hive for persistence hijackers."""
        items: List[PersistenceItem] = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                0,
                winreg.KEY_READ
            ) as key:
                # 1. Shell (Expected: explorer.exe)
                try:
                    shell_val, _ = winreg.QueryValueEx(key, "Shell")
                    shell_str = str(shell_val).strip()
                    is_bad = shell_str.lower() != "explorer.exe"
                    items.append(PersistenceItem(
                        location_type="WINLOGON",
                        name="Winlogon Shell",
                        target=shell_str,
                        is_suspicious=is_bad,
                        risk_level="CRITICAL" if is_bad else "LOW",
                        reason=f"Secuestro de shell detectado ({shell_str})" if is_bad else "Shell legítimo de Windows (explorer.exe)",
                        is_signed=True,
                        signature_status="VALID_TRUSTED"
                    ))
                except Exception:
                    pass

                # 2. Userinit (Expected: C:\Windows\system32\userinit.exe,)
                try:
                    userinit_val, _ = winreg.QueryValueEx(key, "Userinit")
                    userinit_str = str(userinit_val).strip()
                    is_bad = "userinit.exe" not in userinit_str.lower() or len(userinit_str.split(",")) > 2
                    items.append(PersistenceItem(
                        location_type="WINLOGON",
                        name="Winlogon Userinit",
                        target=userinit_str,
                        is_suspicious=is_bad,
                        risk_level="CRITICAL" if is_bad else "LOW",
                        reason=f"Cadena Userinit alterada con payload secundario: {userinit_str}" if is_bad else "Userinit legítimo del sistema",
                        is_signed=True,
                        signature_status="VALID_TRUSTED"
                    ))
                except Exception:
                    pass
        except Exception:
            pass
        return items

    @classmethod
    def _audit_ifeo_hijacks(cls) -> List[PersistenceItem]:
        """Audits Image File Execution Options for 'Debugger' hijacks."""
        items: List[PersistenceItem] = []
        ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    app_name = winreg.EnumKey(key, i)
                    try:
                        with winreg.OpenKey(key, app_name, 0, winreg.KEY_READ) as sub:
                            debugger_val, _ = winreg.QueryValueEx(sub, "Debugger")
                            items.append(PersistenceItem(
                                location_type="IFEO",
                                name=f"IFEO Hijack: {app_name}",
                                target=str(debugger_val),
                                is_suspicious=True,
                                risk_level="CRITICAL",
                                reason=f"Secuestro IFEO activo: al abrir '{app_name}' se ejecuta '{debugger_val}'",
                                is_signed=False,
                                signature_status="UNKNOWN"
                            ))
                    except FileNotFoundError:
                        pass
        except Exception:
            pass
        return items

    @classmethod
    def _audit_scheduled_tasks(cls) -> List[PersistenceItem]:
        """Scans Scheduled Tasks checking for missing author, script wrappers, or user-dir paths."""
        items: List[PersistenceItem] = []
        if os.name != "nt":
            return items

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "@((Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, Author, @{Name='Action';Expression={$_.Actions.Execute + ' ' + $_.Actions.Arguments}})) | ConvertTo-Json"
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=12, creationflags=NO_WINDOW)
            tasks = json.loads(res.stdout)
            if not isinstance(tasks, list):
                tasks = [tasks] if tasks else []

            for t in tasks:
                tname = str(t.get("TaskName") or "")
                action = str(t.get("Action") or "").strip()
                author = str(t.get("Author") or "").strip()

                is_suspicious = False
                risk = "LOW"
                reason = "Tarea programada registrada"

                act_lower = action.lower()
                if "temp" in act_lower or "appdata" in act_lower or "public" in act_lower:
                    is_suspicious = True
                    risk = "CRITICAL"
                    reason = f"Tarea programada apunta a ruta no confiable: {action}"
                elif ("powershell" in act_lower and "-enc" in act_lower) or "mshta" in act_lower or "wscript" in act_lower:
                    is_suspicious = True
                    risk = "CRITICAL"
                    reason = f"Ejecución de script ofuscado o MSHTA: {action}"
                elif not author and ("\\" in tname or ".exe" in act_lower):
                    if not any(k in act_lower for k in ["microsoft", "system32", "program files"]):
                        is_suspicious = True
                        risk = "MEDIUM"
                        reason = f"Tarea sin autor verificado ejecutando binario de terceros: {action}"

                if is_suspicious:
                    raw_bin = action.split(" ")[0].strip('"')
                    sig = AuthenticodeVerifier.verify_file(raw_bin) if os.path.exists(raw_bin) else {"is_signed": False, "status": "FILE_NOT_FOUND"}

                    items.append(PersistenceItem(
                        location_type="SCHEDULED_TASK",
                        name=f"Tarea: {tname}",
                        target=action,
                        is_suspicious=True,
                        risk_level=risk,
                        reason=reason,
                        is_signed=sig["is_signed"],
                        signature_status=sig["status"]
                    ))

        except Exception:
            pass
        return items

    @classmethod
    def _audit_hosts_file(cls) -> List[PersistenceItem]:
        """Audits Windows hosts file looking for malicious DNS sinkholes or security blockades."""
        items: List[PersistenceItem] = []
        if not cls.HOSTS_PATH.exists():
            return items

        security_domains = [
            "virustotal.com", "microsoft.com", "update.microsoft.com",
            "kaspersky.com", "bitdefender.com", "malwarebytes.com",
            "symantec.com", "eset.com", "avast.com", "clamav.net"
        ]

        try:
            with open(cls.HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue

                    parts = stripped.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        domain = parts[1].lower()

                        if any(sd in domain for sd in security_domains):
                            items.append(PersistenceItem(
                                location_type="HOSTS",
                                name=f"Bloqueo en Hosts: {domain}",
                                target=f"{ip} -> {domain}",
                                is_suspicious=True,
                                risk_level="CRITICAL",
                                reason=f"El malware está desviando el dominio de seguridad '{domain}' hacia {ip}",
                                is_signed=True,
                                signature_status="SYSTEM_FILE"
                            ))
        except Exception:
            pass
        return items
