from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from ...core.signature import AuthenticodeVerifier
from .hollowing_detector import ProcessHollowingDetector

# Process creation flags & priority
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
THREAD_PRIORITY_LOWEST = -2
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

@dataclass
class ProcessSuspicionRecord:
    pid: int
    name: str
    path: str
    parent_pid: Optional[int]
    parent_name: Optional[str]
    score: int  # 0 to 100
    level: str  # CLEAN, LOW_RISK, SUSPICIOUS, CRITICAL_THREAT
    reasons: List[str]
    is_signed: bool
    signature_status: str
    hollowing_detected: bool
    hollowing_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ProcessTelemetryEngine:
    """Enterprise Process Telemetry & Suspicion Engine.
    Evaluates in-memory execution anomalies, path trust, digital signatures,
    and process hollowing in non-blocking low-priority threads.
    """

    SYSTEM_MASQUERADE_TARGETS = {
        "svchost.exe": [r"c:\windows\system32\svchost.exe", r"c:\windows\syswow64\svchost.exe"],
        "explorer.exe": [r"c:\windows\explorer.exe"],
        "lsass.exe": [r"c:\windows\system32\lsass.exe"],
        "csrss.exe": [r"c:\windows\system32\csrss.exe"],
        "smss.exe": [r"c:\windows\system32\smss.exe"],
        "services.exe": [r"c:\windows\system32\services.exe"],
        "winlogon.exe": [r"c:\windows\system32\winlogon.exe"],
        "taskhostw.exe": [r"c:\windows\system32\taskhostw.exe"],
    }

    @classmethod
    def set_thread_low_priority(cls) -> None:
        """Lowers current thread priority to THREAD_PRIORITY_LOWEST to ensure 0% user stutter."""
        if os.name == "nt":
            try:
                ctypes.windll.kernel32.SetThreadPriority(
                    ctypes.windll.kernel32.GetCurrentThread(),
                    THREAD_PRIORITY_LOWEST
                )
            except Exception:
                pass

    @classmethod
    def evaluate_process(cls, proc: Dict[str, Any]) -> ProcessSuspicionRecord:
        pid = int(proc.get("Id") or proc.get("pid") or 0)
        name = str(proc.get("ProcessName") or proc.get("name") or "")
        path = str(proc.get("Path") or proc.get("path") or "")
        parent_pid = proc.get("ParentId") or proc.get("parent_pid")
        parent_name = proc.get("ParentName") or proc.get("parent_name")

        score = 0
        reasons: List[str] = []

        path_lower = path.lower()
        name_lower = name.lower()

        # 1. Untrusted Directory Heuristics
        user_temp = os.environ.get("TEMP", "").lower()
        local_appdata = os.environ.get("LOCALAPPDATA", "").lower()
        roaming_appdata = os.environ.get("APPDATA", "").lower()
        public_dir = r"c:\users\public"
        program_data = r"c:\programdata"

        if user_temp and user_temp in path_lower:
            score += 40
            reasons.append(f"Ejecución desde directorio temporal (%TEMP%): {path}")
        elif roaming_appdata and roaming_appdata in path_lower:
            score += 25
            reasons.append("Ejecutable ubicado en %APPDATA% Roaming")
        elif local_appdata and (local_appdata + r"\temp") in path_lower:
            score += 40
            reasons.append("Ejecución desde AppData Local Temp")
        elif public_dir in path_lower:
            score += 35
            reasons.append("Ejecución desde C:\\Users\\Public (Vector común de troyanos)")
        elif program_data in path_lower:
            # Check if outside legitimate vendor folders
            trusted_programdata = ["microsoft", "nvidia", "intel", "realtek"]
            if not any(t in path_lower for t in trusted_programdata):
                score += 20
                reasons.append("Ejecución en C:\\ProgramData (ruta no verificada)")

        # 2. Masquerading / Fake System Process Heuristics
        exe_file = Path(path).name.lower()
        if exe_file in cls.SYSTEM_MASQUERADE_TARGETS:
            allowed = [p.lower() for p in cls.SYSTEM_MASQUERADE_TARGETS[exe_file]]
            if path_lower not in allowed:
                score += 55
                reasons.append(
                    f"Falsificación crítica de binario del sistema: '{exe_file}' corriendo desde ruta no autorizada ({path})"
                )

        # 3. Authenticode Digital Signature Verification
        is_signed = False
        sig_status = "NOT_EVALUATED"
        if path and os.path.exists(path):
            sig = AuthenticodeVerifier.verify_file(path)
            is_signed = sig["is_signed"]
            sig_status = sig["status"]

            if is_signed:
                # Valid Microsoft or trusted certificate reduces false positive score
                score = max(0, score - 20)
            else:
                if "UNTRUSTED" in sig_status or "REVOKED" in sig_status:
                    score += 45
                    reasons.append(f"Firma digital revocada o certificado no confiable ({sig_status})")
                else:
                    if score > 0:  # If already suspicious
                        score += 25
                        reasons.append("Binario sin firma digital Authenticode")

        # 4. Process Hollowing & Injected Memory Inspection
        hollowing_detected = False
        hollowing_reasons: List[str] = []
        if pid > 4:
            audit = ProcessHollowingDetector.audit_process(
                pid=pid,
                process_name=name,
                parent_pid=parent_pid,
                parent_name=parent_name
            )
            if audit.is_suspicious:
                hollowing_detected = True
                hollowing_reasons = audit.reasons
                score += int(audit.hollowing_confidence * 50)
                reasons.extend(audit.reasons)

        score = max(0, min(100, score))

        if score >= 70:
            level = "CRITICAL_THREAT"
        elif score >= 45:
            level = "SUSPICIOUS"
        elif score >= 20:
            level = "LOW_RISK"
        else:
            level = "CLEAN"

        return ProcessSuspicionRecord(
            pid=pid,
            name=name,
            path=path,
            parent_pid=parent_pid,
            parent_name=parent_name,
            score=score,
            level=level,
            reasons=reasons,
            is_signed=is_signed,
            signature_status=sig_status,
            hollowing_detected=hollowing_detected,
            hollowing_reasons=hollowing_reasons,
        )

    @classmethod
    def scan_all_processes(cls, max_processes: int = 150) -> List[ProcessSuspicionRecord]:
        """Runs a complete low-priority audit of all active system processes."""
        cls.set_thread_low_priority()
        records: List[ProcessSuspicionRecord] = []

        if os.name != "nt":
            return records

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, ParentProcessId | ConvertTo-Json"
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=12,
                creationflags=NO_WINDOW
            )
            import json
            procs = json.loads(res.stdout)
            if not isinstance(procs, list):
                procs = [procs] if procs else []

            # Map PID to Name for parent lookups
            pid_to_name = {p.get("ProcessId"): p.get("Name") for p in procs if p.get("ProcessId")}

            for p in procs[:max_processes]:
                pid = p.get("ProcessId")
                name = p.get("Name") or ""
                path = p.get("ExecutablePath") or ""
                ppid = p.get("ParentProcessId")
                pname = pid_to_name.get(ppid)

                rec = cls.evaluate_process({
                    "Id": pid,
                    "ProcessName": name,
                    "Path": path,
                    "ParentId": ppid,
                    "ParentName": pname
                })
                records.append(rec)

        except Exception:
            pass

        # Sort with most suspicious processes on top
        records.sort(key=lambda r: r.score, reverse=True)
        return records
