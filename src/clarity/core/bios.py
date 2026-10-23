from __future__ import annotations

import os
import subprocess
from typing import Dict, Any, Optional
from .base import BaseDiagnosticEngine, DiagnosticItem, DiagnosticReport, Severity

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class BiosDiagnosticEngine(BaseDiagnosticEngine):
    @property
    def name(self) -> str:
        return "bios"

    @property
    def display_name(self) -> str:
        return "BIOS & Firmware UEFI"

    def run(self) -> DiagnosticReport:
        report = DiagnosticReport(engine_name=self.name)
        bios_info = self._get_bios_wmi()
        secure_boot = self._check_secure_boot()

        # Item 1: BIOS Version and Age
        rel_date = bios_info.get("ReleaseDate", "Desconocido")
        version = bios_info.get("SMBIOSBIOSVersion", "Desconocido")
        mfg = bios_info.get("Manufacturer", "Desconocido")

        report.items.append(DiagnosticItem(
            id="bios_firmware_info",
            category="Firmware",
            title=f"BIOS {mfg} ({version})",
            severity=Severity.INFO,
            summary=f"Versión: {version} | Fecha: {rel_date}",
            details=f"Fabricante: {mfg}\nVersión SMBIOS: {version}\nFecha de compilación: {rel_date}",
            metrics={"version": version, "manufacturer": mfg, "date": rel_date}
        ))

        # Item 2: Secure Boot Status
        sb_severity = Severity.OK if secure_boot else Severity.WARNING
        report.items.append(DiagnosticItem(
            id="bios_secure_boot",
            category="Seguridad",
            title="Arranque Seguro (Secure Boot)",
            severity=sb_severity,
            summary="Activado" if secure_boot else "Desactivado",
            details="Secure Boot protege contra rootkits y bootkits a nivel de firmware pre-arranque.",
            recommendation=None if secure_boot else "Activa Secure Boot en la BIOS si juegas a títulos con Vanguard/BattlEye o usas Windows 11."
        ))

        return report

    @staticmethod
    def reboot_to_uefi() -> bool:
        """Executes native Windows order to restart directly into UEFI Firmware settings."""
        try:
            res = subprocess.run(["shutdown.exe", "/r", "/fw", "/t", "0"], capture_output=True, text=True, errors="replace", creationflags=NO_WINDOW)
            return res.returncode == 0
        except Exception:
            return False

    def _get_bios_wmi(self) -> Dict[str, str]:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            import json
            data = json.loads(res.stdout)
            return {k: str(v) for k, v in data.items()}
        except Exception:
            return {}

    def _check_secure_boot(self) -> bool:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Confirm-SecureBootUEFI"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5, creationflags=NO_WINDOW)
            return "true" in res.stdout.strip().lower()
        except Exception:
            return False
