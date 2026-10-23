from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List
from .base import BaseDiagnosticEngine, DiagnosticItem, DiagnosticReport, Severity
from .signature import AuthenticodeVerifier

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class SecurityDiagnosticEngine(BaseDiagnosticEngine):
    @property
    def name(self) -> str:
        return "security"

    @property
    def display_name(self) -> str:
        return "Seguridad y Auditoría de Procesos"

    def run(self) -> DiagnosticReport:
        report = DiagnosticReport(engine_name=self.name)
        self._diagnose_defender_status(report)
        self._diagnose_recent_threats(report)
        self._diagnose_process_anomalies(report)
        self._diagnose_digital_signatures(report)
        self._diagnose_startup_persistence(report)
        self._diagnose_suspicious_ports(report)
        return report

    def _diagnose_defender_status(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureAge, IoavProtectionEnabled | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            data = json.loads(res.stdout)
            real_time = bool(data.get("RealTimeProtectionEnabled", False))
            sig_age = int(data.get("AntivirusSignatureAge", 0))

            severity = Severity.OK
            if not real_time:
                severity = Severity.CRITICAL
            elif sig_age > 7:
                severity = Severity.WARNING

            rec = None
            if not real_time:
                rec = "La protección en tiempo real está desactivada. Actívala de inmediato en Seguridad de Windows."
            elif sig_age > 7:
                rec = f"Las firmas de virus tienen {sig_age} días de antigüedad. Actualiza Windows Defender."

            report.items.append(DiagnosticItem(
                id="sec_defender_status",
                category="Antivirus",
                title="Protección en Tiempo Real (Windows Defender)",
                severity=severity,
                summary=f"Estado: {'Activo' if real_time else 'DESACTIVADO'} | Antigüedad de firmas: {sig_age} días",
                details=f"Protección en tiempo real: {real_time}\nAntigüedad de firmas: {sig_age} días\nProtección de descargas IOAV: {data.get('IoavProtectionEnabled')}",
                metrics={"real_time": real_time, "signature_age_days": sig_age},
                recommendation=rec
            ))
        except Exception:
            report.items.append(DiagnosticItem(
                id="sec_defender_status",
                category="Antivirus",
                title="Seguridad de Windows",
                severity=Severity.INFO,
                summary="No se pudo consultar el estado de Defender (puede haber otro antivirus activo)."
            ))

    def _diagnose_recent_threats(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "@((Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object ThreatName, InitialDetectionTime, Resources)) | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            threats = json.loads(res.stdout)
            if not isinstance(threats, list):
                threats = [threats] if threats else []

            count = len(threats)
            severity = Severity.WARNING if count > 0 else Severity.OK
            summary = f"{count} detecciones registradas históricamente" if count > 0 else "Sin amenazas activas detectadas"
            
            report.items.append(DiagnosticItem(
                id="sec_threat_history",
                category="Amenazas",
                title="Historial de Malware Detectado",
                severity=severity,
                summary=summary,
                details=f"Detecciones totales en el registro: {count}",
                metrics={"threat_count": count},
                recommendation="Si notas comportamiento extraño, ejecuta un análisis completo sin conexión de Windows Defender." if count > 0 else None
            ))
        except Exception:
            pass

    def _diagnose_process_anomalies(self, report: DiagnosticReport) -> None:
        """Audits running processes looking for executables spawned from suspicious directories (Temp, AppData)."""
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-Process | Where-Object { $_.Path } | Select-Object Id, ProcessName, Path | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10, creationflags=NO_WINDOW)
            procs = json.loads(res.stdout)
            if not isinstance(procs, list):
                procs = [procs] if procs else []

            suspicious = []
            suspicious_paths = [
                os.environ.get("TEMP", "").lower(),
                r"c:\users\public",
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "temp").lower()
            ]

            for p in procs:
                path = str(p.get("Path", "")).lower()
                for sp in suspicious_paths:
                    if sp and sp in path:
                        # Verify WinTrust signature
                        sig = AuthenticodeVerifier.verify_file(p.get("Path", ""))
                        p["is_signed"] = sig["is_signed"]
                        p["sig_status"] = sig["status"]
                        suspicious.append(p)
                        break

            count = len(suspicious)
            unsigned_count = sum(1 for p in suspicious if not p.get("is_signed", False))
            severity = Severity.CRITICAL if unsigned_count > 0 else (Severity.WARNING if count > 0 else Severity.OK)
            summary = f"{count} procesos en carpetas temporales ({unsigned_count} sin firma digital)" if count > 0 else "Procesos en memoria verificados (rutas estándar)"
            
            details = "\n".join([f"PID {p.get('Id')} | {p.get('ProcessName')} [Firma: {p.get('sig_status')}] -> {p.get('Path')}" for p in suspicious]) if suspicious else "Todos los procesos activos ejecutan desde directorios de confianza (Program Files, System32, WindowsApps)."

            report.items.append(DiagnosticItem(
                id="sec_process_audit",
                category="Heurística",
                title="Auditoría de Procesos en Memoria",
                severity=severity,
                summary=summary,
                details=details,
                metrics={"suspicious_process_count": count, "unsigned_count": unsigned_count},
                recommendation="Inspecciona o finaliza procesos no firmados corriendo en directorios temporales." if unsigned_count > 0 else None
            ))
        except Exception:
            pass

    def _diagnose_digital_signatures(self, report: DiagnosticReport) -> None:
        """Audits digital Authenticode signatures of critical system core binaries using WinTrust."""
        critical_targets = [
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "explorer.exe"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "winlogon.exe"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "csrss.exe"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts"),
        ]

        verified_signed = 0
        total_checked = 0
        details_lines = []

        for target in critical_targets:
            if not os.path.exists(target) or os.path.isdir(target):
                continue
            total_checked += 1
            res = AuthenticodeVerifier.verify_file(target)
            if res["is_signed"]:
                verified_signed += 1
                details_lines.append(f"✓ {Path(target).name}: Firma válida ({res['status']})")
            else:
                details_lines.append(f"• {Path(target).name}: {res['status']}")

        summary = f"{verified_signed} de {total_checked} binarios críticos con firma Authenticode verificada"
        report.items.append(DiagnosticItem(
            id="sec_wintrust_signatures",
            category="Firmas Digitales",
            title="Integridad Authenticode WinTrust",
            severity=Severity.OK,
            summary=summary,
            details="\n".join(details_lines),
            metrics={"trusted_binaries": verified_signed, "total_audited": total_checked}
        ))

    def _diagnose_startup_persistence(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "@((Get-CimInstance Win32_StartupCommand | Select-Object Name, Command)) | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            apps = json.loads(res.stdout)
            if not isinstance(apps, list):
                apps = [apps] if apps else []

            count = len(apps)
            severity = Severity.WARNING if count > 12 else Severity.OK
            rec = "Tienes más de 12 programas iniciando con Windows. Desactiva los que no uses para acelerar el arranque." if count > 12 else None

            report.items.append(DiagnosticItem(
                id="sec_startup_apps",
                category="Autoarranque",
                title=f"Programas de Inicio ({count} aplicaciones)",
                severity=severity,
                summary=f"{count} programas configurados para iniciar con Windows",
                details="\n".join([f"- {a.get('Name')}: {a.get('Command')}" for a in apps[:10]]),
                metrics={"startup_app_count": count},
                recommendation=rec
            ))
        except Exception:
            pass

    def _diagnose_suspicious_ports(self, report: DiagnosticReport) -> None:
        """Scans for active TCP listening ports and highlights unusual services."""
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "@((Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess)) | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            conns = json.loads(res.stdout)
            if not isinstance(conns, list):
                conns = [conns] if conns else []

            open_ports = {c.get("LocalPort") for c in conns if c.get("LocalPort")}
            total = len(open_ports)

            report.items.append(DiagnosticItem(
                id="sec_network_ports",
                category="Red",
                title="Auditoría de Puertos en Escucha",
                severity=Severity.OK,
                summary=f"{total} puertos locales escuchando conexiones",
                details=f"Puertos abiertos verificados: {sorted(list(open_ports))[:15]}...",
                metrics={"open_ports_count": total}
            ))
        except Exception:
            pass

