from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List
from .base import BaseDiagnosticEngine, DiagnosticItem, DiagnosticReport, Severity

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class HardwareDiagnosticEngine(BaseDiagnosticEngine):
    @property
    def name(self) -> str:
        return "hardware"

    @property
    def display_name(self) -> str:
        return "Hardware y Sensores"

    def run(self) -> DiagnosticReport:
        report = DiagnosticReport(engine_name=self.name)
        
        self._diagnose_cpu(report)
        self._diagnose_ram_xmp(report)
        self._diagnose_gpu_tdr(report)
        self._diagnose_motherboard(report)
        self._diagnose_power_stability(report)

        return report

    def _diagnose_cpu(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            data = json.loads(res.stdout)
            name = data.get("Name", "CPU").strip()
            cores = data.get("NumberOfCores", 0)
            threads = data.get("NumberOfLogicalProcessors", 0)
            report.items.append(DiagnosticItem(
                id="hw_cpu",
                category="Procesador",
                title=f"{name}",
                severity=Severity.OK,
                summary=f"{cores} núcleos físicos / {threads} hilos",
                details=f"Modelo: {name}\nNúcleos: {cores}\nHilos: {threads}",
                metrics={"cores": cores, "threads": threads}
            ))
        except Exception:
            report.items.append(DiagnosticItem(
                id="hw_cpu",
                category="Procesador",
                title="Procesador (CPU)",
                severity=Severity.INFO,
                summary="Información no disponible temporalmente."
            ))

    def _diagnose_ram_xmp(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "@((Get-CimInstance Win32_PhysicalMemory | Select-Object PartNumber, Speed, ConfiguredClockSpeed, Capacity)) | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            data = json.loads(res.stdout)
            if not isinstance(data, list):
                data = [data] if data else []
            
            total_gb = sum(int(m.get("Capacity", 0)) for m in data) // (1024**3)
            configured_speeds = [int(m.get("ConfiguredClockSpeed", 0)) for m in data if m.get("ConfiguredClockSpeed")]
            rated_speeds = [int(m.get("Speed", 0)) for m in data if m.get("Speed")]
            
            current_speed = configured_speeds[0] if configured_speeds else 0
            max_rated = max(rated_speeds) if rated_speeds else 0

            xmp_missing = max_rated > current_speed and current_speed <= 2666 and max_rated >= 3000
            severity = Severity.WARNING if xmp_missing else Severity.OK
            
            rec = None
            if xmp_missing:
                rec = f"Tus memorias son de {max_rated} MHz pero están corriendo a {current_speed} MHz. Activa el perfil X.M.P. en la BIOS para ganar hasta un 15-20% de rendimiento."

            report.items.append(DiagnosticItem(
                id="hw_ram_xmp",
                category="Memoria RAM",
                title=f"Memoria RAM ({total_gb} GB a {current_speed} MHz)",
                severity=severity,
                summary=f"Capacidad total: {total_gb} GB | Velocidad activa: {current_speed} MHz" + (" (XMP Desactivado)" if xmp_missing else ""),
                details=f"Módulos detectados: {len(data)}\nVelocidad actual: {current_speed} MHz\nVelocidad nominal: {max_rated} MHz",
                metrics={"total_gb": total_gb, "current_mhz": current_speed, "rated_mhz": max_rated},
                recommendation=rec
            ))
        except Exception:
            pass

    def _diagnose_gpu_tdr(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "$gpu = Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion | ConvertTo-Json; " +
            "$tdr = (Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='nvlddmkm'; Id=153; StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue | Measure-Object).Count; " +
            "@{Gpu=$gpu; TdrCount=$tdr} | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10, creationflags=NO_WINDOW)
            data = json.loads(res.stdout)
            gpu_data = json.loads(data.get("Gpu", "{}"))
            if isinstance(gpu_data, list):
                gpu_data = gpu_data[0]
            name = gpu_data.get("Name", "GPU Desconocida")
            driver = gpu_data.get("DriverVersion", "")
            tdr_count = int(data.get("TdrCount", 0))

            severity = Severity.CRITICAL if tdr_count > 5 else (Severity.WARNING if tdr_count > 0 else Severity.OK)
            summary = f"Controlador: {driver}" + (f" | ¡{tdr_count} cuelgues TDR detectados!" if tdr_count > 0 else " | Estable")

            rec = None
            if tdr_count > 0:
                rec = "Se detectaron caídas de video TDR en la GPU. Puede indicar problemas en VRAM, alimentación o inestabilidad física del chip."

            report.items.append(DiagnosticItem(
                id="hw_gpu_tdr",
                category="Tarjeta Gráfica",
                title=f"{name}",
                severity=severity,
                summary=summary,
                details=f"Modelo: {name}\nDriver: {driver}\nEventos TDR (Últimas 48h): {tdr_count}",
                metrics={"tdr_count": tdr_count},
                recommendation=rec
            ))
        except Exception:
            pass

    def _diagnose_motherboard(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product | ConvertTo-Json"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            data = json.loads(res.stdout)
            mfg = data.get("Manufacturer", "").strip()
            prod = data.get("Product", "").strip()
            report.items.append(DiagnosticItem(
                id="hw_motherboard",
                category="Placa Base",
                title=f"{mfg} {prod}",
                severity=Severity.INFO,
                summary="Placa base del sistema",
                details=f"Fabricante: {mfg}\nModelo: {prod}"
            ))
        except Exception:
            pass

    def _diagnose_power_stability(self, report: DiagnosticReport) -> None:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue | Measure-Object).Count"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=8, creationflags=NO_WINDOW)
            count = int(res.stdout.strip() or "0")
            severity = Severity.CRITICAL if count >= 3 else (Severity.WARNING if count > 0 else Severity.OK)
            summary = f"{count} reinicios o apagados súbitos en 48h" if count > 0 else "Suministro eléctrico y apagados limpios"
            rec = "Revisar conector PCIe, fuente de poder o estabilidad de la tarjeta gráfica." if count >= 3 else None

            report.items.append(DiagnosticItem(
                id="hw_power_stability",
                category="Energía / Fuente",
                title="Estabilidad de Energía (Kernel-Power)",
                severity=severity,
                summary=summary,
                details=f"Eventos Kernel-Power 41 en 48h: {count}",
                metrics={"kernel_power_events": count},
                recommendation=rec
            ))
        except Exception:
            pass
