from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Dict, List, Tuple
from .base import BaseDiagnosticEngine, DiagnosticItem, DiagnosticReport, Severity

class NetworkDiagnosticEngine(BaseDiagnosticEngine):
    @property
    def name(self) -> str:
        return "network"

    @property
    def display_name(self) -> str:
        return "Red y Conectividad"

    def run(self) -> DiagnosticReport:
        report = DiagnosticReport(engine_name=self.name)
        
        latency_ms, loss_pct, jitter_ms = self._test_ping("1.1.1.1")
        severity = Severity.OK
        if loss_pct > 0 or latency_ms > 100:
            severity = Severity.WARNING
        if loss_pct > 25 or latency_ms > 200:
            severity = Severity.CRITICAL

        rec = None
        if loss_pct > 0:
            rec = "Se detectó pérdida de paquetes. Si usas Wi-Fi, intenta cambiar a cable Ethernet o reiniciar el router."
        elif latency_ms > 80:
            rec = "Latencia alta. Revisa si hay descargas activas en segundo plano o cambia tus DNS a Cloudflare (1.1.1.1)."

        report.items.append(DiagnosticItem(
            id="net_latency_jitter",
            category="Conexión",
            title=f"Latencia: {latency_ms:.1f} ms | Pérdida: {loss_pct}%",
            severity=severity,
            summary=f"Ping: {latency_ms:.1f}ms | Jitter: {jitter_ms:.1f}ms | Pérdida: {loss_pct}%",
            details=f"Destino: 1.1.1.1 (Cloudflare)\nLatencia media: {latency_ms:.1f} ms\nJitter estimado: {jitter_ms:.1f} ms\nPérdida de paquetes: {loss_pct}%",
            metrics={"latency_ms": latency_ms, "loss_pct": loss_pct, "jitter_ms": jitter_ms},
            recommendation=rec
        ))

        # Check DNS resolution latency
        report.items.append(self._test_dns())

        return report

    def _test_dns(self) -> DiagnosticItem:
        import socket
        try:
            t0 = time.perf_counter()
            socket.gethostbyname("one.one.one.one")
            dns_ms = round((time.perf_counter() - t0) * 1000, 1)
            sev = Severity.OK if dns_ms < 80 else (Severity.WARNING if dns_ms < 200 else Severity.CRITICAL)
            summary = f"Resolución DNS: {dns_ms} ms"
            rec = "Considera cambiar a DNS más rápidos como 1.1.1.1 o 8.8.8.8 para agilizar la navegación." if dns_ms >= 80 else None
            return DiagnosticItem(
                id="net_dns_latency",
                category="DNS",
                title=f"Resolución DNS: {dns_ms} ms",
                severity=sev,
                summary=summary,
                details=f"Tiempo de respuesta del servidor DNS asignado: {dns_ms} ms",
                metrics={"dns_latency_ms": dns_ms},
                recommendation=rec
            )
        except Exception:
            return DiagnosticItem(
                id="net_dns_latency",
                category="DNS",
                title="Resolución DNS",
                severity=Severity.WARNING,
                summary="Fallo al resolver nombres de dominio",
                details="No se pudo contactar el servidor DNS local.",
                recommendation="Verifica tu configuración de red o ejecuta un vaciado de caché DNS."
            )

    def _test_ping(self, host: str = "1.1.1.1") -> Tuple[float, float, float]:
        cmd = ["ping.exe", "-n", "5", "-w", "1000", host]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="cp1252", errors="replace", timeout=8, creationflags=flags)
            times = [float(m) for m in re.findall(r"tiempo[=<](\d+)ms", res.stdout, re.IGNORECASE)]
            if not times:
                times = [float(m) for m in re.findall(r"time[=<](\d+)ms", res.stdout, re.IGNORECASE)]
            
            lost = re.search(r"\((\d+)%\s*(?:perdidos|loss)\)", res.stdout, re.IGNORECASE)
            loss_pct = float(lost.group(1)) if lost else (0.0 if times else 100.0)

            if not times:
                return (999.0, 100.0, 0.0)

            avg_latency = sum(times) / len(times)
            jitter = (max(times) - min(times)) if len(times) > 1 else 0.0
            return (avg_latency, loss_pct, jitter)
        except Exception:
            return (999.0, 100.0, 0.0)
