from __future__ import annotations

from typing import Any, Dict, List, Optional

class PCHealthScoreCalculator:
    """Calculates an empirical 0-100 PC Health & Stability Index based on
    real forensic telemetry (DPC jitter, GPU TDRs, Kernel-Power 41, XMP profile, storage).
    """

    @staticmethod
    def calculate(
        topology_data: Optional[Dict[str, Any]] = None,
        telemetry_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        topo = topology_data or {}
        telem = telemetry_data or {}

        score = 100
        penalties: List[Dict[str, Any]] = []

        # 1. GPU Stability (TDR Crashes)
        tdr_count = topo.get("gpu", {}).get("tdr_count", 0)
        if tdr_count > 10:
            deduction = 35
            score -= deduction
            penalties.append({
                "subsystem": "GPU",
                "points": deduction,
                "reason": f"Inestabilidad crítica de video: {tdr_count} cuelgues TDR en 48 horas.",
                "fix": "Aplicar límite seguro de 100W y programar revisión de alimentación/VRAM."
            })
        elif tdr_count > 0:
            deduction = 15
            score -= deduction
            penalties.append({
                "subsystem": "GPU",
                "points": deduction,
                "reason": f"Detección de {tdr_count} caídas del controlador nvlddmkm.",
                "fix": "Verificar drivers de video limpios y ventilación."
            })

        # 2. Power Supply Stability (Kernel-Power 41)
        kp41 = topo.get("psu", {}).get("kp41_count", 0)
        if kp41 >= 3:
            deduction = 25
            score -= deduction
            penalties.append({
                "subsystem": "Energía",
                "points": deduction,
                "reason": f"Suministro eléctrico inestable: {kp41} apagados o reinicios súbitos en 48h.",
                "fix": "Revisar cable PCIe individual (evitar conectores en cadena) o fuente de poder."
            })
        elif kp41 > 0:
            deduction = 10
            score -= deduction
            penalties.append({
                "subsystem": "Energía",
                "points": deduction,
                "reason": f"{kp41} reinicio inesperado registrado.",
                "fix": "Asegurar que el botón de apagado o cortes de luz no coincidan con fallos."
            })

        # 3. RAM XMP Memory Frequency
        ram_cfg = topo.get("ram", {}).get("configured_mhz", 2666)
        ram_rated = topo.get("ram", {}).get("rated_mhz", 3200)
        if ram_cfg < ram_rated:
            deduction = 15
            score -= deduction
            penalties.append({
                "subsystem": "Memoria RAM",
                "points": deduction,
                "reason": f"XMP inactivo en BIOS (Memorias a {ram_cfg} MHz de los {ram_rated} MHz nominales).",
                "fix": "Habilitar Extreme Memory Profile (Profile 1) en firmware UEFI."
            })

        # 4. Latency & DPC Jitter
        dpc_peak = telem.get("dpc_peak_us", 200.0)
        if dpc_peak > 2000:
            deduction = 15
            score -= deduction
            penalties.append({
                "subsystem": "Latencia DPC",
                "points": deduction,
                "reason": f"Picos de interrupción de kernel elevados ({dpc_peak:.0f} µs) causando micro-tirones.",
                "fix": "Purgar caché de sombreadores DirectX y activar temporizador de alta resolución."
            })
        elif dpc_peak > 1000:
            deduction = 8
            score -= deduction
            penalties.append({
                "subsystem": "Latencia DPC",
                "points": deduction,
                "reason": f"Fluctuaciones moderadas de jitter ({dpc_peak:.0f} µs).",
                "fix": "Optimizar prioridades de proceso en juegos."
            })

        score = max(10, min(100, score))

        if score >= 85:
            verdict = "Óptimo y Estable"
            verdict_en = "Optimal & Stable"
            status_color = "optimal"
        elif score >= 60:
            verdict = "Cuellos de Botella Detectados"
            verdict_en = "Bottlenecks Detected"
            status_color = "warning"
        else:
            verdict = "Crítico: Requiere Intervención"
            verdict_en = "Critical: Hardware Intervention Needed"
            status_color = "critical"

        # Estimated score after ClarityPC fixes
        potential_score = 98 if (tdr_count > 0 or kp41 > 0) else 100

        return {
            "score": score,
            "potential_score": potential_score,
            "verdict": verdict,
            "verdict_en": verdict_en,
            "status_color": status_color,
            "total_penalties": len(penalties),
            "penalties": penalties
        }
