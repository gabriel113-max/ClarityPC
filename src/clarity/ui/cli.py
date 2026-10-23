from __future__ import annotations

import sys
from typing import List
from ..companion.state_machine import CompanionMood, CompanionStateMachine
from ..companion.characters import CharacterType
from ..core.hardware import HardwareDiagnosticEngine
from ..core.bios import BiosDiagnosticEngine
from ..core.network import NetworkDiagnosticEngine
from ..core.security import SecurityDiagnosticEngine
from ..core.base import DiagnosticReport, Severity
from ..optimizer.profiles.gaming import GameModeAction, GameDVRAction
from ..optimizer.profiles.legacy import LegacyVisualsAction, StorageTrimAction
from ..reports.exporter import ReportExporter

def render_companion_banner(bubble) -> None:
    border = "=" * 65
    print("\n" + border)
    print(f" {bubble.icon} [{bubble.character_name}] :: {bubble.headline}")
    print(f" > {bubble.message}")
    if bubble.tip:
        print(f" 💡 {bubble.tip}")
    print(border + "\n")

def run_cli() -> None:
    companion = CompanionStateMachine(CharacterType.BYTE_CAT)
    
    # Welcome banner
    render_companion_banner(companion.get_speech(CompanionMood.IDLE))

    print("Iniciando escaneo de diagnóstico integral con ClarityPC...\n")
    
    engines = [
        HardwareDiagnosticEngine(),
        BiosDiagnosticEngine(),
        NetworkDiagnosticEngine(),
        SecurityDiagnosticEngine(),
    ]

    all_reports: List[DiagnosticReport] = []

    for eng in engines:
        print(f"[*] Analizando subsistema: {eng.display_name}...")
        report = eng.run()
        all_reports.append(report)

    # Calculate overall health
    has_critical = any(r.highest_severity == Severity.CRITICAL for r in all_reports)
    has_warning = any(r.highest_severity == Severity.WARNING for r in all_reports)

    if has_critical:
        bubble = companion.get_speech(
            CompanionMood.ALARMED,
            context="Se detectaron errores críticos en el hardware o seguridad de tu equipo.",
            extra_data="Revisa los ítems marcados en rojo a continuación."
        )
    elif has_warning:
        bubble = companion.get_speech(
            CompanionMood.ALARMED,
            context="El equipo es funcional, pero hay advertencias importantes (ej. RAM sin XMP o latencia).",
            extra_data="Puedes optimizar estos puntos para ganar velocidad."
        )
    else:
        bubble = companion.get_speech(
            CompanionMood.HAPPY,
            context="Tu equipo superó todas las pruebas sin advertencias graves."
        )

    render_companion_banner(bubble)

    # Print summary items
    print("--- RESULTADOS DEL DIAGNÓSTICO ---")
    for r in all_reports:
        print(f"\n[+] {r.engine_name.upper()}:")
        for item in r.items:
            icon = "🟢" if item.severity == Severity.OK else ("🟡" if item.severity == Severity.WARNING else ("🔴" if item.severity == Severity.CRITICAL else "ℹ️"))
            print(f"  {icon} {item.title}: {item.summary}")
            if item.recommendation:
                print(f"     └─ 💡 {item.recommendation}")

    print("\n" + "-" * 65)
    print("Generando informe preliminar en Markdown...")
    md = ReportExporter.to_markdown(all_reports)
    print("Informe generado exitosamente en memoria.")
    print("-" * 65)
