from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List
from ..core.base import DiagnosticReport, Severity

class ReportExporter:
    @staticmethod
    def to_markdown(reports: List[DiagnosticReport], user_name: str = "Usuario") -> str:
        lines = [
            f"# Informe de Diagnóstico y Salud - ClarityPC",
            f"**Fecha:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} | **Equipo:** {user_name}",
            "",
            "---",
            ""
        ]

        for r in reports:
            lines.append(f"## Módulo: {r.engine_name.upper()}")
            for item in r.items:
                badge = "🟢 OK" if item.severity == Severity.OK else ("🟡 AVISO" if item.severity == Severity.WARNING else ("🔴 CRÍTICO" if item.severity == Severity.CRITICAL else "ℹ️ INFO"))
                lines.append(f"### {badge} {item.title}")
                lines.append(f"- **Resumen:** {item.summary}")
                if item.details:
                    lines.append(f"- **Detalles:**\n```\n{item.details}\n```")
                if item.recommendation:
                    lines.append(f"- **💡 Recomendación:** {item.recommendation}")
                lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_json(reports: List[DiagnosticReport]) -> str:
        data = []
        for r in reports:
            data.append({
                "engine": r.engine_name,
                "timestamp": r.timestamp.isoformat(),
                "highest_severity": r.highest_severity.value,
                "items": [
                    {
                        "id": i.id,
                        "category": i.category,
                        "title": i.title,
                        "severity": i.severity.value,
                        "summary": i.summary,
                        "details": i.details,
                        "metrics": i.metrics,
                        "recommendation": i.recommendation,
                    }
                    for i in r.items
                ]
            })
        return json.dumps(data, indent=2, ensure_ascii=False)
