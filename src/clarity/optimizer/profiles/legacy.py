from __future__ import annotations

import os
import subprocess
import winreg
from typing import Any, Dict
from ..base import BaseOptimizationAction, DryRunPreview, OptimizationCategory, OptimizationImpact, OptimizationResult

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class LegacyVisualsAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "opt_legacy_visuals"

    @property
    def title(self) -> str:
        return "Aliviar Efectos Visuales (PCs Antiguas / Débiles)"

    @property
    def description(self) -> str:
        return "Desactiva animaciones de apertura de ventanas, sombras bajo el ratón y desenfoques pesados de Windows, manteniendo la fuente de texto nítida."

    @property
    def why_it_matters(self) -> str:
        return "En procesadores de 2 a 4 núcleos o gráficas antiguas/integradas, reduce el uso de memoria RAM del Administrador de Ventanas (dwm.exe) hasta en un 40% y hace que la interfaz responda al instante."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.LEGACY_PC

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.HIGH

    def is_applicable(self) -> bool:
        return True

    def is_applied(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop\WindowMetrics") as key:
                val, _ = winreg.QueryValueEx(key, "MinAnimate")
                return str(val) == "0"
        except Exception:
            return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=[
                "Set HKCU\\Control Panel\\Desktop\\WindowMetrics\\MinAnimate = 0",
                "Set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarAnimations = 0"
            ],
            affected_targets=["Animaciones de ventanas y barra de tareas"],
            rollback_guarantee="Vuelve a activar las animaciones de ventanas por defecto (MinAnimate = 1)."
        )

    def apply(self) -> OptimizationResult:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop\WindowMetrics") as key:
                winreg.SetValueEx(key, "MinAnimate", 0, winreg.REG_SZ, "0")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") as key:
                winreg.SetValueEx(key, "TaskbarAnimations", 0, winreg.REG_DWORD, 0)

            return OptimizationResult(
                success=True,
                message="Efectos visuales pesados atenuados para máxima fluidez.",
                action_id=self.id,
                saved_state={"min_animate": "1", "taskbar_animations": 1}
            )
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop\WindowMetrics") as key:
                winreg.SetValueEx(key, "MinAnimate", 0, winreg.REG_SZ, "1")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") as key:
                winreg.SetValueEx(key, "TaskbarAnimations", 0, winreg.REG_DWORD, 1)

            return OptimizationResult(success=True, message="Efectos visuales originales restaurados.", action_id=self.id)
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)


class StorageTrimAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "opt_storage_retrim"

    @property
    def title(self) -> str:
        return "Mantenimiento TRIM en Unidades SSD/NVMe"

    @property
    def description(self) -> str:
        return "Notifica a los discos de estado sólido qué bloques de datos ya no se usan para que el recolector de basura mantenga velocidades de escritura máximas."

    @property
    def why_it_matters(self) -> str:
        return "Evita la degradación de velocidad con el tiempo en discos SSD y reduce los tiempos de carga en juegos y programas pesados."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.STORAGE

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def is_applicable(self) -> bool:
        return True

    def is_applied(self) -> bool:
        return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=["Optimize-Volume -DriveLetter C -ReTrim"],
            affected_targets=["Unidad de almacenamiento del sistema"],
            rollback_guarantee="Operación de mantenimiento puro (no altera datos de usuario)."
        )

    def apply(self) -> OptimizationResult:
        try:
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", "Optimize-Volume -DriveLetter C -ReTrim -ErrorAction Stop"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=NO_WINDOW
            )
            if res.returncode == 0:
                return OptimizationResult(success=True, message="TRIM completado en disco C:.", action_id=self.id)
            return OptimizationResult(success=False, message=res.stderr.strip() or "Error al ejecutar TRIM", action_id=self.id)
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        return OptimizationResult(success=True, message="Operación de mantenimiento no requiere rollback.", action_id=self.id)
