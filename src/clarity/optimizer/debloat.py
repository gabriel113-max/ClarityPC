from __future__ import annotations

import os
import subprocess
import winreg
from typing import Any, Dict, List, Optional
from .base import BaseOptimizationAction, DryRunPreview, OptimizationCategory, OptimizationImpact, OptimizationResult

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class DisableDiagTrackAction(BaseOptimizationAction):
    """Disables the Connected User Experiences and Telemetry service (DiagTrack)."""
    @property
    def id(self) -> str:
        return "opt_debloat_diagtrack"

    @property
    def title(self) -> str:
        return "Desactivar Telemetría de Diagnóstico de Windows (DiagTrack)"

    @property
    def description(self) -> str:
        return "Detiene el servicio DiagTrack que recopila y sube datos de diagnóstico y telemetría en segundo plano."

    @property
    def why_it_matters(self) -> str:
        return "Elimina picos periódicos de lectura en disco y uso de CPU en reposo, ahorrando además unos 150 MB de memoria RAM."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.SYSTEM

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        cmd = ["powershell.exe", "-NoProfile", "-Command", "(Get-Service -Name DiagTrack -ErrorAction SilentlyContinue).StartType"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=4, creationflags=NO_WINDOW)
            return "disabled" in res.stdout.strip().lower()
        except Exception:
            return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=[
                "Detener servicio: Stop-Service -Name DiagTrack",
                "Fijar inicio en Deshabilitado: Set-Service -Name DiagTrack -StartupType Disabled"
            ],
            affected_targets=["Servicio de Windows 'Connected User Experiences and Telemetry' (DiagTrack)"],
            rollback_guarantee="Vuelve a iniciar el servicio y restaura el tipo de inicio a 'Automatic' (Automático)."
        )

    def apply(self) -> OptimizationResult:
        cmd = [
            "powershell.exe", "-NoProfile", "-Command",
            "Stop-Service -Name DiagTrack -Force -ErrorAction SilentlyContinue; "
            "Set-Service -Name DiagTrack -StartupType Disabled"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6, creationflags=NO_WINDOW)
            return OptimizationResult(
                success=res.returncode == 0,
                action_id=self.id,
                message="Servicio de telemetría DiagTrack detenido y deshabilitado con éxito.",
                saved_state={"previous_startup": "Automatic"}
            )
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Fallo al deshabilitar DiagTrack: {e}")

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        cmd = [
            "powershell.exe", "-NoProfile", "-Command",
            "Set-Service -Name DiagTrack -StartupType Automatic; "
            "Start-Service -Name DiagTrack -ErrorAction SilentlyContinue"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6, creationflags=NO_WINDOW)
            return OptimizationResult(
                success=res.returncode == 0,
                action_id=self.id,
                message="Servicio DiagTrack restaurado a su configuración original."
            )
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Fallo al restaurar DiagTrack: {e}")


class DisableStartMenuBingSearchAction(BaseOptimizationAction):
    """Disables web/Bing search suggestions in Windows Start Menu."""
    @property
    def id(self) -> str:
        return "opt_debloat_bing_search"

    @property
    def title(self) -> str:
        return "Desactivar Búsqueda Web de Bing en el Menú Inicio"

    @property
    def description(self) -> str:
        return "Evita que Windows consulte servidores de Bing cada vez que buscas un programa o archivo local en el menú inicio."

    @property
    def why_it_matters(self) -> str:
        return "Hace que la búsqueda del menú Inicio responda al instante (sin lag de red) y protege la privacidad de tus búsquedas locales."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.SYSTEM

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer") as k:
                val, _ = winreg.QueryValueEx(k, "DisableSearchBoxSuggestions")
                return val == 1
        except Exception:
            return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=["Set HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer\\DisableSearchBoxSuggestions = 1 (DWORD)"],
            affected_targets=["Directivas de búsqueda del Explorador y Menú Inicio de Windows"],
            rollback_guarantee="Elimina la directiva o la establece en 0 para reactivar sugerencias web si el usuario lo desea."
        )

    def apply(self) -> OptimizationResult:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer") as k:
                winreg.SetValueEx(k, "DisableSearchBoxSuggestions", 0, winreg.REG_DWORD, 1)
            return OptimizationResult(
                success=True,
                action_id=self.id,
                message="Búsqueda web de Bing desactivada en Menú Inicio.",
                saved_state={"key": r"Software\Policies\Microsoft\Windows\Explorer", "value_name": "DisableSearchBoxSuggestions"}
            )
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Error en registro: {e}")

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer", 0, winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.DeleteValue(k, "DisableSearchBoxSuggestions")
                except Exception:
                    winreg.SetValueEx(k, "DisableSearchBoxSuggestions", 0, winreg.REG_DWORD, 0)
            return OptimizationResult(success=True, action_id=self.id, message="Búsqueda web restaurada en Menú Inicio.")
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Fallo al restaurar: {e}")


class DisableEdgeBackgroundBoostAction(BaseOptimizationAction):
    """Disables Microsoft Edge background startup boost processes."""
    @property
    def id(self) -> str:
        return "opt_debloat_edge_boost"

    @property
    def title(self) -> str:
        return "Desactivar Pre-arranque en Segundo Plano de Edge"

    @property
    def description(self) -> str:
        return "Impide que Microsoft Edge mantenga procesos durmientes en segundo plano consumiendo memoria al encender el PC."

    @property
    def why_it_matters(self) -> str:
        return "Libera entre 200 MB y 400 MB de memoria RAM que Edge acapara sin estar en uso."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.SYSTEM

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def is_applicable(self) -> bool:
        return os.name == "nt"

    def is_applied(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge") as k:
                val, _ = winreg.QueryValueEx(k, "StartupBoostEnabled")
                return val == 0
        except Exception:
            return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=[
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\StartupBoostEnabled = 0",
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\BackgroundModeEnabled = 0"
            ],
            affected_targets=["Directivas de inicio en segundo plano de Microsoft Edge"],
            rollback_guarantee="Elimina las directivas de restricción permitiendo el inicio previo de Edge si se requiere."
        )

    def apply(self) -> OptimizationResult:
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge") as k:
                winreg.SetValueEx(k, "StartupBoostEnabled", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(k, "BackgroundModeEnabled", 0, winreg.REG_DWORD, 0)
            return OptimizationResult(
                success=True,
                action_id=self.id,
                message="Pre-arranque en segundo plano de Edge desactivado.",
                saved_state={"policy": "EdgeBoost"}
            )
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Error en registro: {e}")

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", 0, winreg.KEY_SET_VALUE) as k:
                try:
                    winreg.DeleteValue(k, "StartupBoostEnabled")
                except Exception:
                    pass
                try:
                    winreg.DeleteValue(k, "BackgroundModeEnabled")
                except Exception:
                    pass
            return OptimizationResult(success=True, action_id=self.id, message="Directivas de Edge restauradas.")
        except Exception as e:
            return OptimizationResult(success=False, action_id=self.id, message=f"Fallo al restaurar: {e}")
