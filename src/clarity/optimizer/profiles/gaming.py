from __future__ import annotations

import subprocess
import winreg
from typing import Any, Dict
from ..base import BaseOptimizationAction, DryRunPreview, OptimizationCategory, OptimizationImpact, OptimizationResult

class GameModeAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "opt_gaming_gamemode"

    @property
    def title(self) -> str:
        return "Modo Juego de Windows"

    @property
    def description(self) -> str:
        return "Prioriza de forma estricta los subprocesos del juego activo en primer plano sobre los procesos en segundo plano."

    @property
    def why_it_matters(self) -> str:
        return "Reduce tirones (micro-stuttering) y fluctuaciones de FPS durante partidas al pausar tareas de mantenimiento mientras juegas."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.GAMING

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.HIGH

    def is_applicable(self) -> bool:
        return True

    def is_applied(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\GameBar") as key:
                val, _ = winreg.QueryValueEx(key, "AllowAutoGameMode")
                return val == 1
        except Exception:
            return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=["Set HKCU\\Software\\Microsoft\\GameBar\\AllowAutoGameMode = 1 (DWORD)"],
            affected_targets=["Registro de Windows (GameBar)"],
            rollback_guarantee="Restaura el valor previo exacto (0 o 1) o elimina la clave si no existía."
        )

    def apply(self) -> OptimizationResult:
        old_val = None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\GameBar") as key:
                old_val, _ = winreg.QueryValueEx(key, "AllowAutoGameMode")
        except Exception:
            old_val = None

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\GameBar") as key:
                winreg.SetValueEx(key, "AllowAutoGameMode", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "AutoGameModeEnabled", 0, winreg.REG_DWORD, 1)

            return OptimizationResult(
                success=True,
                message="Modo Juego activado correctamente.",
                action_id=self.id,
                saved_state={"previous_value": old_val}
            )
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        prev = saved_state.get("previous_value")
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\GameBar") as key:
                if prev is None:
                    try:
                        winreg.DeleteValue(key, "AllowAutoGameMode")
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, "AllowAutoGameMode", 0, winreg.REG_DWORD, int(prev))
            return OptimizationResult(success=True, message="Modo Juego restablecido a su estado original.", action_id=self.id)
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)


class GameDVRAction(BaseOptimizationAction):
    @property
    def id(self) -> str:
        return "opt_gaming_gamedvr"

    @property
    def title(self) -> str:
        return "Desactivar Grabación de Fondo (GameDVR)"

    @property
    def description(self) -> str:
        return "Desactiva el búfer de grabación continua en segundo plano que consume memoria VRAM y codificador de video."

    @property
    def why_it_matters(self) -> str:
        return "Libera hasta 300-500 MB de memoria de video y ciclos del chip NVENC/AMF, evitando caídas repentinas de cuadros por segundo."

    @property
    def category(self) -> OptimizationCategory:
        return OptimizationCategory.GAMING

    @property
    def impact(self) -> OptimizationImpact:
        return OptimizationImpact.MEDIUM

    def is_applicable(self) -> bool:
        return True

    def is_applied(self) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR") as key:
                val, _ = winreg.QueryValueEx(key, "AppCaptureEnabled")
                return val == 0
        except Exception:
            return False

    def dry_run(self) -> DryRunPreview:
        return DryRunPreview(
            action_id=self.id,
            operations=["Set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR\\AppCaptureEnabled = 0"],
            affected_targets=["Registro de Windows (GameDVR)"],
            rollback_guarantee="Vuelve a activar la grabación en segundo plano (valor = 1)."
        )

    def apply(self) -> OptimizationResult:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR") as key:
                winreg.SetValueEx(key, "AppCaptureEnabled", 0, winreg.REG_DWORD, 0)
            return OptimizationResult(success=True, message="Grabación de fondo GameDVR desactivada.", action_id=self.id, saved_state={"previous": 1})
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)

    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR") as key:
                winreg.SetValueEx(key, "AppCaptureEnabled", 0, winreg.REG_DWORD, 1)
            return OptimizationResult(success=True, message="Grabación de fondo GameDVR restaurada.", action_id=self.id)
        except Exception as e:
            return OptimizationResult(success=False, message=str(e), action_id=self.id)
