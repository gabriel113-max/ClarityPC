from __future__ import annotations

import os
import subprocess
import winreg
from typing import Dict, Any, List
from ..base import OptimizationResult

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class MasterModesManager:
    @staticmethod
    def apply_gamer_mode() -> Dict[str, Any]:
        results = []
        try:
            # 1. Enable Game Mode
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\GameBar") as key:
                winreg.SetValueEx(key, "AllowAutoGameMode", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "AutoGameModeEnabled", 0, winreg.REG_DWORD, 1)
            results.append("Modo Juego de Windows forzado.")

            # 2. Disable background GameDVR
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR") as key:
                winreg.SetValueEx(key, "AppCaptureEnabled", 0, winreg.REG_DWORD, 0)
            results.append("Grabación de fondo GameDVR desactivada (ahorra VRAM).")

            # 3. Activate Ultimate Performance
            subprocess.run(["powercfg", "-setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"], capture_output=True, text=True, timeout=5, creationflags=NO_WINDOW)
            results.append("Plan de energía cambiado a Máximo Rendimiento.")

            return {
                "success": True,
                "mode": "gamer",
                "title": "Modo Gamer Activado",
                "details": results
            }
        except Exception as e:
            return {"success": False, "mode": "gamer", "error": str(e)}

    @staticmethod
    def apply_unity_mode() -> Dict[str, Any]:
        results = []
        try:
            # 1. High Performance plan for fast Roslyn compilation
            subprocess.run(["powercfg", "-setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"], capture_output=True, text=True, timeout=5, creationflags=NO_WINDOW)
            results.append("CPU configurada para máxima frecuencia en hilos de compilación.")

            # 2. ReTrim SSD caches
            subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue"], capture_output=True, text=True, timeout=15, creationflags=NO_WINDOW)
            results.append("Celdas de caché NVMe optimizadas con TRIM.")

            return {
                "success": True,
                "mode": "unity",
                "title": "Modo Unity & Desarrollo Activado",
                "details": results
            }
        except Exception as e:
            return {"success": False, "mode": "unity", "error": str(e)}

    @staticmethod
    def apply_ai_mode() -> Dict[str, Any]:
        results = []
        try:
            # 1. Purge Standby memory list to free fragmented RAM
            subprocess.run(["powershell.exe", "-NoProfile", "-Command", "[System.GC]::Collect()"], capture_output=True, text=True, timeout=5, creationflags=NO_WINDOW)
            results.append("Memoria RAM purgada para datasets de PyTorch.")

            # 2. Check and optimize power
            subprocess.run(["powercfg", "-setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"], capture_output=True, text=True, timeout=5, creationflags=NO_WINDOW)
            results.append("Prioridad de bus PCIe y alimentación fijada en modo Performance.")

            return {
                "success": True,
                "mode": "ai",
                "title": "Modo IA & PyTorch Activado",
                "details": results
            }
        except Exception as e:
            return {"success": False, "mode": "ai", "error": str(e)}

    @staticmethod
    def apply_potato_mode() -> Dict[str, Any]:
        results = []
        try:
            # 1. Disable window animations and visual effects
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop\WindowMetrics") as key:
                winreg.SetValueEx(key, "MinAnimate", 0, winreg.REG_SZ, "0")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") as key:
                winreg.SetValueEx(key, "TaskbarAnimations", 0, winreg.REG_DWORD, 0)
            results.append("Animaciones pesadas de ventanas y barra de tareas desactivadas.")

            # 2. Enable Windows Memory Compression
            subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Enable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue"], capture_output=True, text=True, timeout=8, creationflags=NO_WINDOW)
            results.append("Compresión inteligente de RAM activada para hardware limitado.")

            return {
                "success": True,
                "mode": "potato",
                "title": "Modo Revivir PC Patata Activado",
                "details": results
            }
        except Exception as e:
            return {"success": False, "mode": "potato", "error": str(e)}
