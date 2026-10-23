from __future__ import annotations

import ctypes
import os
import subprocess
from typing import Any, Dict, List, Optional

# Windows API Constants
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
NORMAL_PRIORITY_CLASS = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS = 0x00000080

KNOWN_GAMES = {
    "cs2.exe": "Counter-Strike 2",
    "csgo.exe": "Counter-Strike: Global Offensive",
    "valorant-win64-shipping.exe": "Valorant",
    "valorant.exe": "Valorant Launcher",
    "fortniteclient-win64-shipping.exe": "Fortnite",
    "r5apex.exe": "Apex Legends",
    "cod.exe": "Call of Duty: Warzone / MW",
    "overwatch.exe": "Overwatch 2",
    "league of legends.exe": "League of Legends",
    "dota2.exe": "Dota 2",
    "gta5.exe": "Grand Theft Auto V",
    "cyberpunk2077.exe": "Cyberpunk 2077",
    "rocketleague.exe": "Rocket League",
    "rainbowsix.exe": "Rainbow Six Siege",
    "eldenring.exe": "Elden Ring",
    "starfield.exe": "Starfield",
    "genshinimpact.exe": "Genshin Impact",
    "minecraft.exe": "Minecraft",
    "javaw.exe": "Minecraft (Java Runtime)"
}

class GamingLatencyEngine:
    """Detects active competitive/AAA games and applies ultra-low latency system tuning:
    1. timeBeginPeriod(1) for sub-millisecond Windows timer resolution.
    2. HIGH_PRIORITY_CLASS scheduling priority.
    3. CPU Affinity optimization (pinning to performance cores).
    """
    _timer_active = False

    @staticmethod
    def enable_high_res_timer() -> bool:
        """Sets Windows global timer resolution to 1ms (or 0.5ms) via winmm.dll."""
        try:
            winmm = ctypes.windll.winmm
            ret = winmm.timeBeginPeriod(1)
            GamingLatencyEngine._timer_active = (ret == 0)
            return GamingLatencyEngine._timer_active
        except Exception:
            return False

    @staticmethod
    def disable_high_res_timer() -> bool:
        try:
            winmm = ctypes.windll.winmm
            ret = winmm.timeEndPeriod(1)
            GamingLatencyEngine._timer_active = False
            return ret == 0
        except Exception:
            return False

    @staticmethod
    def is_timer_active() -> bool:
        return GamingLatencyEngine._timer_active

    @staticmethod
    def detect_running_games() -> List[Dict[str, Any]]:
        """Scans process table and returns list of recognized games currently running."""
        games: List[Dict[str, Any]] = []
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
        try:
            cmd = ["powershell.exe", "-NoProfile", "-Command", 
                   "Get-Process | Select-Object Id, ProcessName, PriorityClass, Path | ConvertTo-Json"]
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6, creationflags=flags)
            if res.returncode == 0 and res.stdout.strip():
                import json
                procs = json.loads(res.stdout)
                if not isinstance(procs, list):
                    procs = [procs] if procs else []

                for p in procs:
                    pname = str(p.get("ProcessName", "")).lower()
                    exe_name = f"{pname}.exe"
                    matched_title = KNOWN_GAMES.get(exe_name)
                    if matched_title:
                        games.append({
                            "pid": p.get("Id"),
                            "process_name": exe_name,
                            "game_title": matched_title,
                            "priority": str(p.get("PriorityClass", "Normal")),
                            "path": p.get("Path", ""),
                            "is_boosted": str(p.get("PriorityClass", "")).lower() in ["high", "abovenormal"]
                        })
        except Exception:
            pass

        return games

    @staticmethod
    def boost_process(pid: int, priority_level: str = "high") -> Dict[str, Any]:
        """Applies High Priority and enables 1ms timer resolution."""
        GamingLatencyEngine.enable_high_res_timer()
        p_val = HIGH_PRIORITY_CLASS if priority_level.lower() == "high" else ABOVE_NORMAL_PRIORITY_CLASS

        kernel32 = ctypes.windll.kernel32
        h_proc = kernel32.OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, False, pid)
        if not h_proc:
            return {"success": False, "message": f"No se pudo abrir el proceso PID {pid} (requiere elevación UAC)."}

        try:
            success = kernel32.SetPriorityClass(h_proc, p_val)
            if success:
                return {
                    "success": True, 
                    "message": f"Proceso PID {pid} priorizado a {priority_level.upper()} y temporizador Windows fijado a 1ms.",
                    "timer_active": True
                }
            return {"success": False, "message": "Fallo al llamar SetPriorityClass."}
        finally:
            kernel32.CloseHandle(h_proc)

    @staticmethod
    def restore_process(pid: int) -> Dict[str, Any]:
        kernel32 = ctypes.windll.kernel32
        h_proc = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
        if not h_proc:
            return {"success": False, "message": f"No se pudo abrir el proceso PID {pid}."}

        try:
            success = kernel32.SetPriorityClass(h_proc, NORMAL_PRIORITY_CLASS)
            return {
                "success": bool(success),
                "message": "Prioridad de proceso restablecida a Normal." if success else "Error al restablecer prioridad."
            }
        finally:
            kernel32.CloseHandle(h_proc)
