from __future__ import annotations

import collections
import datetime
import json
import os
import subprocess
import threading
import time
from typing import Any, Deque, Dict, List, Optional

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

class SystemWatchdog:
    """Background Sentry that monitors Windows Event Log in near real-time for:
    - GPU Driver TDR (Event ID 153 - nvlddmkm)
    - Abrupt Power Loss / Hard Crash (Event ID 41 - Kernel-Power)

    When Auto-TDR Guard is enabled, it automatically throttles GPU to 100W / 1350MHz
    to prevent unrecoverable hard freezes and system crashes.
    """
    _instance: Optional[SystemWatchdog] = None
    _lock = threading.Lock()

    def __init__(self, poll_interval_sec: float = 6.0):
        self.poll_interval = poll_interval_sec
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.auto_guard_enabled = True
        self.last_check_time = datetime.datetime.now() - datetime.timedelta(minutes=5)
        self.recent_incidents: Deque[Dict[str, Any]] = collections.deque(maxlen=20)
        self.last_action_taken: Optional[str] = None
        self.total_tdr_intercepted = 0

    @classmethod
    def get_instance(cls) -> SystemWatchdog:
        with cls._lock:
            if cls._instance is None:
                cls._instance = SystemWatchdog()
                cls._instance.start()
            return cls._instance

    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="SystemWatchdogThread")
        self._thread.start()

    def stop(self) -> None:
        self.is_running = False

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "auto_guard_enabled": self.auto_guard_enabled,
            "total_tdr_intercepted": self.total_tdr_intercepted,
            "last_action_taken": self.last_action_taken,
            "recent_incidents": list(self.recent_incidents),
            "timestamp": time.time()
        }

    def set_auto_guard(self, enabled: bool) -> None:
        self.auto_guard_enabled = bool(enabled)

    def _monitor_loop(self) -> None:
        while self.is_running:
            try:
                self._check_event_log()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _check_event_log(self) -> None:
        # Check System log since last_check_time for Event 153 or 41
        time_str = self.last_check_time.strftime("%Y-%m-%dT%H:%M:%S")
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f"@((Get-WinEvent -FilterHashtable @{{LogName='System'; Id=153,41; StartTime='{time_str}'}} -ErrorAction SilentlyContinue | "
            f"Select-Object Id, ProviderName, TimeCreated, Message)) | ConvertTo-Json"
        ]
        now = datetime.datetime.now()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6, creationflags=NO_WINDOW)
            if res.returncode == 0 and res.stdout.strip():
                events = json.loads(res.stdout)
                if not isinstance(events, list):
                    events = [events] if events else []

                for ev in events:
                    ev_id = ev.get("Id")
                    provider = ev.get("ProviderName", "")
                    time_raw = ev.get("TimeCreated", "")
                    
                    incident = {
                        "event_id": ev_id,
                        "provider": provider,
                        "time": time_raw,
                        "timestamp": time.time(),
                        "auto_action_applied": False
                    }

                    if ev_id == 153:
                        self.total_tdr_intercepted += 1
                        incident["description"] = "Cuelgue de controlador GPU (TDR Event 153 nvlddmkm)"
                        if self.auto_guard_enabled:
                            self._apply_emergency_guard()
                            incident["auto_action_applied"] = True
                            self.last_action_taken = f"Auto-TDR Guard activado: GPU limitada a 100W @ {now.strftime('%H:%M:%S')}"
                    elif ev_id == 41:
                        incident["description"] = "Corte abrupto de energía / reinicio forzado (Kernel-Power 41)"

                    self.recent_incidents.appendleft(incident)
        except Exception:
            pass
        finally:
            self.last_check_time = now

    def _apply_emergency_guard(self) -> bool:
        """Applies safe GPU power limit and clock cap to stabilize hardware."""
        try:
            subprocess.run(["nvidia-smi", "-pl", "100"], capture_output=True, text=True, errors="replace", timeout=4, creationflags=NO_WINDOW)
            subprocess.run(["nvidia-smi", "-lgc", "210,1350"], capture_output=True, text=True, errors="replace", timeout=4, creationflags=NO_WINDOW)
            return True
        except Exception:
            return False
