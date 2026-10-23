from __future__ import annotations

import collections
import ctypes
import os
import subprocess
import threading
import time
from typing import Any, Deque, Dict, List, Optional

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

class TelemetryWorker:
    """Continuous low-overhead background daemon that polls hardware sensors at 1 Hz

    and stores a rolling history buffer for live graphs and sparklines.
    """
    _instance: Optional[TelemetryWorker] = None
    _lock = threading.Lock()

    def __init__(self, history_size: int = 60):
        self.history_size = history_size
        self.cpu_history: Deque[float] = collections.deque(maxlen=history_size)
        self.ram_history: Deque[float] = collections.deque(maxlen=history_size)
        self.gpu_temp_history: Deque[float] = collections.deque(maxlen=history_size)
        self.gpu_power_history: Deque[float] = collections.deque(maxlen=history_size)
        self.dpc_history: Deque[float] = collections.deque(maxlen=history_size)

        self.current_snapshot: Dict[str, Any] = {
            "cpu_pct": 0.0,
            "ram_load_pct": 0,
            "ram_used_gb": 0.0,
            "ram_total_gb": 16.0,
            "gpu": {"utilization": 0, "temp_c": 0, "power_w": 0.0, "clock_mhz": 0},
            "dpc_jitter_us": 14.0,
            "dpc_peak_us": 14.0,
            "timestamp": time.time()
        }

        self._last_cpu_times: Optional[tuple] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @classmethod
    def get_instance(cls) -> TelemetryWorker:
        with cls._lock:
            if cls._instance is None:
                cls._instance = TelemetryWorker()
                cls._instance.start()
            return cls._instance

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        try:
            self._poll_once()
        except Exception:
            pass
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="ClarityTelemetryDaemon")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._poll_once()
            except Exception:
                pass
            time.sleep(1.0)

    def _poll_once(self) -> None:
        # 1. RAM via Win32 API
        ms = MEMORYSTATUSEX()
        ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ram_load = 50
        total_ram = 16.0
        used_ram = 8.0
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
            ram_load = ms.dwMemoryLoad
            total_ram = round(ms.ullTotalPhys / (1024 ** 3), 1)
            used_ram = round((ms.ullTotalPhys - ms.ullAvailPhys) / (1024 ** 3), 1)

        # 2. CPU % via GetSystemTimes
        i, k, u = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
        curr = (i.value, k.value, u.value)
        cpu_pct = 5.0
        if self._last_cpu_times:
            i1, k1, u1 = self._last_cpu_times
            i2, k2, u2 = curr
            idle = i2 - i1
            total = (k2 - k1) + (u2 - u1)
            if total > 0:
                cpu_pct = max(0.0, min(100.0, round((1.0 - (idle / total)) * 100, 1)))
        self._last_cpu_times = curr

        # 3. GPU via nvidia-smi
        gpu_info = {"utilization": 0, "temp_c": 50, "power_w": 15.0, "clock_mhz": 210}
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
            res = subprocess.run(
                ["nvidia-smi", "--query-gpu=utilization.gpu,temperature.gpu,power.draw,clocks.current.graphics", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, errors="replace", timeout=1, creationflags=creation_flags
            )
            if res.returncode == 0 and res.stdout.strip():
                parts = [p.strip() for p in res.stdout.strip().split(",")]
                if len(parts) >= 4:
                    gpu_info = {
                        "utilization": int(parts[0]),
                        "temp_c": int(parts[1]),
                        "power_w": float(parts[2]),
                        "clock_mhz": int(parts[3])
                    }
        except Exception:
            pass

        # 4. Timer Jitter / DPC Pulse
        t0 = time.perf_counter()
        time.sleep(0.001)
        jitter = round(abs((time.perf_counter() - t0) * 1_000_000 - 1000), 1)

        # Append to histories
        self.cpu_history.append(cpu_pct)
        self.ram_history.append(float(ram_load))
        self.gpu_temp_history.append(float(gpu_info["temp_c"]))
        self.gpu_power_history.append(float(gpu_info["power_w"]))
        self.dpc_history.append(jitter)

        peak_dpc = max(self.dpc_history) if self.dpc_history else jitter

        self.current_snapshot = {
            "cpu_pct": cpu_pct,
            "ram_load_pct": ram_load,
            "ram_used_gb": used_ram,
            "ram_total_gb": total_ram,
            "gpu": gpu_info,
            "dpc_jitter_us": jitter,
            "dpc_peak_us": peak_dpc,
            "history": {
                "cpu": list(self.cpu_history),
                "ram": list(self.ram_history),
                "gpu_temp": list(self.gpu_temp_history),
                "gpu_power": list(self.gpu_power_history),
                "dpc": list(self.dpc_history)
            },
            "timestamp": time.time()
        }

    def get_snapshot(self) -> Dict[str, Any]:
        return self.current_snapshot
