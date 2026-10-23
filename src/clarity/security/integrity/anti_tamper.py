from __future__ import annotations

import ctypes
import os
import threading
import time
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Win32 File Notification Constants
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040

FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
FILE_ACTION_MODIFIED = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
FILE_ACTION_RENAMED_NEW_NAME = 0x00000005

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wintypes.DWORD),
        ("Action", wintypes.DWORD),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 260),
    ]

@dataclass
class TamperEventRecord:
    timestamp: float
    time_str: str
    action: str
    target_path: str
    is_critical_extension: bool  # .sys, .dll, .exe
    severity: str                # WARNING, CRITICAL, INFO
    alert_message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class SystemIntegrityMonitor:
    """Anti-Tampering System Sentry.
    Monitors Windows System32 and Driver directories for unauthorized file drops,
    replacements, or deletions using low-level kernel notification channels (ReadDirectoryChangesW).
    """

    _instance: Optional[SystemIntegrityMonitor] = None
    CRITICAL_EXTENSIONS = {".sys", ".dll", ".exe", ".inf"}

    def __init__(self, watch_paths: Optional[List[Path]] = None):
        default_driver_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers"
        default_system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"

        self.watch_paths: List[Path] = watch_paths or [default_driver_dir, default_system32]
        self._running = False
        self._threads: List[threading.Thread] = []
        self._events: List[TamperEventRecord] = []
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> SystemIntegrityMonitor:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start(self) -> None:
        if self._running or os.name != "nt":
            return
        self._running = True

        for p in self.watch_paths:
            if p.exists() and p.is_dir():
                t = threading.Thread(target=self._watch_worker, args=(p,), daemon=True)
                t.start()
                self._threads.append(t)

    def stop(self) -> None:
        self._running = False

    def get_recent_alerts(self, limit: int = 30) -> List[TamperEventRecord]:
        with self._lock:
            return list(reversed(self._events[-limit:]))

    def _watch_worker(self, directory: Path) -> None:
        kernel32 = ctypes.windll.kernel32
        h_dir = kernel32.CreateFileW(
            str(directory),
            0x0001,  # FILE_LIST_DIRECTORY
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        if h_dir == wintypes.HANDLE(-1).value or not h_dir:
            return

        buffer = ctypes.create_string_buffer(4096)
        bytes_returned = wintypes.DWORD()

        filter_flags = (
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_CREATION
        )

        action_names = {
            FILE_ACTION_ADDED: "CREACIÓN",
            FILE_ACTION_REMOVED: "ELIMINACIÓN",
            FILE_ACTION_MODIFIED: "MODIFICACIÓN",
            FILE_ACTION_RENAMED_OLD_NAME: "RENOMBRADO_ORIGEN",
            FILE_ACTION_RENAMED_NEW_NAME: "RENOMBRADO_DESTINO"
        }

        try:
            while self._running:
                success = kernel32.ReadDirectoryChangesW(
                    h_dir,
                    ctypes.byref(buffer),
                    len(buffer),
                    False,  # Non-recursive for performance
                    filter_flags,
                    ctypes.byref(bytes_returned),
                    None,
                    None
                )

                if not success or bytes_returned.value == 0:
                    time.sleep(0.5)
                    continue

                # Parse FILE_NOTIFY_INFORMATION structures
                offset = 0
                while offset < bytes_returned.value:
                    info = FILE_NOTIFY_INFORMATION.from_buffer_copy(buffer, offset)
                    file_name = info.FileName[: info.FileNameLength // 2]
                    full_path = directory / file_name

                    action_str = action_names.get(info.Action, "DESCONOCIDO")
                    ext = full_path.suffix.lower()
                    is_crit = ext in self.CRITICAL_EXTENSIONS

                    severity = "INFO"
                    if is_crit:
                        if info.Action == FILE_ACTION_ADDED:
                            severity = "CRITICAL"
                            msg = f"¡Alerta Anti-Tamper! Se creó un nuevo binario crítico en el sistema: {full_path}"
                        elif info.Action == FILE_ACTION_MODIFIED:
                            severity = "WARNING"
                            msg = f"Modificación detectada en controlador o librería de sistema: {full_path}"
                        elif info.Action == FILE_ACTION_REMOVED:
                            severity = "WARNING"
                            msg = f"Eliminación de binario en directorio de sistema: {full_path}"
                        else:
                            msg = f"Acción de archivo en ruta crítica: {full_path}"
                    else:
                        msg = f"Evento de archivo ({action_str}) en {full_path.name}"

                    event = TamperEventRecord(
                        timestamp=time.time(),
                        time_str=time.strftime("%Y-%m-%d %H:%M:%S"),
                        action=action_str,
                        target_path=str(full_path),
                        is_critical_extension=is_crit,
                        severity=severity,
                        alert_message=msg
                    )

                    with self._lock:
                        self._events.append(event)
                        if len(self._events) > 500:
                            self._events.pop(0)

                    if info.NextEntryOffset == 0:
                        break
                    offset += info.NextEntryOffset

        except Exception:
            pass
        finally:
            kernel32.CloseHandle(h_dir)
