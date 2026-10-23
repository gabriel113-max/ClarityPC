from __future__ import annotations

import json
import os
import subprocess
import winreg
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

APP_NAME = "ClarityPC"
APP_VERSION = "0.2.0"
APP_ORGANIZATION = "OpenClarity"

SILENT_CREATION_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0

DEFAULT_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
DEFAULT_BACKUP_DIR = DEFAULT_DATA_DIR / "backups"
DEFAULT_REPORTS_DIR = DEFAULT_DATA_DIR / "reports"
DEFAULT_STATE_FILE = DEFAULT_DATA_DIR / "transactions.json"
DEFAULT_SETTINGS_FILE = DEFAULT_DATA_DIR / "settings.json"

@dataclass
class ClaritySettings:
    language: str = "es"
    theme: str = "dark"
    autostart: bool = False
    auto_tdr_guard: bool = True
    auto_timer_boost: bool = False
    gpu_safe_wattage: int = 100
    telemetry_interval_sec: float = 1.0

    @classmethod
    def load(cls, path: Path = DEFAULT_SETTINGS_FILE) -> ClaritySettings:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            except Exception:
                pass
        return cls()

    def save(self, path: Path = DEFAULT_SETTINGS_FILE) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(asdict(self), f, indent=2)
            return True
        except Exception:
            return False

    def sync_autostart_registry(self) -> bool:
        """Adds or removes ClarityPC from HKCU Run key for automatic Windows startup."""
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_exe = Path(r"C:\Users\gabri\ClarityPC\dist\ClarityPC\ClarityPC.exe")
        if not app_exe.exists():
            app_exe = Path(os.environ.get("USERPROFILE", "")) / "OneDrive" / "Desktop" / "ClarityPC.bat"

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as key:
                if self.autostart:
                    winreg.SetValueEx(key, "ClarityPC", 0, winreg.REG_SZ, f'"{app_exe}"')
                else:
                    try:
                        winreg.DeleteValue(key, "ClarityPC")
                    except FileNotFoundError:
                        pass
            return True
        except Exception:
            return False

@dataclass(slots=True)
class ClarityConfig:
    data_dir: Path = DEFAULT_DATA_DIR
    backup_dir: Path = DEFAULT_BACKUP_DIR
    reports_dir: Path = DEFAULT_REPORTS_DIR
    state_file: Path = DEFAULT_STATE_FILE
    settings_file: Path = DEFAULT_SETTINGS_FILE
    dry_run: bool = False
    auto_create_restore_point: bool = True
    selected_companion: str = "byte_cat"
    companion_enabled: bool = True
    telemetry_enabled: bool = True

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
