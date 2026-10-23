from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

@dataclass
class TransactionRecord:
    timestamp: str
    action_id: str
    action_title: str
    saved_state: Dict[str, Any]
    rolled_back: bool = False
    rolled_back_at: Optional[str] = None

class StateManager:
    def __init__(self, state_file_path: Path):
        self.state_file = state_file_path
        self._ensure_file()

    def _ensure_file(self) -> None:
        if not self.state_file.exists():
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self._write_records([])

    def _read_records(self) -> List[Dict[str, Any]]:
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write_records(self, records: List[Dict[str, Any]]) -> None:
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)

    def record_apply(self, action_id: str, action_title: str, state: Dict[str, Any]) -> None:
        records = self._read_records()
        record = TransactionRecord(
            timestamp=datetime.now().isoformat(),
            action_id=action_id,
            action_title=action_title,
            saved_state=state,
            rolled_back=False,
        )
        records.append(asdict(record))
        self._write_records(records)

    def get_latest_state(self, action_id: str) -> Optional[Dict[str, Any]]:
        records = self._read_records()
        for record in reversed(records):
            if record["action_id"] == action_id and not record.get("rolled_back", False):
                return record.get("saved_state")
        return None

    def mark_rolled_back(self, action_id: str) -> None:
        records = self._read_records()
        for record in reversed(records):
            if record["action_id"] == action_id and not record.get("rolled_back", False):
                record["rolled_back"] = True
                record["rolled_back_at"] = datetime.now().isoformat()
                break
        self._write_records(records)

    def get_all_active_transactions(self) -> List[Dict[str, Any]]:
        return [r for r in self._read_records() if not r.get("rolled_back", False)]
