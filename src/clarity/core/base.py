from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

class Severity(str, Enum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass(slots=True)
class DiagnosticItem:
    id: str
    category: str
    title: str
    severity: Severity
    summary: str
    details: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    action_id: Optional[str] = None

@dataclass(slots=True)
class DiagnosticReport:
    engine_name: str
    timestamp: datetime = field(default_factory=datetime.now)
    items: List[DiagnosticItem] = field(default_factory=list)

    @property
    def highest_severity(self) -> Severity:
        if any(i.severity == Severity.CRITICAL for i in self.items):
            return Severity.CRITICAL
        if any(i.severity == Severity.WARNING for i in self.items):
            return Severity.WARNING
        if any(i.severity == Severity.INFO for i in self.items):
            return Severity.INFO
        return Severity.OK

class BaseDiagnosticEngine(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the diagnostic engine."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name."""
        pass

    @abstractmethod
    def run(self) -> DiagnosticReport:
        """Executes the diagnostic inspection and returns a structured report."""
        pass
