from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class OptimizationCategory(str, Enum):
    SYSTEM = "system"
    GAMING = "gaming"
    LEGACY_PC = "legacy_pc"
    STORAGE = "storage"
    PRIVACY = "privacy"
    NETWORK = "network"

class OptimizationImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass(slots=True)
class OptimizationResult:
    success: bool
    message: str
    action_id: str
    saved_state: Optional[Dict[str, Any]] = None

@dataclass(slots=True)
class DryRunPreview:
    action_id: str
    operations: List[str]
    affected_targets: List[str]
    rollback_guarantee: str

class BaseOptimizationAction(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        """Unique key for the action."""
        pass

    @property
    @abstractmethod
    def title(self) -> str:
        """Brief descriptive title."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Plain language explanation of what the action does."""
        pass

    @property
    @abstractmethod
    def why_it_matters(self) -> str:
        """Technical reasoning and performance impact."""
        pass

    @property
    @abstractmethod
    def category(self) -> OptimizationCategory:
        """Categorization tag."""
        pass

    @property
    @abstractmethod
    def impact(self) -> OptimizationImpact:
        """Impact level."""
        pass

    @abstractmethod
    def is_applicable(self) -> bool:
        """Whether this action is valid for the current OS/hardware environment."""
        pass

    @abstractmethod
    def is_applied(self) -> bool:
        """Checks if the optimization is already active."""
        pass

    @abstractmethod
    def dry_run(self) -> DryRunPreview:
        """Returns preview of commands, registry keys, or service modifications."""
        pass

    @abstractmethod
    def apply(self) -> OptimizationResult:
        """Applies the change and records previous state for rollback."""
        pass

    @abstractmethod
    def rollback(self, saved_state: Dict[str, Any]) -> OptimizationResult:
        """Reverts the change using the recorded state."""
        pass
