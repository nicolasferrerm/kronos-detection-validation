# emulators/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any
from core.config import KronosConfig


class BaseEmulator(ABC):
    """Abstract Base Class for all KRONOS Attack Emulators."""

    def __init__(
        self,
        name: str,
        mitre_id: str,
        event_id: str,
        description: str,
        config: KronosConfig,
    ):
        self.name = name
        self.mitre_id = mitre_id
        self.event_id = event_id
        self.description = description
        self.config = config

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """
        Executes the safe attack emulation.

        Returns:
            Dict containing:
                "status": "success" | "failed"
                "timestamp": str (ISO format)
                "username_targeted": str
                "details": Dict of specific execution info
                "error": str (optional)
        """
        pass
