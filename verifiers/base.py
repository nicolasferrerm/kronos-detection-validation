# verifiers/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any
from core.config import KronosConfig


class BaseVerifier(ABC):
    """Abstract Base Class for all KRONOS SIEM/Detection Verifiers."""

    def __init__(self, name: str, config: KronosConfig):
        self.name = name
        self.config = config

    @abstractmethod
    def verify_detection(
        self, emulation_result: Dict[str, Any], event_id: str, mitre_id: str
    ) -> Dict[str, Any]:
        """
        Queries the SIEM to verify if logs were generated for the specified emulation event.

        Args:
            emulation_result: Output from the emulator.run() call.
            event_id: Event ID target (e.g., "4769").
            mitre_id: MITRE ATT&CK technique code (e.g., "T1558.003").

        Returns:
            Dict containing:
                "detected": bool
                "query_used": str
                "log_entries_found": int
                "raw_logs": List[Dict]
                "details": str (status description)
        """
        pass
