# verifiers/mock.py
import datetime
from typing import Dict, Any
from verifiers.base import BaseVerifier
from core.logger import logger
from core.config import KronosConfig


class MockVerifier(BaseVerifier):
    """Simulates a SIEM response for testing/demonstration without an active connection."""

    def __init__(self, config: KronosConfig):
        super().__init__(name="Mock SIEM Verifier", config=config)

    def verify_detection(
        self, emulation_result: Dict[str, Any], event_id: str, mitre_id: str
    ) -> Dict[str, Any]:
        logger.info(f"Querying Mock SIEM for event: {event_id} (MITRE {mitre_id})...")

        # If the emulation itself failed, the SIEM won't have logs
        if emulation_result.get("status") != "success":
            logger.warning(
                "Emulation status was 'failed'. Mock SIEM returns no records."
            )
            return {
                "detected": False,
                "query_used": f"index=security EventCode={event_id} status=failed",
                "log_entries_found": 0,
                "raw_logs": [],
                "details": "No logs found because the emulation failed to generate indicators.",
            }

        # Build realistic logs based on event type
        username = emulation_result.get("username_targeted", "unknown")
        details = emulation_result.get("details", {})
        timestamp = (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

        query_used = ""
        mock_log = {}

        if event_id == "4768":  # AS-REP Roasting
            query_used = f"index=security EventCode=4768 TargetUserName='{username}' PreAuthType=0"
            mock_log = {
                "@timestamp": timestamp,
                "event": {
                    "code": "4768",
                    "provider": "Microsoft-Windows-Security-Auditing",
                },
                "winlog": {
                    "event_data": {
                        "TargetUserName": username,
                        "TargetDomainName": details.get("domain", "domain.local"),
                        "PreAuthType": "0",  # No pre-auth
                        "TicketOptions": "0x40810010",
                        "TicketEncryptionType": "0x17",  # RC4-HMAC
                        "IpAddress": "192.168.1.45",
                    },
                    "computer_name": details.get(
                        "domain_controller", "dc01.domain.local"
                    ),
                },
            }
        elif event_id == "4769":  # Kerberoasting
            query_used = f"index=security EventCode=4769 ServiceName='{details.get('spn_targeted', 'unknown')}' TicketEncryptionType=0x17"
            mock_log = {
                "@timestamp": timestamp,
                "event": {
                    "code": "4769",
                    "provider": "Microsoft-Windows-Security-Auditing",
                },
                "winlog": {
                    "event_data": {
                        "TargetUserName": f"{username}@domain.local",
                        "ServiceName": details.get(
                            "spn_targeted", "MSSQLSvc/sql01.domain.local:1433"
                        ),
                        "TicketOptions": "0x40810000",
                        "TicketEncryptionType": "0x17",  # RC4
                        "IpAddress": "192.168.1.45",
                        "Status": "0x0",
                    },
                    "computer_name": details.get(
                        "domain_controller", "dc01.domain.local"
                    ),
                },
            }
        else:  # Entra ID App Consent
            query_used = f"AzureDiagnostics | where Category == 'AuditLogs' and OperationName == 'Consent to application' and TargetResources contains '{username}'"
            mock_log = {
                "time": timestamp,
                "category": "AuditLogs",
                "operationName": "Consent to application",
                "identity": {"user": {"userPrincipalName": username}},
                "properties": {
                    "targetResources": [
                        {
                            "displayName": details.get(
                                "app_display_name", "KRONOS-Enterprise-Sync-Tool"
                            ),
                            "id": details.get(
                                "app_id", "9abc2345-def6-7890-abcd-ef1234567890"
                            ),
                            "type": "Application",
                        }
                    ],
                    "initiatedBy": {"user": {"userPrincipalName": username}},
                    "result": "success",
                },
            }

        logger.success(f"Mock SIEM match found! Query: {query_used}")
        return {
            "detected": True,
            "query_used": query_used,
            "log_entries_found": 1,
            "raw_logs": [mock_log],
            "details": "Detection verified: Corresponding security event logs were discovered in SIEM database.",
        }
