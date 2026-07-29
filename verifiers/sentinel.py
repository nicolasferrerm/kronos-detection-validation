# verifiers/sentinel.py
import requests
from typing import Dict, Any
from verifiers.base import BaseVerifier
from core.logger import logger
from core.config import KronosConfig


class SentinelVerifier(BaseVerifier):
    """Queries Microsoft Sentinel (Log Analytics) API using KQL queries."""

    def __init__(self, config: KronosConfig):
        super().__init__(name="Microsoft Sentinel Verifier", config=config)

    def verify_detection(
        self, emulation_result: Dict[str, Any], event_id: str, mitre_id: str
    ) -> Dict[str, Any]:
        sentinel_cfg = self.config.siem.sentinel
        workspace_id = sentinel_cfg.workspace_id

        # 1. Get OAuth Access Token for Log Analytics
        token_url = (
            f"https://login.microsoftonline.com/{sentinel_cfg.tenant_id}/oauth2/token"
        )
        token_data = {
            "grant_type": "client_credentials",
            "client_id": sentinel_cfg.client_id,
            "client_secret": sentinel_cfg.client_secret,
            "resource": "https://api.loganalytics.io",
        }

        username = emulation_result.get("username_targeted", "")

        # 2. Build KQL Query
        if event_id == "Consent to application":
            kql = "AuditLogs | where OperationName == 'Consent to application'"
            if username and username != "N/A":
                kql += f" | where TargetResources contains '{username}' or InitiatedBy contains '{username}'"
        else:
            kql = f"SecurityEvent | where EventID == {event_id}"
            if username and username != "N/A":
                kql += f" | where TargetUserName has '{username}'"

        kql += " | order by TimeGenerated desc | take 10"

        logger.info(
            f"Authenticating to Azure AD tenant '{sentinel_cfg.tenant_id}' for Sentinel..."
        )
        logger.info(f"Querying Log Analytics Workspace: {workspace_id}")
        logger.info(f"KQL Query: {kql}")

        try:
            # Authenticate
            token_res = requests.post(token_url, data=token_data, timeout=5)
            token_res.raise_for_status()
            access_token = token_res.json().get("access_token")

            # Run Query
            query_url = (
                f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
            )
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            query_payload = {"query": kql}

            res = requests.post(
                query_url, json=query_payload, headers=headers, timeout=10
            )
            res.raise_for_status()

            tables = res.json().get("tables", [])
            rows = []
            if tables:
                columns = [col.get("name") for col in tables[0].get("columns", [])]
                for row in tables[0].get("rows", []):
                    rows.append(dict(zip(columns, row)))

            detected = len(rows) > 0
            if detected:
                logger.success(
                    f"Microsoft Sentinel verification success! Found {len(rows)} matching log(s)."
                )
            else:
                logger.warning(
                    "Microsoft Sentinel verification completed: No matching logs found."
                )

            return {
                "detected": detected,
                "query_used": kql,
                "log_entries_found": len(rows),
                "raw_logs": rows,
                "details": f"Sentinel query executed. Returned {len(rows)} rows from active index.",
            }

        except Exception as e:
            logger.error(f"Failed to query Microsoft Sentinel API: {e}")
            return {
                "detected": False,
                "query_used": kql,
                "log_entries_found": 0,
                "raw_logs": [],
                "details": f"Error connecting to Sentinel: {str(e)}",
            }
