# emulators/entra_app_grant.py
import datetime
import requests
from typing import Dict, Any
from emulators.base import BaseEmulator
from core.logger import logger
from core.config import KronosConfig


class EntraAppGrantEmulator(BaseEmulator):
    """Emulates Microsoft Entra ID Malicious Application Registration and Consent Grant (MITRE T1528 / T1098.002)."""

    def __init__(self, config: KronosConfig):
        super().__init__(
            name="Entra ID OAuth App Consent Emulation",
            mitre_id="T1098.002",
            event_id="Consent to application",
            description="Simulates registering an OAuth application and granting access permissions in Entra ID.",
            config=config,
        )

    def run(self) -> Dict[str, Any]:
        logger.info(f"Starting {self.name} (MITRE {self.mitre_id})...")
        timestamp = (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

        tenant_id = self.config.entra_id.tenant_id
        client_id = self.config.entra_id.client_id
        client_secret = self.config.entra_id.client_secret

        # Check if Azure AD credentials are configured
        real_credentials_exist = False
        if (
            self.config.execution.allow_live_actions
            and tenant_id
            and client_id
            and client_secret
            and "00000000" not in tenant_id
        ):
            real_credentials_exist = True

        if real_credentials_exist:
            logger.info(
                f"Microsoft Entra ID credentials detected for Tenant '{tenant_id}'. Attempting API connection..."
            )
            try:
                # 1. Authenticate to Microsoft Graph API
                token_url = (
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
                )
                token_data = {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                }
                token_res = requests.post(token_url, data=token_data, timeout=5)
                token_res.raise_for_status()
                access_token = token_res.json().get("access_token")

                # 2. Register mock application to trigger logs
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                }
                app_payload = {
                    "displayName": "KRONOS-Audit-App",
                    "signInAudience": "AzureADMyOrg",
                }
                app_url = "https://graph.microsoft.com/v1.0/applications"
                app_res = requests.post(
                    app_url, json=app_payload, headers=headers, timeout=5
                )
                app_res.raise_for_status()
                app_data = app_res.json()
                app_object_id = app_data.get("id")
                app_app_id = app_data.get("appId")

                # 3. Clean up immediately (delete the registered app to remain safe)
                logger.info(
                    f"OAuth Application registered successfully (ID: {app_app_id}). Cleaning up..."
                )
                delete_url = (
                    f"https://graph.microsoft.com/v1.0/applications/{app_object_id}"
                )
                requests.delete(delete_url, headers=headers, timeout=5)
                logger.success("OAuth Application cleanup completed successfully.")

                return {
                    "status": "success",
                    "timestamp": timestamp,
                    "username_targeted": "N/A (Azure Application Service Principal)",
                    "emulation_type": "real",
                    "details": {
                        "tenant_id": tenant_id,
                        "app_display_name": "KRONOS-Audit-App",
                        "app_id": app_app_id,
                        "permissions_requested": "User.Read",
                        "result_msg": "Application registration triggered. Check Entra ID Audit Logs for category 'ApplicationManagement'.",
                    },
                }
            except Exception as e:
                logger.error(f"Error during Microsoft Graph API connection: {e}")
                return {
                    "status": "failed",
                    "timestamp": timestamp,
                    "username_targeted": "N/A",
                    "emulation_type": "real",
                    "error": str(e),
                    "details": {"tenant_id": tenant_id},
                }
        else:
            # Local Simulation Mode (Portfolio demonstration)
            logger.info("Executing KRONOS Safe Emulation Protocol...")
            logger.info("[SIMULATION] Connecting to Microsoft Graph API endpoint...")
            logger.info(
                "[SIMULATION] Creating Application Registration: 'KRONOS-Enterprise-Sync-Tool'..."
            )
            logger.info(
                "[SIMULATION] Requesting delegated scopes: ['Mail.Read', 'User.Read.All', 'Files.ReadWrite.All']..."
            )
            logger.success(
                "[SIMULATION] Simulating user consent grant. Audit log event generated."
            )

            return {
                "status": "success",
                "timestamp": timestamp,
                "username_targeted": "john.doe@enterprise.onmicrosoft.com",
                "emulation_type": "simulated",
                "details": {
                    "tenant_id": "00000000-0000-0000-0000-000000000000",
                    "app_display_name": "KRONOS-Enterprise-Sync-Tool",
                    "app_id": "9abc2345-def6-7890-abcd-ef1234567890",
                    "permissions_requested": "Mail.Read, User.Read.All, Files.ReadWrite.All",
                    "result_msg": "Simulated OAuth App registration and user consent completed safely.",
                },
            }
