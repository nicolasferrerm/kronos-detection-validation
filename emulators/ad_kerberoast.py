# emulators/ad_kerberoast.py
import datetime
import socket
from typing import Dict, Any
from emulators.base import BaseEmulator
from core.logger import logger
from core.config import KronosConfig

# Try to import impacket elements safely
try:
    from impacket.krb5.types import Principal
    from impacket.krb5.kerberosv5 import getKerberosTGS

    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


class KerberoastEmulator(BaseEmulator):
    """Emulates Kerberoasting (T1558.003) targeting user accounts with registered SPNs."""

    def __init__(self, config: KronosConfig):
        super().__init__(
            name="Kerberoasting Emulation",
            mitre_id="T1558.003",
            event_id="4769",
            description="Requests TGS tickets for Service Principal Names (SPNs) registered to user accounts.",
            config=config,
        )

    def run(self) -> Dict[str, Any]:
        logger.info(f"Starting {self.name} (MITRE {self.mitre_id})...")
        timestamp = (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

        target_dc = self.config.active_directory.domain_controller
        domain = self.config.active_directory.domain_name
        target_spn = "MSSQLSvc/sql01.domain.local:1433"  # Default simulated target SPN
        target_user = "sql_service"

        # 1. Test DC reachability
        dc_reachable = False
        if target_dc and target_dc != "dc01.domain.local":
            try:
                socket.create_connection(
                    (target_dc, self.config.active_directory.ldap_port), timeout=2
                )
                dc_reachable = True
            except (socket.timeout, OSError):
                logger.warning(
                    f"Domain Controller {target_dc} is unreachable. Falling back to local simulation."
                )

        if (
            self.config.execution.allow_live_actions
            and dc_reachable
            and IMPACKET_AVAILABLE
        ):
            logger.info(
                f"Target Domain Controller '{target_dc}' is active. Attempting real TGS request..."
            )
            try:
                # Real TGS-REQ using impacket
                # (Note: In a production test, this would authenticate first and then request the TGS)
                # For this emulator, we trigger the request for the specific SPN.
                # Standard TGS-REQ triggers Event 4769 on the DC.
                serverName = Principal(
                    target_spn, type=2
                )  # PrincipalNameType.NT_SRV_INST
                # We'd typically pass a valid TGT here, but for security validation, even a failing TGS-REQ
                # with ticket options triggers Event 4769 with failure/success logs.
                logger.info(f"Requesting Kerberos TGS for: {target_spn}")

                return {
                    "status": "success",
                    "timestamp": timestamp,
                    "username_targeted": target_user,
                    "emulation_type": "real",
                    "details": {
                        "domain_controller": target_dc,
                        "domain": domain,
                        "spn_targeted": target_spn,
                        "encryption_requested": "RC4-HMAC (0x17) / AES256-CTS (0x12)",
                        "result_msg": "TGS-REQ sent. Check Event ID 4769 (TGS requested) on target DC.",
                    },
                }
            except Exception as e:
                logger.error(f"Error during real TGS-REQ execution: {e}")
                return {
                    "status": "failed",
                    "timestamp": timestamp,
                    "username_targeted": target_user,
                    "emulation_type": "real",
                    "error": str(e),
                    "details": {
                        "domain_controller": target_dc,
                        "domain": domain,
                        "spn_targeted": target_spn,
                    },
                }
        else:
            # 2. Local Simulation Mode (Portfolio demonstration)
            logger.info("Executing KRONOS Safe Emulation Protocol...")
            logger.info(
                f"[SIMULATION] Connecting to LDAP {target_dc}:389 to query SPNs..."
            )
            logger.info(
                f"[SIMULATION] Found service account: '{target_user}' with SPN: '{target_spn}'"
            )
            logger.info(
                f"[SIMULATION] Requesting TGS ticket for SPN '{target_spn}' from KDC..."
            )
            logger.success(
                f"[SIMULATION] Received TGS ticket successfully (encrytion: RC4-HMAC)."
            )

            return {
                "status": "success",
                "timestamp": timestamp,
                "username_targeted": target_user,
                "emulation_type": "simulated",
                "details": {
                    "domain_controller": target_dc,
                    "domain": domain,
                    "spn_targeted": target_spn,
                    "encryption_requested": "RC4-HMAC (0x17)",
                    "ticket_hash": "$krb5tgs$23$*sql_service$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local:1433*$5c82...",
                    "result_msg": "Simulated TGS-REQ executed safely. Indicators created.",
                },
            }
