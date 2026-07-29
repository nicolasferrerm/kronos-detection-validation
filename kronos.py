#!/usr/bin/env python
# kronos.py
import os
import sys
import time
import argparse
import datetime

# Add root folder to sys.path to allow execution from outside
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.logger import logger, Colors
from core.config import load_config
from emulators import ASREPRoastEmulator, KerberoastEmulator, EntraAppGrantEmulator
from verifiers import MockVerifier, SplunkVerifier, ElasticVerifier, SentinelVerifier
from reports.generator import generate_report

BANNER = rf"""
{Colors.MAGENTA}  _  _______   ____  _   _  ____   _____
 | |/ /  __ \ / __ \| \ | |/ __ \ / ____|
 | ' /| |__) | |  | |  \| | |  | | (___
 |  < |  _  /| |  | | . ` | |  | |\___ \
 | . \| | \ \| |__| | |\  | |__| |____) |
 |_|\_\_|  \_\\____/|_| \_|\____/|_____/

   AD & Entra ID Purple Teaming Framework
   Developed by Nicolas Ferrer
{Colors.RESET}"""


def main():
    print(BANNER)

    # 1. Parse Arguments
    parser = argparse.ArgumentParser(
        description="KRONOS Purple Team Detection Validation Framework"
    )
    parser.add_argument(
        "--emulator",
        type=str,
        default="all",
        choices=["asrep", "kerberoast", "entra_grant", "all"],
        help="Specify which attack vector to emulate (default: all)",
    )
    parser.add_argument(
        "--verifier",
        type=str,
        default="mock",
        choices=["mock", "splunk", "elastic", "sentinel"],
        help="Specify which SIEM provider to query (default: mock)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--no-delay",
        action="store_true",
        help="Skip log propagation delay (recommended only for mock verifications)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow authorized lab actions when supported; simulation remains the default",
    )
    parser.add_argument(
        "--confirm-authorized-lab",
        default="",
        help="Required with --live. Value: I_HAVE_WRITTEN_AUTHORIZATION",
    )

    args = parser.parse_args()

    # 2. Load Configuration
    config = load_config(args.config)
    if args.live:
        if args.confirm_authorized_lab != "I_HAVE_WRITTEN_AUTHORIZATION":
            parser.error(
                "--live requires --confirm-authorized-lab I_HAVE_WRITTEN_AUTHORIZATION"
            )
        config.execution.allow_live_actions = True
        logger.warning("Live lab actions enabled by explicit operator confirmation.")

    # 3. Instantiate Emulators
    emulators_map = {
        "asrep": ASREPRoastEmulator(config),
        "kerberoast": KerberoastEmulator(config),
        "entra_grant": EntraAppGrantEmulator(config),
    }

    selected_emulators = []
    if args.emulator == "all":
        selected_emulators = list(emulators_map.values())
    else:
        selected_emulators = [emulators_map[args.emulator]]

    # 4. Instantiate Verifier
    verifiers_map = {
        "mock": MockVerifier(config),
        "splunk": SplunkVerifier(config),
        "elastic": ElasticVerifier(config),
        "sentinel": SentinelVerifier(config),
    }
    verifier = verifiers_map[args.verifier]

    results = []

    # 5. Run Attack Emulations (Red Team)
    logger.info(
        f"Initiating Red Team phase. Running {len(selected_emulators)} emulation(s)..."
    )
    emulation_results = []
    for emulator in selected_emulators:
        emul_res = emulator.run()
        emulation_results.append((emulator, emul_res))
        print(
            f"{Colors.BLUE}------------------------------------------------------------{Colors.RESET}"
        )

    # 6. Propagation Wait
    delay = (
        0
        if args.no_delay or args.verifier == "mock"
        else config.siem.propagation_delay_seconds
    )
    if delay > 0:
        logger.info(
            f"Waiting {delay} seconds for log telemetry ingestion to propagate to the SIEM..."
        )
        for remaining in range(delay, 0, -1):
            sys.stdout.write(f"\rTime remaining: {remaining}s ")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write("\rLog propagation wait completed.\n")

    # 7. Run Detection Verifications (Blue Team)
    logger.info(f"Initiating Blue Team phase. Querying SIEM '{verifier.name}'...")
    for emulator, emul_res in emulation_results:
        verifier_res = verifier.verify_detection(
            emulation_result=emul_res,
            event_id=emulator.event_id,
            mitre_id=emulator.mitre_id,
        )

        results.append(
            {
                "emulator": {
                    "name": emulator.name,
                    "mitre_id": emulator.mitre_id,
                    "event_id": emulator.event_id,
                    "description": emulator.description,
                },
                "emulation_result": emul_res,
                "verifier": verifier_res,
            }
        )
        print(
            f"{Colors.BLUE}------------------------------------------------------------{Colors.RESET}"
        )

    # 8. Compile Report
    output_dir = config.reporting.output_dir
    report_path = generate_report(results, verifier.name, output_dir)

    # 9. Output CLI Summary Table
    print(
        f"\n{Colors.BOLD}{Colors.MAGENTA}================= KRONOS RUN EXECUTION SUMMARY ================={Colors.RESET}"
    )
    print(f"{'Attack Vector':<38} | {'MITRE ID':<10} | {'Status':<12}")
    print(f"----------------------------------------------------------------")
    for res in results:
        status_color = Colors.GREEN if res["verifier"]["detected"] else Colors.RED
        status_text = "DETECTED" if res["verifier"]["detected"] else "BLIND SPOT"
        print(
            f"{res['emulator']['name']:<38} | {res['emulator']['mitre_id']:<10} | {status_color}{status_text:<12}{Colors.RESET}"
        )
    print(
        f"{Colors.BOLD}{Colors.MAGENTA}================================================================{Colors.RESET}"
    )
    print(f"Interactive dashboard: {report_path}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("KRONOS execution cancelled by operator.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"KRONOS encountered an unhandled exception: {e}")
        sys.exit(1)
