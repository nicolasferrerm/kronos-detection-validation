# reports/generator.py
import os
import json
import datetime
from typing import List, Dict, Any
from jinja2 import Template
from core.logger import logger


def generate_report(
    results: List[Dict[str, Any]],
    verifier_name: str,
    output_dir: str = "./reports/output",
) -> str:
    """
    Generates an interactive HTML Purple Team report from KRONOS execution results.

    Args:
        results: List of execution dicts.
        verifier_name: The SIEM verifier name used.
        output_dir: Path to write the output report.

    Returns:
        str: Absolute path to the generated HTML report.
    """
    logger.info("Aggregating test metrics for report compilation...")

    # 1. Calculate Summary Stats
    total_runs = len(results)
    detected = sum(1 for r in results if r.get("verifier", {}).get("detected", False))
    undetected = total_runs - detected
    rate = int((detected / total_runs) * 100) if total_runs > 0 else 0

    summary = {
        "total_runs": total_runs,
        "detected": detected,
        "undetected": undetected,
        "rate": rate,
    }

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    # 2. Format Raw Logs for Jinja2 (Converting dict logs to indented JSON strings)
    processed_results = []
    for item in results:
        processed_item = item.copy()
        processed_item["verifier_name"] = verifier_name

        emulation_result = dict(item.get("emulation_result", {}))
        details = dict(emulation_result.get("details", {}))
        details.setdefault("domain_controller", "N/A")
        details.setdefault("encryption_requested", "N/A")
        details.setdefault("result_msg", "Synthetic evidence generated")
        emulation_result["details"] = details
        emulation_result.setdefault("username_targeted", "N/A")
        processed_item["emulation_result"] = emulation_result

        verifier = dict(item.get("verifier", {}))
        raw_logs = verifier.get("raw_logs", [])
        if raw_logs:
            verifier["raw_logs_json"] = json.dumps(raw_logs, indent=4)
        else:
            verifier["raw_logs_json"] = ""
        processed_item["verifier"] = verifier

        processed_results.append(processed_item)

    # 3. Read Template
    template_path = os.path.join(os.path.dirname(__file__), "template.html")
    if not os.path.exists(template_path):
        logger.error(f"Report template not found at: {template_path}")
        raise FileNotFoundError("template.html template is missing.")

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    # 4. Render Template
    logger.info("Compiling HTML template with Jinja2...")
    template = Template(template_content)
    rendered_html = template.render(
        timestamp=timestamp, summary=summary, results=processed_results
    )

    # 5. Write to File
    os.makedirs(output_dir, exist_ok=True)
    report_filename = (
        f"kronos_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    report_path = os.path.join(output_dir, report_filename)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    logger.success(
        f"Purple Team Security Report generated successfully: {os.path.abspath(report_path)}"
    )
    return os.path.abspath(report_path)
