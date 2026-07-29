# verifiers/splunk.py
import time
import requests
from typing import Dict, Any
from verifiers.base import BaseVerifier
from core.logger import logger
from core.config import KronosConfig


class SplunkVerifier(BaseVerifier):
    """Queries Splunk Enterprise Search API to verify Event ID detection."""

    def __init__(self, config: KronosConfig):
        super().__init__(name="Splunk SIEM Verifier", config=config)

    def verify_detection(
        self, emulation_result: Dict[str, Any], event_id: str, mitre_id: str
    ) -> Dict[str, Any]:
        splunk_cfg = self.config.siem.splunk
        base_url = f"https://{splunk_cfg.host}:{splunk_cfg.port}/services/search/jobs"

        # 1. Build Query
        username = emulation_result.get("username_targeted", "")
        query = f"search index={splunk_cfg.index} EventCode={event_id} "
        if username and username != "N/A":
            query += f'TargetUserName="*{username}*"'

        logger.info(f"Connecting to Splunk host {splunk_cfg.host}:{splunk_cfg.port}...")
        logger.info(f"Querying: {query}")

        try:
            # Create search job
            auth = (splunk_cfg.username, splunk_cfg.password)
            post_data = {"search": query, "output_mode": "json", "exec_mode": "normal"}

            res = requests.post(
                base_url,
                data=post_data,
                auth=auth,
                verify=splunk_cfg.verify_ssl,
                timeout=10,
            )
            res.raise_for_status()
            sid = res.json().get("sid")

            # Wait for search job to complete
            job_url = f"{base_url}/{sid}"
            status = "QUEUED"
            retries = 10
            while status not in ["DONE", "FAILED"] and retries > 0:
                job_res = requests.get(
                    job_url,
                    params={"output_mode": "json"},
                    auth=auth,
                    verify=splunk_cfg.verify_ssl,
                    timeout=5,
                )
                job_res.raise_for_status()
                status = (
                    job_res.json()
                    .get("entry", [{}])[0]
                    .get("content", {})
                    .get("dispatchState", "")
                )
                time.sleep(1)
                retries -= 1

            if status != "DONE":
                raise Exception("Splunk search job failed or timed out.")

            # Fetch results
            results_url = f"{job_url}/results"
            results_res = requests.get(
                results_url,
                params={"output_mode": "json", "count": 10},
                auth=auth,
                verify=splunk_cfg.verify_ssl,
                timeout=5,
            )
            results_res.raise_for_status()
            results = results_res.json().get("results", [])

            detected = len(results) > 0
            if detected:
                logger.success(
                    f"Splunk verification success! Found {len(results)} matching log(s)."
                )
            else:
                logger.warning(
                    "Splunk verification query completed: No matching logs found."
                )

            return {
                "detected": detected,
                "query_used": query,
                "log_entries_found": len(results),
                "raw_logs": results,
                "details": f"Splunk job {sid} finished. Status: {status}.",
            }

        except Exception as e:
            logger.error(f"Failed to query Splunk API: {e}")
            return {
                "detected": False,
                "query_used": query,
                "log_entries_found": 0,
                "raw_logs": [],
                "details": f"Error connecting to Splunk: {str(e)}",
            }
