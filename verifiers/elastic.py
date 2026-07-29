# verifiers/elastic.py
import requests
from typing import Dict, Any
from verifiers.base import BaseVerifier
from core.logger import logger
from core.config import KronosConfig


class ElasticVerifier(BaseVerifier):
    """Queries Elasticsearch REST API to verify security logs."""

    def __init__(self, config: KronosConfig):
        super().__init__(name="Elasticsearch SIEM Verifier", config=config)

    def verify_detection(
        self, emulation_result: Dict[str, Any], event_id: str, mitre_id: str
    ) -> Dict[str, Any]:
        elastic_cfg = self.config.siem.elastic
        search_url = f"{elastic_cfg.host}/{elastic_cfg.index}/_search"

        username = emulation_result.get("username_targeted", "")

        # Build elastic query DSL
        query_dsl = {
            "query": {"bool": {"must": [{"match": {"winlog.event_id": event_id}}]}},
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        if username and username != "N/A":
            query_dsl["query"]["bool"]["must"].append(
                {"match": {"winlog.event_data.TargetUserName": username}}
            )

        logger.info(f"Connecting to Elasticsearch host {elastic_cfg.host}...")
        logger.info(f"Querying Index '{elastic_cfg.index}' for Event ID: {event_id}")

        headers = {"Content-Type": "application/json"}
        if elastic_cfg.api_key:
            headers["Authorization"] = f"ApiKey {elastic_cfg.api_key}"

        try:
            res = requests.post(
                search_url,
                json=query_dsl,
                headers=headers,
                verify=elastic_cfg.verify_ssl,
                timeout=10,
            )
            res.raise_for_status()

            hits_data = res.json().get("hits", {})
            hits = hits_data.get("hits", [])
            total_hits = hits_data.get("total", {}).get("value", 0)

            detected = total_hits > 0
            if detected:
                logger.success(
                    f"Elasticsearch verification success! Found {total_hits} matching log(s)."
                )
            else:
                logger.warning(
                    "Elasticsearch verification completed: No matching logs found."
                )

            raw_logs = [hit.get("_source", {}) for hit in hits]

            return {
                "detected": detected,
                "query_used": str(query_dsl),
                "log_entries_found": total_hits,
                "raw_logs": raw_logs,
                "details": f"Elastic query completed. Search duration: {res.json().get('took', 0)}ms.",
            }

        except Exception as e:
            logger.error(f"Failed to query Elasticsearch API: {e}")
            return {
                "detected": False,
                "query_used": str(query_dsl),
                "log_entries_found": 0,
                "raw_logs": [],
                "details": f"Error connecting to Elasticsearch: {str(e)}",
            }
