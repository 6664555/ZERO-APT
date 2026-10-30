"""
monitor_tools.py - Defender ELK log query utility
Query logic extracted from scripts/ELK_analyst.py, LLM part removed, packaged as pure utility functions
"""

import os
import json
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")


def get_logs(minutes: int = 1, index: str = "winlogbeat-*") -> list:
    """Fetch logs from Elasticsearch for the last N minutes

    Args:
        minutes: Time range (minutes), default 1
        index: Index pattern, default winlogbeat-*

    Returns:
        list[dict]: List of log _source
    """
    time_range = f"now-{minutes}m"
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 100
    }

    try:
        resp = requests.post(
            f"{ES_URL}/{index}/_search",
            headers={"Content-Type": "application/json"},
            json=query,
            timeout=30
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            return [hit["_source"] for hit in hits]
        else:
            print(f"[monitor] Query failed: {resp.status_code}")
            return []
    except Exception as e:
        print(f"[monitor] Connection failed: {e}")
        return []


def format_logs(logs: list, max_events: int = 10) -> str:
    """Format log list into readable text

    Args:
        logs: Log list returned by get_logs
        max_events: Maximum number of events to output, default 10

    Returns:
        str: Formatted log text
    """
    if not logs:
        return "No logs"

    lines = [f"Total {len(logs)} logs, showing first {min(max_events, len(logs))}:"]
    for log in logs[:max_events]:
        ts = log.get("@timestamp", "N/A")
        provider = log.get("event", {}).get("provider", "")
        event_id = ""
        winlog = log.get("winlog", {})
        if isinstance(winlog, dict):
            event_id = winlog.get("event_id", "")
        message = log.get("message", "")
        msg_short = message[:120] if message else ""
        lines.append(f"[{ts}] provider={provider} event_id={event_id} | {msg_short}")

    return "\n".join(lines)


if __name__ == "__main__":
    logs = get_logs(minutes=1)
    print(format_logs(logs))
