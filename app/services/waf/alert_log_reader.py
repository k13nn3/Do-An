import json
import os
from typing import List, Dict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../../"))
DATA_DIR = os.path.join(BOT_DIR, "data")

ALERT_LOG_PATH = os.path.join(DATA_DIR, "alert_logs.json")


def get_logs_by_alert_id(alert_id: str) -> List[Dict]:
    """
    Đọc alert_logs.json theo alert_id
    ❌ BỎ data
    ❌ BỎ match
    """
    if not os.path.exists(ALERT_LOG_PATH):
        return []

    with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
        store = json.load(f)

    alert = store.get(alert_id)
    if not alert:
        return []

    clean_logs = []

    for req in alert.get("requests", []):
        clean_logs.append({
            "request_id": req.get("request_id"),
            "uri": req.get("uri"),
            "method": req.get("method", ""),
            "request_headers": req.get("request_headers", []),
            "request_body": req.get("request_body", ""),
        })

    return clean_logs
