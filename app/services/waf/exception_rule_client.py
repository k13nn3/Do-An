import os
import requests
from datetime import datetime

WAF_API_URL = os.getenv("WAF_API_URL", "http://192.168.10.138:5001/api/exception/rule")
WAF_API_TOKEN = os.getenv("WAF_API_TOKEN", "testkey123")

def apply_exception_rule(rule: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    headers = {"X-API-TOKEN": WAF_API_TOKEN}

    try:
        res = requests.post(
            WAF_API_URL,
            json={"rule": rule},
            headers=headers,
            timeout=10
        )
    except Exception as e:
        return False, ts, "request_failed", str(e)

    try:
        data = res.json()
    except Exception:
        data = {}

    if res.status_code == 200:
        return True, ts, data.get("reload_status", "unknown"), None
    else:
        return False, ts, data.get("stage", "unknown"), data.get("message", res.text)
