import json
import os
import threading
from datetime import datetime
from app.services.waf.alert_log_store import remove_alerts, _LOGS

_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../../"))
STORE_DIR = os.path.join(ROOT_DIR, "data")
STORE_PATH = os.path.join(STORE_DIR, "cases.json")

os.makedirs(STORE_DIR, exist_ok=True)

if os.path.exists(STORE_PATH):
    try:
        with open(STORE_PATH, "r") as f:
            _CASES = json.load(f)
        if not isinstance(_CASES, dict):
            _CASES = {}
    except json.JSONDecodeError:
        _CASES = {}
else:
    _CASES = {}


def _save():
    with open(STORE_PATH, "w") as f:
        json.dump(_CASES, f, indent=2)


def _ensure_schema(ip: str):
    updated = False
    cases = _CASES.get(ip)

    if isinstance(cases, dict):
        _CASES[ip] = [cases]
        cases = _CASES[ip]
        updated = True

    if cases is None or not isinstance(cases, list):
        _CASES[ip] = []
        updated = True

    for c in _CASES[ip]:
        if "case_id" not in c:
            c["case_id"] = ""
            updated = True
        if "status" not in c:
            c["status"] = "open"
            updated = True
        if "alerts" not in c or not isinstance(c["alerts"], list):
            c["alerts"] = []
            updated = True
        if "created_at" not in c:
            c["created_at"] = datetime.utcnow().isoformat()
            updated = True
        if "closed_at" not in c:
            c["closed_at"] = None
            updated = True

    if updated:
        _save()


def get_case(ip: str):
    if not ip:
        return None
    with _lock:
        _ensure_schema(ip)
        for case in reversed(_CASES.get(ip, [])):
            if case.get("status") == "open":
                return case
        return None


def save_case(ip: str, case_id: str, status: str = "open"):
    if not ip or not case_id:
        return
    with _lock:
        _ensure_schema(ip)
        new_case = {
            "case_id": case_id,
            "status": status,
            "alerts": [],
            "created_at": datetime.utcnow().isoformat(),
            "closed_at": None,
        }
        _CASES[ip].append(new_case)
        _save()


def append_alert(ip: str, alert_id: str):
    if not ip or not alert_id:
        return
    with _lock:
        _ensure_schema(ip)
        for case in reversed(_CASES[ip]):
            if case["status"] == "open":
                if alert_id not in case["alerts"]:
                    case["alerts"].append(alert_id)
                    _save()
                return


def update_status(ip: str, status: str):
    if not ip:
        return
    with _lock:
        _ensure_schema(ip)
        for case in reversed(_CASES[ip]):
            if case.get("status") == "open":
                case["status"] = status
                if status == "closed":
                    case["closed_at"] = datetime.utcnow().isoformat()
                    remove_alerts(case.get("alerts"))
                _save()
                return


# 🔥 NEW: Gỡ alert khỏi case khi mark-fp
def remove_alert_from_cases(alert_id: str):
    if not alert_id:
        return False

    alert_info = _LOGS.get(alert_id)
    if not alert_info:
        return False

    ip = alert_info.get("client_ip")
    if not ip:
        return False

    with _lock:
        _ensure_schema(ip)
        for case in _CASES[ip]:
            alerts = case.get("alerts", [])
            if alert_id in alerts:
                alerts.remove(alert_id)
                case["alerts"] = alerts
                _save()
                return True

    return False


def list_not_confirm():
    with _lock:
        result = []
        for ip, cases in _CASES.items():
            _ensure_schema(ip)
            for case in cases:
                if case["status"] == "open":
                    result.append({
                        "ip": ip,
                        "case_id": case["case_id"],
                        "status": case["status"],
                        "alerts": case["alerts"],
                        "created_at": case.get("created_at"),
                    })
        return result
