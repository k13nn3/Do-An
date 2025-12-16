import json
import os
import threading

_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../../"))
STORE_DIR = os.path.join(ROOT_DIR, "data")
STORE_PATH = os.path.join(STORE_DIR, "alert_logs.json")

os.makedirs(STORE_DIR, exist_ok=True)

if os.path.exists(STORE_PATH):
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            _LOGS = json.load(f)
        if not isinstance(_LOGS, dict):
            _LOGS = {}
    except json.JSONDecodeError:
        _LOGS = {}
else:
    _LOGS = {}


def _save():
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(_LOGS, f, ensure_ascii=False, indent=2)


def save_alert_log(alert_id: str, data: dict):
    if not alert_id or not isinstance(data, dict):
        return
    with _lock:
        _LOGS[alert_id] = data
        _save()


def remove_alert_log(alert_id: str):
    if not alert_id:
        return
    with _lock:
        if alert_id in _LOGS:
            del _LOGS[alert_id]
            _save()


def remove_alerts(alert_ids: list[str]):
    if not alert_ids:
        return
    with _lock:
        for aid in alert_ids:
            _LOGS.pop(aid, None)
        _save()


# 🔥 NEW: Đánh dấu False Positive
def mark_false_positive(alert_id: str):
    if not alert_id:
        return False

    with _lock:
        info = _LOGS.get(alert_id)
        if not info:
            return False

        info["status"] = "fp"
        _save()

    return True

def clear_logs():
    """
    Xóa toàn bộ logs khỏi RAM và JSON file
    """
    global _LOGS
    with _lock:
        _LOGS = {}
        _save()
