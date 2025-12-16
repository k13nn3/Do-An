import re
from app.services.waf.case_store import get_case, save_case, append_alert
from app.services.elk.kibana_api import create_case, attach_alert
from app.services.elk.query_top_anomaly import get_top_anomaly_requests
from app.services.waf.alert_log_store import save_alert_log
from app.routes.waf.ai_exception import background_ai
import threading



ALERT_KEYWORDS = [
    "ModSecurity Alert Triggered",
    "event created high alert",
    "threshold_result",
]


def extract_alert_id(text):
    m = re.search(r"\*Alert ID:\*\s*`([0-9a-fA-F]+)`", text)
    return m.group(1) if m else None


def extract_ip(text):
    m = re.search(r"Client IP:\*?\s*`(\b\d{1,3}(?:\.\d{1,3}){3}\b)`", text)
    if m:
        return m.group(1)
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else None


last_alert_ts = None


def register_message_event(app):
    slack_events = app.config["SLACK_EVENTS"]
    bot_id = app.config["BOT_ID"]
    slack_client = app.config["SLACK_CLIENT"]

    @slack_events.on("message")
    def handle_message(payload):
        global last_alert_ts

        event = payload.get("event", {}) or {}
        text = event.get("text", "")
        user = event.get("user")
        ts = event.get("ts")
        channel = event.get("channel")

        # Tránh loop bot
        if user == bot_id or ts == last_alert_ts:
            return
        last_alert_ts = ts

        if not any(k in text for k in ALERT_KEYWORDS):
            return

        alert_id = extract_alert_id(text)
        ip = extract_ip(text)
        if not alert_id or not ip:
            return

        # ================== CASE LOGIC ==================
        case_info = get_case(ip)
        if not case_info or case_info.get("status") == "closed":
            case_id = create_case(ip)
            save_case(ip, case_id, "open")
        else:
            case_id = case_info["case_id"]

        try:
            attach_alert(case_id, alert_id)
            append_alert(ip, alert_id)
        except Exception:
            pass
        # =================================================

        # ================== SAVE ALERT LOG ==================
        try:
            reqs = get_top_anomaly_requests(ip, size=100)
            if reqs:
                logs = []

                for idx, r in enumerate(reqs, start=1):
                    # Gộp tags unique
                    tags_lists = r.get("tags") or []
                    flat_tags = sorted({t for group in tags_lists for t in (group or [])})

                    matches = r.get("match_d") or []
                    clean_match = [m.strip() for m in matches if m and m.strip()]
                    

                    item = {
                        "request_id": idx,
                        "uri": r.get("uri"),
                        "tags": flat_tags,
                        "match": clean_match,
                        "request_headers": r.get("request_headers"),
                        "request_body": r.get("request_body"),
                        "rule_id": r.get("rules"),
                        "data": r.get("datas")
                    }

                    logs.append(item)

                # Append vào log cũ của alert nếu có
                from app.services.waf.alert_log_store import _LOGS
                existing = _LOGS.get(alert_id, {})
                old_reqs = existing.get("requests", [])
                old_reqs.extend(logs)  # APPEND, không overwrite

                log_data = {
                    "client_ip": ip,
                    "requests": old_reqs
                }

                save_alert_log(alert_id, log_data)

        except Exception as e:
            print(f"[Store Alert Log Error] {e}")
        # ===================================================

        # ============ SHOW TOP ANOMALY REQUESTS ============
        try:
            reqs = get_top_anomaly_requests(ip, size=5)
            if not reqs:
                return

            for idx, r in enumerate(reqs, start=1):
                uri = r.get("uri")
                payload_loc = r.get("payload_location")
                payload_detect = r.get("payload_detect")
                payload_decode = r.get("payload_decoded")
                score = r.get("score")
                method = r.get("method")
                tag = r.get("tags")
                body = r.get("request_body")
                request_header = r.get("request_headers")

                msg = f"*Request #{idx}*\n"
                if method:
                    msg += f"*Method:* `{method}`"
                if score is not None:
                    msg += f" | *Score:* `{score}`"
                if uri:
                    msg += f"\n*URI:* `{uri}`"
                if payload_loc:
                    msg += f"\n*Payload Location:* `{payload_loc}`"
                if payload_decode:
                    msg += f"\n*Payload Decoded:* `{payload_decode}`"
                if payload_detect:
                    msg += f"\n*Payload Detect:* `{payload_detect}`"

                if tag:
                    msg += f"\n*Tags:* `{tag}`"

                if request_header:
                    msg += f"\n*Headers:* `{request_header}`"

                if body:
                    msg += f"\n*Request Body:* `{body}`"

                # ĐỔI MÀU HIỂN THỊ CODE BLOCK XÁM
                slack_client.chat_postMessage(
                    channel=channel,
                    text=f"```\n{msg}\n```",
                    thread_ts=ts
                )

        except Exception as e:
            print(f"[Slack Extra Display Error] {e}")
