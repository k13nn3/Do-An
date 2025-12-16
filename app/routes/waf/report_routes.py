import threading
import json
import os
from flask import Blueprint, request, jsonify, current_app

from app.services.waf.alert_handler import build_ai_message

# ❗ GIỮ NGUYÊN – dùng cho report-no-AI
from app.services.elk.query_top_anomaly import (
    get_top_anomaly_requests,
    get_top_requests_last_3h
)

# ❗ DÙNG CHO report-AI
from app.services.waf.alert_log_reader import get_logs_by_alert_id
from app.services.ai.gpt_waf_analyzer import analyze_waf_with_gpt


report_bp = Blueprint("report_bp", __name__)

# ===========================================================
#  PATH CONFIG
# ===========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../../"))
DATA_DIR = os.path.join(BOT_DIR, "data")
ALERT_LOG_PATH = os.path.join(DATA_DIR, "alert_logs.json")


# ===========================================================
#  ASYNC AI WORKER (GIỮ NGUYÊN LOGIC CŨ)
# ===========================================================
def _async_ai_worker(slack_client, logs: list, channel_id: str, parent_ts: str, alert_id: str):
    try:
        ai_msg_text, ai_blocks = build_ai_message(
            alert_id=alert_id,
            logs=logs
        )

        if ai_blocks:
            slack_client.chat_postMessage(
                channel=channel_id,
                thread_ts=parent_ts,
                text=ai_msg_text,
                blocks=ai_blocks
            )
        else:
            slack_client.chat_postMessage(
                channel=channel_id,
                thread_ts=parent_ts,
                text=ai_msg_text
            )

    except Exception as e:
        try:
            slack_client.chat_postMessage(
                channel=channel_id,
                thread_ts=parent_ts,
                text=f"AI worker error: {e}"
            )
        except Exception:
            pass


# ===========================================================
#  WORKER: report-no-AI (GIỮ NGUYÊN)
# ===========================================================
def _format_block(req: dict) -> str:
    lines = [
        f"Request ID : {req.get('request_id')}",
        f"Score      : {req.get('score')}",
        f"Method     : {req.get('method')}",
        f"URI        : {req.get('uri')}",
    ]
    if req.get("request_headers"):
        lines.append("")
        lines.append("Headers:")
        for h in req["request_headers"]:
            lines.append(f"  {h}")
    if req.get("request_body"):
        lines.append("")
        lines.append("Body:")
        lines.append(req["request_body"])
    return "```" + "\n".join(lines) + "```"


def _worker(slack_client, ip: str, channel_id: str, parent_ts: str):
    logs = get_top_requests_last_3h(ip)

    if not logs:
        slack_client.chat_postMessage(
            channel=channel_id,
            thread_ts=parent_ts,
            text=f":warning: No requests found for IP `{ip}` in last 3 hours"
        )
        return

    for req in logs:
        slack_client.chat_postMessage(
            channel=channel_id,
            thread_ts=parent_ts,
            text=_format_block(req)
        )


# ===========================================================
#  /report-no-AI
# ===========================================================
@report_bp.route("/report-no-AI", methods=["POST"])
def report_no_ai():
    ip = request.form.get("text", "").strip()
    channel_id = request.form.get("channel_id")

    if not ip:
        return jsonify({
            "response_type": "ephemeral",
            "text": "Usage: `/report-no-AI <IP>`"
        }), 200

    slack_client = current_app.config["SLACK_CLIENT"]

    parent = slack_client.chat_postMessage(
        channel=channel_id,
        text=f":mag: Querying top 20 requests for IP `{ip}` (last 3 hours)..."
    )
    parent_ts = parent["ts"]

    threading.Thread(
        target=_worker,
        args=(slack_client, ip, channel_id, parent_ts),
        daemon=True
    ).start()

    return "", 200


# ===========================================================
#  /report-AI <ALERT_ID>
#  ✅ AI phân tích
#  ✅ GIỮ request false_positive
#  ❌ XOÁ request còn lại khỏi alert_logs.json
# ===========================================================
@report_bp.route("/report-AI", methods=["POST"])
def report_ai():
    alert_id = request.form.get("text", "").strip()
    channel_id = request.form.get("channel_id")

    if not alert_id:
        return jsonify({
            "response_type": "ephemeral",
            "text": "Usage: `/report-AI <ALERT_ID>`"
        }), 200

    try:
        logs = get_logs_by_alert_id(alert_id)
    except Exception as e:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"Error reading alert logs: {e}"
        }), 200

    if not logs:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"No logs found for alert `{alert_id}`"
        }), 200

    slack_client = current_app.config["SLACK_CLIENT"]

    parent = slack_client.chat_postMessage(
        channel=channel_id,
        text=f":hourglass_flowing_sand: AI đang phân tích alert `{alert_id}`..."
    )
    parent_ts = parent["ts"]

    # =======================================================
    #  BACKGROUND: AI + CLEANUP alert_logs.json
    # =======================================================
    def ai_and_cleanup():
        # 1️⃣ Gửi kết quả AI lên Slack (giữ nguyên UI)
        ai_msg_text, ai_blocks = build_ai_message(alert_id, logs)
        slack_client.chat_postMessage(
            channel=channel_id,
            thread_ts=parent_ts,
            text=ai_msg_text,
            blocks=ai_blocks if ai_blocks else None
        )

        # 2️⃣ Lấy kết quả AI dạng JSON để lọc FP
        ai_result = analyze_waf_with_gpt(alert_id=alert_id, logs=logs)
        if "requests" not in ai_result:
            return

        fp_request_ids = {
            r["request_id"]
            for r in ai_result["requests"]
            if r.get("classification") == "false_positive"
        }

        if not fp_request_ids:
            return

        if not os.path.exists(ALERT_LOG_PATH):
            return

        # 3️⃣ Load alert_logs.json
        with open(ALERT_LOG_PATH, "r", encoding="utf-8") as f:
            store = json.load(f)

        alert = store.get(alert_id)
        if not alert:
            return

        # 4️⃣ GIỮ LẠI request false_positive
        alert["requests"] = [
            r for r in alert.get("requests", [])
            if r.get("request_id") in fp_request_ids
        ]

        # 5️⃣ Nếu không còn request → xoá alert
        if not alert["requests"]:
            store.pop(alert_id, None)

        # 6️⃣ Ghi lại file
        with open(ALERT_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2, ensure_ascii=False)

    threading.Thread(target=ai_and_cleanup, daemon=True).start()
    return "", 200
