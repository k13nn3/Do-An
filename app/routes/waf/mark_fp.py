from flask import Blueprint, request, jsonify
import re
from datetime import datetime

from app.services.waf.alert_log_store import save_alert_log
from app.services.waf.case_store import _CASES, _save as save_cases
from app.services.waf.case_store import update_status
from app.services.elk.kibana_api import close_case_in_kibana

mark_fp_bp = Blueprint("mark_fp_bp", __name__)


@mark_fp_bp.route("/mark-fp", methods=["POST"])
def mark_fp():
    text = request.form.get("text", "").strip()
    alert_id = re.sub(r"[^\w]", "", text)

    if not alert_id:
        return jsonify({
            "response_type": "ephemeral",
            "text": "⚠️ Cú pháp đúng: `/mark-fp <alert_id>`"
        }), 200

    # 1️⃣ Đánh dấu alert là FP trong alert_logs.json
    from app.services.waf.alert_log_store import _LOGS

    alert_data = _LOGS.get(alert_id)
    if not alert_data:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Không tìm thấy alert `{alert_id}` trong alert_logs.json"
        }), 200

    alert_data["status"] = "FP"
    save_alert_log(alert_id, alert_data)

    # 2️⃣ Gỡ alert khỏi case OPEN
    removed_from_cases = 0
    auto_closed_cases = 0

    for ip, cases in _CASES.items():
        if not isinstance(cases, list):
            continue

        for case in cases:
            if case.get("status") != "open":
                continue

            alerts = case.get("alerts", [])
            if alert_id not in alerts:
                continue

            # 🔥 Case chỉ có 1 alert → remove + close case
            if len(alerts) == 1:
                try:
                    close_case_in_kibana(case["case_id"])
                except Exception:
                    pass  # không block flow nếu Kibana lỗi

                case["alerts"] = []
                case["status"] = "closed"
                case["closed_at"] = datetime.utcnow().isoformat()

                auto_closed_cases += 1
            else:
                # Case nhiều alert → chỉ remove alert FP
                case["alerts"] = [a for a in alerts if a != alert_id]

            removed_from_cases += 1

    save_cases()

    # 3️⃣ Trả kết quả Slack
    msg = (
        f":large_yellow_circle: `{alert_id}` đã được đánh dấu **FP**.\n"
    )

    if removed_from_cases == 0:
        msg += "ℹ️ Alert không nằm trong case nào đang mở."
    else:
        msg += f"🧹 Gỡ khỏi `{removed_from_cases}` case(s) đang mở.\n"

    if auto_closed_cases > 0:
        msg += f"🔒 Tự động đóng `{auto_closed_cases}` case vì không còn alert."

    return jsonify({
        "response_type": "in_channel",
        "text": msg
    }), 200
