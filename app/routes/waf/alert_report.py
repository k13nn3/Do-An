from flask import Blueprint, jsonify, request
from app.services.waf.case_store import list_not_confirm

list_not_confirm_bp = Blueprint("list_not_confirm_bp", __name__)

@list_not_confirm_bp.route("/list-not-confirm", methods=["POST"])
def get_not_confirm_cases():
    data = list_not_confirm()

    if not data:
        return jsonify({
            "response_type": "ephemeral",
            "text": "👌 Không có case nào đang mở."
        }), 200

    lines = ["📋 *DANH SÁCH CASE OPEN:*"]

    for item in data:
        ip = item["ip"]
        case_id = item["case_id"]
        alerts = item.get("alerts", [])
        alert_count = len(alerts)

        lines.append(f"\n• IP: `{ip}`")
        lines.append(f"  ├ Case ID: `{case_id}`")
        lines.append(f"  ├ Status: `{item['status']}`")
        lines.append(f"  ├ Alerts: `{alert_count}`")
        
        if alert_count > 0:
            lines.append("    🔹 Alert IDs:")
            for aid in alerts[-5:]:  # chỉ hiển thị 5 cái mới nhất
                lines.append(f"       `- {aid}`")

        lines.append("")  # dòng trống phân tách từng case

    text_message = "\n".join(lines)

    return jsonify({
        "response_type": "ephemeral",
        "text": text_message
    }), 200
