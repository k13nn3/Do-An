from flask import Blueprint, request, jsonify
from app.services.waf.case_store import get_case, update_status
from app.services.elk.kibana_api import close_case_in_kibana

close_case_bp = Blueprint("close_case_bp", __name__)


@close_case_bp.route("/close-case", methods=["POST"])
def close_case():
    case_id = request.form.get("text", "").strip()
    if not case_id:
        return jsonify({
            "response_type": "ephemeral",
            "text": "⚠️ Cú pháp đúng:\n`/close-case <case_id>`"
        }), 200

    from app.services.waf.case_store import _CASES
    target_ip = None
    for ip, cases in _CASES.items():
        for c in cases:
            if isinstance(c, dict) and c.get("case_id") == case_id:
                target_ip = ip
                break

    if not target_ip:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Không tìm thấy Case ID `{case_id}` trong DB!"
        }), 200

    try:
        close_case_in_kibana(case_id)
    except Exception as e:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"⚠️ Lỗi Kibana API:\n`{str(e)}`"
        }), 200

    update_status(target_ip, "closed")

    return jsonify({
        "response_type": "ephemeral",
        "text": f"✔️ Case `{case_id}` cho IP `{target_ip}` đã đóng."
    }), 200
