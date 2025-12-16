from flask import Blueprint, jsonify
from app.services.waf.alert_log_store import clear_logs

clear_logs_bp = Blueprint("clear_logs_bp", __name__)


@clear_logs_bp.route("/clear-alert-logs", methods=["POST"])
def clear_alert_logs():
    clear_logs()

    return jsonify({
        "response_type": "in_channel",
        "text": "🔥 *Đã xóa toàn bộ Alert Logs* (RAM + File synced)."
    }), 200
