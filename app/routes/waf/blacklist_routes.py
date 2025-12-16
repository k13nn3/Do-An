from flask import Blueprint, request, Response, current_app
from app.services.waf.blacklist_client import deny_ip

denyblack_bp = Blueprint('denyblack_bp', __name__)

# Channel duy nhất cho phép dùng lệnh /deny
ALLOWED_CHANNEL = "C09RK60AE11"

@denyblack_bp.route('/deny', methods=['POST'])
def add_ip_blacklist():
    data = request.form
    channel_id = data.get('channel_id')
    text = data.get('text', '').strip()
    client = current_app.config['SLACK_CLIENT']

    # 1) Không cho phép gõ lệnh ở ngoài channel ALLOWED
    if channel_id != ALLOWED_CHANNEL:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Lệnh `/deny` chỉ được dùng trong kênh #security-alerts."
        )
        return Response(), 200

    # 2) Kiểm tra cú pháp lệnh
    if not text:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Sai cú pháp. Dùng: `/deny <ip>`"
        )
        return Response(), 200

    # 3) Thực thi chặn IP
    msg = deny_ip(text)
    client.chat_postMessage(channel=channel_id, text=msg)

    return Response(), 200
