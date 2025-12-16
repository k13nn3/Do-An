from flask import Blueprint, request, Response, current_app
from app.services.waf.whitelist_client import allow_ip

allowwhite_bp = Blueprint('allowwhite_bp', __name__)

# Channel duy nhất cho phép dùng lệnh /allow
ALLOWED_CHANNEL = "C09RK60AE11"

@allowwhite_bp.route('/allow', methods=['POST'])
def add_ip_whitelist():
    data = request.form
    channel_id = data.get('channel_id')
    text = data.get('text', '').strip()
    client = current_app.config['SLACK_CLIENT']

    # 1) Không cho phép chạy lệnh ngoài channel được phép
    if channel_id != ALLOWED_CHANNEL:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Lệnh `/allow` chỉ được dùng trong kênh #security-alerts."
        )
        return Response(), 200

    # 2) Kiểm tra cú pháp
    if not text:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Sai cú pháp. Dùng cú pháp: `/allow <ip>`"
        )
        return Response(), 200

    # 3) Xử lý thêm IP vào whitelist
    msg = allow_ip(text)

    # 4) Gửi kết quả
    client.chat_postMessage(channel=channel_id, text=msg)

    return Response(), 200
