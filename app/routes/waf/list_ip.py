from flask import Blueprint, request, Response, current_app
from app.services.waf.list import list_ips

list_bp = Blueprint('list_bp', __name__)

# Channel duy nhất cho phép dùng lệnh /list
ALLOWED_CHANNEL = "C09RK60AE11"

@list_bp.route('/list', methods=['POST'])
def list_ip():
    data = request.form
    channel_id = data.get('channel_id')
    text = data.get('text', '').strip().lower()
    client = current_app.config['SLACK_CLIENT']

    # 1) Chặn nếu user gõ lệnh ở ngoài channel được phép
    if channel_id != ALLOWED_CHANNEL:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Lệnh `/list` chỉ được dùng trong kênh #security-alerts."
        )
        return Response(), 200

    # 2) Kiểm tra cú pháp: chỉ chấp nhận ip_whitelist hoặc ip_blacklist
    if text not in ["ip_whitelist", "ip_blacklist"]:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Sai cú pháp. Dùng: `/list ip_whitelist` hoặc `/list ip_blacklist`"
        )
        return Response(), 200

    # 3) Xác định mode
    mode = "whitelist" if "whitelist" in text else "blacklist"

    # 4) Gọi hàm lấy danh sách IP
    msg = list_ips(mode)

    # 5) Trả kết quả
    client.chat_postMessage(channel=channel_id, text=msg)

    return Response(), 200
