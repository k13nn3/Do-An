from flask import Blueprint, request, Response, current_app
from app.services.waf.delete_client import delete_ip

delete_bp = Blueprint('delete_bp', __name__)

# Channel duy nhất cho phép dùng lệnh /delete
ALLOWED_CHANNEL = "C09RK60AE11"

@delete_bp.route('/delete', methods=['POST'])
def delete_ip_route():
    data = request.form
    channel_id = data.get('channel_id')
    text = data.get('text', '').strip()
    client = current_app.config['SLACK_CLIENT']

    # 1) Không cho phép dùng lệnh ngoài channel WAF/system
    if channel_id != ALLOWED_CHANNEL:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Lệnh `/delete` chỉ được dùng trong kênh #security-alerts."
        )
        return Response(), 200

    # 2) Kiểm tra cú pháp: phải có đúng 2 tham số
    parts = text.split()
    if len(parts) != 2:
        client.chat_postMessage(
            channel=channel_id,
            text="❌ Sai cú pháp. Dùng: `/delete [ip_whitelist|ip_blacklist] [IP]`"
        )
        return Response(), 200

    # 3) Lấy dữ liệu
    ip_type, ip = parts

    # 4) Gọi client xoá IP
    msg = delete_ip(ip_type, ip)

    # 5) Trả kết quả
    client.chat_postMessage(channel=channel_id, text=msg)

    return Response(), 200
