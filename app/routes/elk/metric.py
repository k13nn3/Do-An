from flask import Blueprint, request, Response, current_app
from app.services.elk.metric import get_metric

metric_bp = Blueprint('metric_bp', __name__)

# Channel duy nhất cho phép chạy /metric
ALLOWED_CHANNEL = "C09UC5GKUHL"

@metric_bp.route('/metric', methods=['POST'])
def metric_host():
    data = request.form
    channel_id = data.get('channel_id')   # channel nơi user gõ command
    text = data.get('text', '').strip()
    host_filter = text if text else None

    # 1) Chặn nếu user gõ ở channel khác
    if channel_id != ALLOWED_CHANNEL:
        return Response(
            "❌ Lệnh `/metric` chỉ được phép dùng trong kênh #system-metrics.",
            status=200
        )

    # 2) Nếu đúng channel → chạy logic bình thường
    msg = get_metric(host_filter)
    client = current_app.config['SLACK_CLIENT']

    # Gửi đúng channel mà user gõ (chính là system-metrics)
    client.chat_postMessage(channel=channel_id, text=msg)

    return Response(), 200
