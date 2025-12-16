# # app/routes/investigate_routes.py
# import threading
# import requests
# from flask import Blueprint, request, jsonify

# from app.services.waf.alert_handler import investigate_ip_sync, build_ai_message

# investigate_bp = Blueprint("investigate_bp", __name__)


# def _async_ai_worker(ip: str, logs: list, response_url: str, alert_id: str):
#     """
#     Worker chạy nền: gọi AI và POST kết quả về Slack qua response_url.
#     """
#     try:
#         ai_msg = build_ai_message(alert_id=alert_id, logs=logs)

#         # Delayed response cho slash command
#         payload = {
#             "response_type": "in_channel",   # hoặc "ephemeral"
#             "text": ai_msg,
#         }
#         requests.post(response_url, json=payload, timeout=10)
#     except Exception as e:
#         error_payload = {
#             "response_type": "ephemeral",
#             "text": f"AI worker error: {e}",
#         }
#         try:
#             requests.post(response_url, json=error_payload, timeout=10)
#         except Exception:
#             pass


# @investigate_bp.route("/investigate", methods=["POST"])
# def investigate_command():
#     """
#     Slack slash command handler: /investigate <IP>

#     - Trong 3s: trả log + info cho user
#     - Gọi AI ở background, gửi kết quả sau qua response_url
#     """
#     text = request.form.get("text", "").strip()
#     response_url = request.form.get("response_url", "").strip()
#     user_id = request.form.get("user_id", "")
#     command = request.form.get("command", "")

#     if not text:
#         return jsonify(
#             {
#                 "text": "Usage: /investigate <IP>",
#                 "response_type": "ephemeral",
#             }
#         )

#     ip = text.split()[0]

#     # 1) Lấy log và build message sync
#     try:
#         msg, logs = investigate_ip_sync(ip)
#     except Exception as e:
#         return jsonify(
#             {
#                 "text": f"Error while querying logs: {e}",
#                 "response_type": "ephemeral",
#             }
#         )

#     # 2) Trả lời ngay lập tức cho Slack trong 3s
#     #    (chỉ có phần request, chưa có AI)
#     initial_msg = msg + "\n\n:hourglass_flowing_sand: AI is analyzing this IP. Results will be posted shortly..."
#     response_data = {
#         "response_type": "in_channel",  # hoặc "ephemeral"
#         "text": initial_msg,
#     }

#     # 3) Nếu có response_url → spawn worker để xử lý AI async
#     if response_url and logs:
#         alert_id = f"{command}:{ip}"  # bạn có thể define alert_id chuẩn hơn
#         t = threading.Thread(
#             target=_async_ai_worker,
#             args=(ip, logs, response_url, alert_id),
#             daemon=True,
#         )
#         t.start()

#     return jsonify(response_data)
