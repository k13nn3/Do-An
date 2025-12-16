from typing import List, Dict
from app.services.elk.query_top_anomaly import get_top_anomaly_requests
from app.services.ai.gpt_waf_analyzer import analyze_waf_with_gpt
from typing import List, Dict, Tuple


def build_log_message(ip: str, logs: List[Dict]) -> str:
    """
    Xây chuỗi message hiển thị phần request trên Slack (không AI).
    Thêm hiển thị metadata phục vụ tạo exception
    (logic cũ giữ nguyên 100%)
    """
    msg = f":mag: *Investigate IP:* `{ip}`\n"
    msg += "\n:bar_chart: *Top anomaly requests*\n"

    if not logs:
        return msg + "_Không có dữ liệu._"

    for item in logs:
        req_id = item.get("request_id")
        uri = item.get("uri") or ""
        method = item.get("method") or ""
        pay_loc = item.get("payload_location") or ""
        headers = " || ".join(item.get("request_headers") or [])
        pay_dec = item.get("payload_decoded") or ""
        pay_det = item.get("payload_detect") or ""

        msg += "-----------------------------------------------------------------------\n"
        msg += f"- Request ID: {req_id}\n"
        msg += f"- URI: `{uri}`\n"
        msg += f"- Method: `{method}`\n"
        msg += f"- Payload Location: `{pay_loc}`\n"
        msg += "- Request Headers:\n"
        msg += f"```{headers}```\n"
        msg += "- Payload Decoded:\n"
        msg += f"```{pay_dec}```\n"
        msg += "- Payload Detect:\n"
        msg += f"```{pay_det}```\n"

        # ============================
        #      NEW EXCEPTION INFO
        # ============================
        norm_uri = item.get("normalized_uri") or ""
        host = item.get("host") or ""
        variable = item.get("variable") or ""
        match_str = item.get("match_string") or ""
        rule_ids = item.get("rules") or []

        # Chỉ hiển thị khi đủ thông tin để tạo exception
        if rule_ids and norm_uri and variable:
            msg += ":white_check_mark: *Exception Metadata* (Auto-Extracted)\n"
            msg += f"- Normalized URI: `{norm_uri}`\n"
            msg += f"- Host: `{host}`\n"
            msg += f"- Variable: `{variable}`\n"
            msg += f"- Match String: `{match_str}`\n"
            msg += f"- Rule IDs: `{','.join(rule_ids)}`\n"

    return msg


# Giả sử hàm này được sửa đổi để trả về cấu trúc Slack Block Kit
# Giả sử hàm này được sửa đổi để trả về cấu trúc Slack Block Kit
# Giả sử hàm này được sửa đổi để trả về cấu trúc Slack Block Kit
def build_ai_message(alert_id: str, logs: List[Dict]) -> Tuple[str, List[Dict]]:
    # ... (phần xử lý ai_result và lỗi giữ nguyên)

    ai_result = analyze_waf_with_gpt(alert_id=alert_id, logs=logs)

    # Xử lý lỗi (Giữ nguyên)
    if "error" in ai_result:
        msg = f":robot_face: *AI Analysis* — ERROR\n```{ai_result['error']}```"
        raw = ai_result.get("raw_output")
        if raw:
            msg += f"\n_RAW OUTPUT (truncated):_\n```{raw}```"
        return msg, []

    
    # --- Xử lý thành công: Tạo các Block Kit blocks ---
    
    # 1. Header Block và Info (Giữ nguyên)
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🤖 AI Analysis Result"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Alert ID:* `{ai_result.get('alert_id', '')}`\n\n_Phân tích chi tiết từng Request ID:_ "
            }
        },
        {"type": "divider"}
    ]
    
    # 2. Section Blocks cho mỗi Request ID
    for i, r in enumerate(ai_result.get("requests", [])):
        
        # Tạo nội dung chi tiết
        content = (
            f"*Request ID: {i+1}* (`{r.get('request_id')}`)\n"
            f"• *classification:* `{r.get('classification')}`\n"
            f"• *confidence:* `{r.get('confidence')}`\n"
            f"• *recommendation:* `{r.get('recommendation')}`\n"
            f"• *rationale:* {r.get('rationale')}\n\n"
            # THÊM analysis_input TẠI ĐÂY
            f"*Analysis Input (Payload):*\n"
            f"```{r.get('analysis_input', 'N/A')}```" # Đặt trong block code
        )
        
        # Thêm Section Block duy nhất
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": content
            }
        })
        
        # Thêm Divider để phân tách các Request ID
        if i < len(ai_result.get("requests", [])) - 1:
            blocks.append({"type": "divider"})

    # Trả về tin nhắn text đơn giản (dùng làm fallback) và danh sách blocks
    return f"AI Analysis Result for Alert ID: {alert_id}", blocks


def investigate_ip_sync(ip: str) -> str:
    logs = get_top_anomaly_requests(ip)
    msg = build_log_message(ip, logs)
    return msg, logs
