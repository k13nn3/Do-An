from flask import Blueprint, request, jsonify
from app.services.waf.exception_rule_client import apply_exception_rule
import re

# Định nghĩa Blueprint
exception_pp2_bp = Blueprint("exception_pp2_bp", __name__)


# --- Hàm Tiện ích (Sử dụng các phiên bản mở rộng từ PP1/PP3) ---

def parse_flags_pp2(text: str) -> dict:
    """
    Parse flags cho lệnh loại trừ mục tiêu toàn cục: --t, --id, --tag.
    --id và --tag là độc lập (chọn 1 trong 2), --t là bắt buộc.
    """
    flags = {
        "--t": None,
        "--id": None,
        "--tag": None,
    }

    # Regex để bắt các flag --t, --id, --tag
    pattern = re.compile(
        r"(--t|--id|--tag)\s+(.+?)(?=\s--(?:t|id|tag)\b|$)"
    )

    for m in pattern.finditer(text):
        flag = m.group(1)
        value = m.group(2).strip()
        flags[flag] = value

    return flags


def is_valid_target(target: str) -> bool:
    """
    Kiểm tra tính hợp lệ của biến mục tiêu (target).
    Bao gồm các biến INPUT chính.
    """
    return bool(re.match(r"^(ARGS|ARGS_GET|ARGS_NAMES|XML|TX|REQUEST_HEADERS|REQUEST_BODY)(:\S+)?$", target))


def is_valid_id_range(id_raw: str) -> bool:
    """
    Kiểm tra tính hợp lệ của Rule ID hoặc dải ID (ví dụ: 942100-942200,930000).
    """
    items = [x.strip() for x in id_raw.split(",") if x.strip()]
    for item in items:
        # Kiểm tra ID đơn lẻ hoặc dải ID
        if not re.match(r"^\d+$|^(\d+)-(\d+)$", item):
            return False
    return True

def is_valid_tag(tag_raw: str) -> bool:
    """
    Kiểm tra tính hợp lệ của một hoặc nhiều Tag.
    """
    items = [x.strip() for x in tag_raw.split(",") if x.strip()]
    for item in items:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_-]*$", item):
            return False
    return True


# --- Route Chính ---
@exception_pp2_bp.route("/exception-pp2", methods=["POST"])
def exception_pp2():
    text = request.form.get("text", "").strip()
    flags = parse_flags_pp2(text)

    target_raw = flags.get("--t")
    id_raw = flags.get("--id")
    tag_raw = flags.get("--tag")

    # --- 1. Validate Presence ---
    if not target_raw:
        return jsonify({
            "response_type": "ephemeral",
            "text": "❌ Thiếu tham số bắt buộc: `--t` (Target Variable).\n"
                    "Cần cung cấp `--id` HOẶC `--tag`.\n"
                    "Ví dụ: `/exception-pp2 --t ARGS:password --id 942100-942900`"
        }), 200
    
    if not id_raw and not tag_raw:
         return jsonify({
            "response_type": "ephemeral",
            "text": "❌ Cần cung cấp chính xác một trong hai: `--id` hoặc `--tag`."
        }), 200

    if id_raw and tag_raw:
        return jsonify({
            "response_type": "ephemeral",
            "text": "❌ Không được cung cấp đồng thời cả `--id` và `--tag`."
        }), 200
    
    # --- 2. Validate Values ---
    
    # Validate Target
    target = target_raw.split()[0] if target_raw else None
    if not is_valid_target(target):
        return jsonify({"response_type": "ephemeral", "text": f"❌ Target `{target}` không hợp lệ."}), 200

    # Xác định loại loại trừ và Validate tương ứng
    if id_raw:
        if not is_valid_id_range(id_raw):
            return jsonify({"response_type": "ephemeral", "text": f"❌ ID/ID Range `{id_raw}` không hợp lệ."}), 200
        # Chế độ ID Range (Trường hợp VI)
        directive = f"SecRuleUpdateTargetById {id_raw} !{target}"
        method_used = "PP2 (ID Range Target Update)"
    else:
        if not is_valid_tag(tag_raw):
            return jsonify({"response_type": "ephemeral", "text": f"❌ Tag `{tag_raw}` không hợp lệ."}), 200
        # Chế độ Tag (Trường hợp VII)
        directive = f"SecRuleUpdateTargetByTag {tag_raw} !{target}"
        method_used = "PP2 (Tag Target Update)"
        
    # --- 3. Tạo Rule và Triển khai ---
    
    # Rule này là lệnh chỉ thị cấu hình, không cần SecRule/ID/Phase
    rule = directive

    # Áp dụng API WAF
    success, ts, stage, err_msg = apply_exception_rule(rule)

    if success:
        header = (
            f":white_check_mark: **{method_used} applied successfully**\n"
            f"- Time: `{ts}`\n"
            f"- Reload: `{stage}`\n"
        )
        err_block = ""
    else:
        header = (
            f":warning: **{method_used} apply FAILED**\n"
            f"- Time: `{ts}`\n"
            f"- Stage: `{stage}`\n"
        )
        err_block = f"```\n{(err_msg or '').strip()}\n```"

    return jsonify({
        "response_type": "in_channel",
        "text": f"{header}{err_block} ```{rule}```"
    }), 200