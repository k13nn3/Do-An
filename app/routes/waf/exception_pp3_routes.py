from flask import Blueprint, request, jsonify
import random
import re
from datetime import datetime
# Giả định: apply_exception_rule là API client để triển khai quy tắc
from app.services.waf.exception_rule_client import apply_exception_rule 

# --- Định nghĩa Blueprint ---
exception_pp3_bp = Blueprint("exception_pp3_bp", __name__)

# --- Hằng số ---
ALLOWED_OPERATORS = [
    "@streq",
    "@rx",
    "@contains",
    "@beginsWith",
    "@endsWith",
]


# --- Hàm Tiện ích ---

def parse_flags(text: str) -> dict:
    """
    Tách flags và lấy giá trị. Hỗ trợ --p.
    """
    flags = {
        "--v": None,
        "--o": None,
        "--m": None,
        "--rort": None,
        "--p": None, 
    }

    # Regex để bắt tất cả các flag đã định nghĩa
    pattern = re.compile(
        r"(--v|--o|--m|--rort|--p)\s+(.+?)(?=\s--(?:v|o|m|rort|p)\b|$)"
    )

    for m in pattern.finditer(text):
        flag = m.group(1)
        value = m.group(2).strip()
        flags[flag] = value

    return flags


def is_valid_variable(v: str) -> bool:
    """
    Kiểm tra tính hợp lệ của biến ModSecurity dùng để trigger (variable).
    Đã mở rộng phạm vi cover.
    """
    return bool(re.match(r"^(REQUEST_URI|REQUEST_HEADERS|REQUEST_FILENAME|REQUEST_LINE|ARGS|ARGS_GET|ARGS_NAMES|XML|TX)(:\S+)?$", v))


# --- Route Chính ---
@exception_pp3_bp.route("/exception-pp3", methods=["POST"])
def exception_pp3():
    text = request.form.get("text", "").strip()
    flags = parse_flags(text)

    # Lấy giá trị các flags
    raw_variable = flags.get("--v")
    raw_operator = flags.get("--o")
    match_string = flags.get("--m")
    rort_value = flags.get("--rort")
    raw_phase = flags.get("--p") 

    # Normalize
    variable = raw_variable.split()[0] if raw_variable else None
    operator = raw_operator.split()[0] if raw_operator else None
    phase = raw_phase.split()[0] if raw_phase else None

    # --- 1. Validate Presence ---
    if not all([variable, operator, match_string, rort_value, phase]):
        return jsonify({
            "response_type": "ephemeral",
            "text": "❌ Thiếu tham số bắt buộc: --v, --o, --m, --rort, --p"
        }), 200

    # --- 2. Validate Values ---
    
    # Validate operator
    if operator not in ALLOWED_OPERATORS:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Operator không hợp lệ: `{operator}`"
        }), 200

    # Validate variable (Sử dụng hàm mở rộng)
    if not is_valid_variable(variable):
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Variable không hợp lệ: `{variable}`"
        }), 200
    
    # Validate Phase
    if phase not in ["1", "2"]:
        return jsonify({"response_type": "ephemeral", "text": f"❌ Phase không hợp lệ: `{phase}`. Chỉ cho phép 1 hoặc 2."}), 200

    # PP3 Requirement: only "all" accepted
    if rort_value.lower() != "all":
        return jsonify({
            "response_type": "ephemeral",
            "text": "❌ Với PP3 giá trị --rort chỉ hợp lệ là `all`."
        }), 200

    # --- 3. Logic tạo Rule ModSecurity ---
    
    # Generate random Rule ID
    new_id = random.randint(900000, 999999)

    # PP3 Logic: Tắt toàn bộ Rule Engine khi match
    actions = [
        f"id:{new_id}",
        f"phase:{phase}",
        "pass",
        "nolog",
        "ctl:ruleEngine=Off" # Lệnh cốt lõi của PP3
    ]

    action_block = ",".join(actions)

    rule = (
        f'SecRule {variable} "{operator} {match_string}" \\\n'
        f'"{action_block}"'
    )

    # --- 4. Triển khai Rule ---
    
    # Gọi service client để triển khai rule lên WAF (Giả định hàm này tồn tại)
    success, ts, stage, err_msg = apply_exception_rule(rule)

    # --- 5. Trả về Slack Response ---
    
    method_used = "PP3 (Conditional Rule Engine Off)"

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