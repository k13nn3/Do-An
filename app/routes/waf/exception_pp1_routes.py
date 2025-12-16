from flask import Blueprint, request, jsonify
import random
import re
from datetime import datetime
# Giả định: apply_exception_rule là API client để triển khai quy tắc
from app.services.waf.exception_rule_client import apply_exception_rule 

# --- Định nghĩa Blueprint (Giữ tên PP1 theo yêu cầu) ---
exception_pp1_bp = Blueprint("exception_pp1_bp", __name__) 

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
    Tách flags và lấy giá trị. --t (Target) là tùy chọn.
    """
    flags = {
        "--v": None,
        "--o": None,
        "--m": None,
        "--rort": None,
        "--t": None,
        "--p": None, 
    }

    # Regex để bắt tất cả các flag đã định nghĩa
    pattern = re.compile(
        r"(--v|--o|--m|--rort|--t|--p)\s+(.+?)(?=\s--(?:v|o|m|rort|t|p)\b|$)"
    )

    for m in pattern.finditer(text):
        flag = m.group(1)
        value = m.group(2).strip()
        flags[flag] = value

    return flags


def is_valid_target(target: str) -> bool:
    """
    Kiểm tra tính hợp lệ của biến mục tiêu (target) trong ctl:ruleRemoveTarget...
    """
    # Chỉ kiểm tra các biến ModSecurity phổ biến ở Phase 1/2
    return bool(re.match(r"^(ARGS|ARGS_GET|ARGS_NAMES|XML|TX|REQUEST_HEADERS)(:\S+)?$", target))


def is_valid_variable(variable: str) -> bool:
    """
    Kiểm tra tính hợp lệ của biến ModSecurity dùng để trigger (variable)
    """
    return bool(re.match(r"^(REQUEST_URI|ARGS|ARGS_GET|ARGS_NAMES|XML|TX|REQUEST_HEADERS)(:\S+)?$", variable))


def classify_rort(raw: str) -> tuple:
    """
    Phân loại đầu vào trong --rort là Rule ID hay Tag.
    Không cho phép mix ID và Tag.
    """
    items = [x.strip() for x in raw.split(",") if x.strip()]
    if not items:
        return None, None, "Thiếu giá trị trong --rort."

    types = []
    for token in items:
        if token.isdigit():
            types.append("id")
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_-]*$", token):
            types.append("tag")
        else:
            return None, None, (
                f"`{token}` trong --rort không phải Rule ID hợp lệ "
                f"cũng không phải Tag hợp lệ."
            )

    if len(set(types)) > 1:
        return None, None, "Không được mix Rule ID và Tag trong cùng --rort."

    return types[0], items, None


# --- Route Chính ---
@exception_pp1_bp.route("/exception-pp1", methods=["POST"])
def exception_pp1():
    text = request.form.get("text", "").strip()

    # Hiển thị hướng dẫn nếu thiếu text
    if not text:
        return jsonify({
            "response_type": "ephemeral",
            "text": (
                "⚠️ Format (Hybrid PP1/PP2):\n"
                "`/exception-pp1 --v [variable] --o [operator] "
                "--m [match] --rort [ruleid/tag] --p [phase] --t [target] (Tùy chọn)`"
            )
        }), 200

    flags = parse_flags(text)

    # Lấy giá trị các flags
    raw_variable = flags.get("--v")
    raw_operator = flags.get("--o")
    match_string = flags.get("--m")
    rort_raw = flags.get("--rort")
    raw_phase = flags.get("--p")
    raw_target = flags.get("--t")  # <-- LÀ TÙY CHỌN

    # Lấy token đầu
    variable = raw_variable.split()[0] if raw_variable else None
    operator = raw_operator.split()[0] if raw_operator else None
    phase = raw_phase.split()[0] if raw_phase else None
    target = raw_target.split()[0] if raw_target else None  # Target có thể None

    # --- 1. Validate Presence (Bỏ kiểm tra --t) ---
    if not all([variable, operator, match_string, rort_raw, phase]):
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

    # Validate variable
    if not is_valid_variable(variable):
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Variable không hợp lệ: `{variable}`"
        }), 200

    # Validate target (Chỉ kiểm tra nếu tồn tại)
    if target and not is_valid_target(target):
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Target không hợp lệ: `{target}`"
        }), 200

    # Validate --rort (ID/Tag check)
    rtype, items, err = classify_rort(rort_raw)
    if err:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Lỗi ở --rort: {err}"
        }), 200

    # Validate Phase
    if phase not in ["1", "2"]:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Phase không hợp lệ: `{phase}`. Chỉ cho phép 1 hoặc 2."
        }), 200

    # --- XỬ LÝ match_string CHỐNG LỖI MODSEC ---
    # Mục tiêu:
    # - Loại bỏ quote bao ngoài nếu có
    # - Unescape \" từ JSON
    # - Bỏ hoàn toàn dấu " bên trong (giữ pattern dạng duration:{fetch:[])
    # - Nén khoảng trắng cho gọn
    s = match_string.strip()

    # Bỏ quote bao ngoài nếu có (cả "..." và '...')
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1]

    # Biến chuỗi dạng JSON escaped \"duration\" -> "duration"
    s = s.replace(r"\\\"", '"')  # trường hợp đã escape kiểu \\"
    s = s.replace(r"\"", '"')    # trường hợp Slack gửi \"

    # Bỏ toàn bộ dấu " bên trong để tránh parser ModSecurity bị vỡ string
    s = s.replace('"', "")

    # Nén whitespace
    s = re.sub(r"\s+", " ", s).strip()

    # Nếu rỗng thì fallback về chuỗi rất ngắn để tránh rule trống
    if not s:
        s = "fp-pattern"

    escaped_match_string = s

    # --- 3. Logic tạo Rule ModSecurity ---
    # Xác định loại loại trừ đang được sử dụng
    is_target_specific = bool(target)  # True nếu PP1 (có target), False nếu PP2 (toàn cục có điều kiện)

    # Sử dụng ID ngẫu nhiên, đảm bảo không trùng lặp nếu chạy nhiều lần
    new_id = random.randint(100000, 199999)
    ctl_lines = []

    # Xây dựng lệnh ctl dựa trên loại loại trừ
    for token in items:
        if is_target_specific:
            # PHƯƠNG PHÁP 1 (PP1): ruleRemoveTarget...
            if rtype == "id":
                # Ví dụ: ctl:ruleRemoveTargetById=942100;ARGS:comment
                ctl_lines.append(f"ctl:ruleRemoveTargetById={token};{target}")
            else:
                # Ví dụ: ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:comment
                ctl_lines.append(f"ctl:ruleRemoveTargetByTag={token};{target}")
        else:
            # PHƯƠNG PHÁP 2 (PP2): ruleRemove...
            if rtype == "id":
                # Ví dụ: ctl:ruleRemoveById=942100
                ctl_lines.append(f"ctl:ruleRemoveById={token}")
            else:
                # Ví dụ: ctl:ruleRemoveByTag=attack-sqli
                ctl_lines.append(f"ctl:ruleRemoveByTag={token}")

    actions = [
        f"id:{new_id}",
        f"phase:{phase}",
        "pass",
        "nolog",
        *ctl_lines
    ]
    action_block = ",".join(actions)

    # Tạo Rule: dùng escaped_match_string đã được sanitize
    rule = (
        f'SecRule {variable} "{operator} {escaped_match_string}" \\\n'
        f'"{action_block}"'
    )

    # --- 4. Triển khai Rule ---
    success, ts, stage, err_msg = apply_exception_rule(rule)

    # --- 5. Trả về Slack Response ---
    method_used = "PP1 (Target Specific)" if is_target_specific else "PP2 (Conditional Global)"

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
