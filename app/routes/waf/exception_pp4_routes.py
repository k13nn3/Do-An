from flask import Blueprint, request, jsonify
from app.services.waf.exception_rule_client import apply_exception_rule
import re

# Định nghĩa Blueprint
exception_pp4_bp = Blueprint("exception_pp4_bp", __name__)


def parse_flags(text: str) -> dict:
    """
    Parse flags cho lệnh loại trừ toàn cục. Chỉ cần --rort.
    """
    flags = {"--rort": None}

    # Tìm kiếm cờ --rort
    m = re.search(r"--rort\s+(.+?)(?=$|\s--)", text)
    if m:
        flags["--rort"] = m.group(1).strip()

    return flags


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


@exception_pp4_bp.route("/exception-pp4", methods=["POST"])
def exception_pp4():
    text = request.form.get("text", "").strip()
    flags = parse_flags(text)

    rort_raw = flags["--rort"]

    if not rort_raw:
        return jsonify({
            "response_type": "ephemeral",
            "text": "❌ Thiếu tham số bắt buộc: `--rort`\n"
                    "Ví dụ (ID): `/exception-pp4 --rort 942400,942430`\n"
                    "Ví dụ (Tag): `/exception-pp4 --rort attack-sqli,lfi`"
        }), 200

    # Phân loại và kiểm tra giá trị
    rtype, items, err = classify_rort(rort_raw)
    
    if err:
        return jsonify({
            "response_type": "ephemeral",
            "text": f"❌ Lỗi ở --rort: {err}"
        }), 200

    rule_lines = []
    
    if rtype == "id":
        # PP4: Loại trừ toàn cục theo ID
        for rid in items:
            rule_lines.append(f"SecRuleRemoveById {rid}")
        method_used = "PP4 (Global ID Removal)"
    else:
        # PP5: Loại trừ toàn cục theo Tag
        for tag in items:
            rule_lines.append(f"SecRuleRemoveByTag {tag}")
        method_used = "PP5 (Global Tag Removal)"

    # Sinh rule hợp lệ: mỗi dòng một lệnh SecRuleRemove
    rule = "\n".join(rule_lines)

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