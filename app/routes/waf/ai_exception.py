from flask import Blueprint, request, jsonify
import json
import os
import re
import threading
import requests

from app.services.ai.gpt_client import ask_gpt

ai_exception_bp = Blueprint("ai_exception_bp", __name__)

# =====================================================
# CONFIG
# =====================================================
STORE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../data/alert_logs.json")
)

# =====================================================
# LOAD ALERT LOGS
# =====================================================
def load_logs():
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def get_alert(alert_id):
    return load_logs().get(alert_id)

# =====================================================
# PREPROCESS ALERT (SAFE FOR AI)
# =====================================================
def preprocess_alert(alert_id, data):
    out = {
        "alert_id": alert_id,
        "client_ip": data.get("client_ip"),
        "requests": []
    }

    for r in data.get("requests", []):
        headers = {}
        for h in r.get("request_headers", []):
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        out["requests"].append({
            "request_id": r.get("request_id"),
            "uri": r.get("uri"),
            "method": r.get("method", "GET"),
            "rule_ids": r.get("rule_id", []),
            "tags": r.get("tags", []),
            "headers": {
                "host": headers.get("Host"),
                "origin": headers.get("Origin"),
                "referer": headers.get("Referer"),
                "content_type": headers.get("Content-Type"),
                "user_agent": headers.get("User-Agent"),
            },
            "body_sample": (r.get("request_body") or "")[:300],
            "matched_samples": r.get("data", [])[:3],
        })

    return out

# =====================================================
# BUILD AI PROMPT (GIỮ LOGIC CŨ)
# =====================================================
def build_prompt(payload):
    lines = [
        "You are a ModSecurity + OWASP CRS false-positive expert.",
        "Analyze an alert containing multiple HTTP requests from the SAME client_ip.",
        "",
        f"AlertID: {payload['alert_id']}",
        f"Client IP: {payload['client_ip']}",
        ""
    ]

    for r in payload["requests"]:
        lines.extend([
            f"Request #{r['request_id']}",
            f"URI: {r['uri']}",
            f"Method: {r['method']}",
            f"Rule IDs: {', '.join(map(str, r['rule_ids']))}",
        ])

        for k, v in r["headers"].items():
            if v:
                lines.append(f"  {k}: {v}")

        if r["body_sample"]:
            lines.append(f"Body sample: {r['body_sample']}")

        for m in r["matched_samples"]:
            lines.append(f"Matched: {m}")

        lines.append("")

    lines.append(
        "Output STRICT JSON only.\n"
        "{ fp_patterns: [...], non_fp_requests: [...] }"
    )

    return "\n".join(lines)

# =====================================================
# PARSE AI OUTPUT
# =====================================================
def parse_ai(text):
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    return None

# =====================================================
# PP SELECTION LOGIC
# =====================================================
def choose_pp(fp):
    variable = fp.get("variable", "")
    rort = fp.get("rort", {})
    values = rort.get("values", [])

    if fp.get("confidence") == "high" and fp.get("scope") == "global":
        return "pp4"

    if variable.startswith("REQUEST_URI"):
        return "pp3"

    if variable.startswith("ARGS") and len(values) >= 3:
        return "pp2"

    return "pp1"

# =====================================================
# COMMAND BUILDERS
# =====================================================
def build_pp1(fp):
    return (
        f"/exception-pp1 "
        f"--v {fp['variable']} "
        f"--o {fp['operator']} "
        f"--m {fp['value']} "
        f"--rort {','.join(map(str, fp['rort']['values']))} "
        f"--p {fp['phase']}"
    )

def build_pp2(fp):
    r = fp["rort"]
    if r["type"] == "id":
        return f"/exception-pp2 --t {fp['variable']} --id {','.join(r['values'])}"
    return f"/exception-pp2 --t {fp['variable']} --tag {','.join(r['values'])}"

def build_pp3(fp):
    return (
        f"/exception-pp3 "
        f"--v {fp['variable']} "
        f"--o {fp['operator']} "
        f"--m {fp['value']} "
        f"--rort all "
        f"--p {fp['phase']}"
    )

def build_pp4(fp):
    return f"/exception-pp4 --rort {','.join(fp['rort']['values'])}"

# =====================================================
# RENDER SLACK MESSAGE
# =====================================================
def render_slack(alert_id, result):
    lines = [
        "🧠 *AI Exception Analysis*",
        f"*AlertID:* `{alert_id}`",
        ""
    ]

    for i, fp in enumerate(result.get("fp_patterns", []), 1):
        pp = choose_pp(fp)

        builder = {
            "pp1": build_pp1,
            "pp2": build_pp2,
            "pp3": build_pp3,
            "pp4": build_pp4
        }[pp]

        lines.extend([
            f"*FP #{i}* – Suggested `{pp.upper()}`",
            f"Requests: `{fp.get('requests')}`",
            f"Confidence: *{fp.get('confidence')}*",
            "```" + builder(fp) + "```",
            ""
        ])

    non_fp = result.get("non_fp_requests", [])
    if non_fp:
        lines.append("*🚫 Non-FP Requests:*")
        lines.append(str(non_fp))

    return "\n".join(lines)

# =====================================================
# BACKGROUND HANDLER (FOR SLASH COMMAND)
# =====================================================
def background_ai_slash(alert_id, response_url):
    try:
        alert = get_alert(alert_id)
        if not alert:
            msg = f"❌ AlertID `{alert_id}` not found."
        else:
            payload = preprocess_alert(alert_id, alert)
            ai_raw = ask_gpt(build_prompt(payload))
            result = parse_ai(ai_raw)

            if not result:
                msg = f"❌ AI failed to analyze AlertID `{alert_id}`"
            else:
                msg = render_slack(alert_id, result)

        requests.post(response_url, json={
            "response_type": "in_channel",
            "text": msg
        })

    except Exception as e:
        requests.post(response_url, json={
            "response_type": "ephemeral",
            "text": f"❌ AI exception error:\n```{e}```"
        })

# =====================================================
# SLASH COMMAND ROUTE (ACK NGAY)
# =====================================================
@ai_exception_bp.route("/ai-exception", methods=["POST"])
def ai_exception():
    alert_id = request.form.get("text", "").strip()
    response_url = request.form.get("response_url")

    if not alert_id:
        return jsonify({
            "response_type": "ephemeral",
            "text": "Usage: /ai-exception <AlertID>"
        }), 200

    # ACK NGAY → KHÔNG TIMEOUT
    threading.Thread(
        target=background_ai_slash,
        args=(alert_id, response_url),
        daemon=True
    ).start()

    return jsonify({
        "response_type": "ephemeral",
        "text": f"🧠 AI is analyzing AlertID `{alert_id}` …"
    }), 200

# =====================================================
# BACKGROUND AI (FOR SLACK EVENTS)
# =====================================================
def background_ai(alert_id, slack_client=None, channel=None, thread_ts=None):
    try:
        alert = get_alert(alert_id)
        if not alert:
            return

        payload = preprocess_alert(alert_id, alert)
        ai_raw = ask_gpt(build_prompt(payload))
        result = parse_ai(ai_raw)

        if not result:
            msg = f"❌ AI failed to analyze AlertID `{alert_id}`"
        else:
            msg = render_slack(alert_id, result)

        if slack_client and channel:
            slack_client.chat_postMessage(
                channel=channel,
                text=msg,
                thread_ts=thread_ts
            )

    except Exception as e:
        if slack_client and channel:
            slack_client.chat_postMessage(
                channel=channel,
                text=f"❌ AI exception error:\n```{e}```",
                thread_ts=thread_ts
            )
