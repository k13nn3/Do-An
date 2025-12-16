import json
import html
import re
from urllib.parse import unquote, parse_qs


# ======================== DECODER ========================

def auto_decode(v: str):
    if not isinstance(v, str):
        return v
    try:
        v = unquote(v)
        v = html.unescape(v)
        v = v.encode("utf-8", "ignore").decode("unicode_escape", "ignore")
        return v
    except Exception:
        return v


# ===================== NORMALIZE EVENT ====================

def normalize_event(raw):
    if isinstance(raw, dict) and "_source" in raw:
        raw = raw["_source"]
    return raw or {}


def get_field(event: dict, key: str):
    if key in event:
        return event[key]

    fields = event.get("fields", {})
    if isinstance(fields, dict) and key in fields:
        val = fields[key]
        if isinstance(val, list) and val:
            return val[0]
        return val

    return None


# ============ PARSE VARIABLES & CANDIDATE SUBSTRINGS ============

def parse_matched_variables(messages):
    vars_found = []

    if not isinstance(messages, list):
        return vars_found

    for m in messages:
        det = m.get("details", {})
        match = det.get("match", "")
        if not isinstance(match, str):
            continue

        for var in re.findall(r"variable\s+`([^']+)'", match):
            if ":" in var:
                vtype, name = var.split(":", 1)
            else:
                vtype, name = var, ""
            vars_found.append((vtype.strip(), name.strip()))

    return vars_found


def extract_candidate_substrings(messages):
    subs = []

    if not isinstance(messages, list):
        return subs

    for m in messages:
        det = m.get("details", {})

        # From details.data: "Matched Data: X found within ..."
        data = det.get("data", "")
        if isinstance(data, str) and "Matched Data:" in data:
            part = data.split("Matched Data:", 1)[1].strip()
            if "found within" in part:
                sub = part.split("found within", 1)[0].strip()
            else:
                sub = part
            if sub:
                subs.append(sub)

        # From details.match: "Value: `....`"
        match = det.get("match", "")
        if isinstance(match, str) and "Value:" in match:
            m2 = re.search(r"Value:\s*`([^`]*)`", match)
            if m2:
                v = m2.group(1).strip()
                if v:
                    subs.append(v)

    return subs


def find_matches_in_text(text, candidates):
    """
    Tìm tất cả pattern (đã decode) trong text (đã decode).
    Trả về list các pattern duy nhất theo thứ tự xuất hiện.
    """
    if not isinstance(text, str) or not text:
        return []

    text_dec = auto_decode(text)
    found = []

    for sub in candidates:
        s_dec = auto_decode(sub)
        if not s_dec:
            continue
        if s_dec.lower() in text_dec.lower():
            if s_dec not in found:
                found.append(s_dec)

    return found


# ===================== PRIORITY 1: URI ======================

def extract_from_uri(event, var_list, candidates):
    uri = get_field(event, "request.uri")
    if not isinstance(uri, str) or "?" not in uri:
        return None

    decoded_uri = auto_decode(uri)
    query = decoded_uri.split("?", 1)[1]

    # 1) ARGS:* match
    arg_names = [name for (typ, name) in var_list if typ.upper().startswith("ARGS")]
    if arg_names:
        qs = parse_qs(query, keep_blank_values=True)
        for name in arg_names:
            if name in qs and qs[name]:
                val = qs[name][0]
                if isinstance(val, str) and val.strip():
                    patterns = find_matches_in_text(query, candidates)
                    return {
                        "payload_location": "request.uri",
                        "payload_raw": query,
                        "payload_decoded": query,
                        "payload_detect": patterns or [val]
                    }

    # 2) fallback: candidate substrings trong query
    patterns = find_matches_in_text(query, candidates)
    if patterns:
        return {
            "payload_location": "request.uri",
            "payload_raw": query,
            "payload_decoded": query,
            "payload_detect": patterns
        }

    return None


# ===================== PRIORITY 2: BODY ======================

def extract_from_body(event, candidates):
    body = get_field(event, "request.body")
    if not isinstance(body, str) or not body.strip():
        return None

    patterns = find_matches_in_text(body, candidates)
    if patterns:
        return {
            "payload_location": "request.body",
            "payload_raw": body,
            "payload_decoded": auto_decode(body),
            "payload_detect": patterns
        }

    return None


# ==================== PRIORITY 3: HEADERS =====================

def extract_from_headers(event, var_list, candidates):
    header_vars = [name for (typ, name) in var_list if typ.upper() == "REQUEST_HEADERS"]
    for hname in header_vars:
        key = f"request.headers.{hname}"
        val = get_field(event, key)
        if isinstance(val, str) and val.strip():
            patterns = find_matches_in_text(val, candidates)
            return {
                "payload_location": key,
                "payload_raw": val,
                "payload_decoded": auto_decode(val),
                # nếu không match được pattern nào thì fallback là full header
                "payload_detect": patterns or [val]
            }
    return None


# ======================= MAIN EXTRACTOR =======================

def extract_payload(raw_event):
    event = normalize_event(raw_event)

    messages = event.get("messages", [])
    var_list = parse_matched_variables(messages)
    candidates = extract_candidate_substrings(messages)

    # 1) URI
    res = extract_from_uri(event, var_list, candidates)
    if res:
        return res

    # 2) BODY
    res = extract_from_body(event, candidates)
    if res:
        return res

    # 3) HEADERS
    res = extract_from_headers(event, var_list, candidates)
    if res:
        return res

    # 4) Fallback nếu có query string mà không match pattern
    uri = get_field(event, "request.uri")
    if isinstance(uri, str) and "?" in uri:
        decoded_uri = auto_decode(uri)
        query = decoded_uri.split("?", 1)[1]
        return {
            "payload_location": "request.uri",
            "payload_raw": query,
            "payload_decoded": query,
            "payload_detect": None
        }

    # 5) Fallback nếu có body mà không match pattern
    body = get_field(event, "request.body")
    if isinstance(body, str) and body.strip():
        return {
            "payload_location": "request.body",
            "payload_raw": body,
            "payload_decoded": auto_decode(body),
            "payload_detect": None
        }

    # 6) Không tìm được payload
    return {
        "payload_location": None,
        "payload_raw": None,
        "payload_decoded": None,
        "payload_detect": None,
        "note": "NO_PAYLOAD_FOUND"
    }
