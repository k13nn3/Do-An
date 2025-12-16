from elasticsearch import Elasticsearch
from app.services.elk.extractor_module import extract_payload


def _get_es_client() -> Elasticsearch:
    return Elasticsearch(
        ["https://192.168.10.140:9200"],
        basic_auth=("elastic", "elastic"),
        verify_certs=False,
    )


def get_top_requests_last_3h(ip: str, size: int = 100) -> list:
    if not ip:
        return []

    es = _get_es_client()

    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"client_ip.keyword": ip}},
                    {"range": {"@timestamp": {"gte": "now-3h"}}}
                ]
            }
        },
        "sort": [
            {"modsec.inbound_score": {"order": "desc"}},
            {"@timestamp": {"order": "desc"}}
        ],
        "_source": {
            "includes": [
                "request.*",
                "messages",
                "modsec.*"
            ]
        },
    }

    resp = es.search(index="modsecurity-*", body=query)
    hits = resp.get("hits", {}).get("hits", []) or []

    out = []
    rid = 1

    for h in hits:
        src = h.get("_source", {}) or {}

        headers = []
        for k, v in src.items():
            if k.startswith("request.headers.") and isinstance(v, str):
                headers.append(f"{k.split('request.headers.',1)[1]}: {v}")


        out.append({
            "request_id": rid,
            "score": src.get("modsec.inbound_score"),
            "uri": src.get("request.uri"),
            "method": src.get("request.method"),

            "request_body": src.get("request.body")
            if isinstance(src.get("request.body"), str) else "",

            "request_headers": headers,
        })

        rid += 1

    return out

def get_top_anomaly_requests(ip: str, size: int = 25) -> list:
    if not ip:
        return []

    es = _get_es_client()

    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"client_ip.keyword": ip}},
                    {"range": {"@timestamp": {"gte": "now-2m"}}}
                ]
            }
        },
        "sort": [
            {"modsec.inbound_score": {"order": "desc"}},
            {"@timestamp": {"order": "desc"}}
        ],
        "_source": {"includes": ["request.*", "messages", "modsec.*"]},
    }

    resp = es.search(index="modsecurity-*", body=query)
    hits = resp.get("hits", {}).get("hits", []) or []

    out = []
    rid = 1
    
    for h in hits:
        src = h.get("_source", {}) or {}
        payload = extract_payload(src) or {}

        headers = []
        host = None
        for k, v in src.items():
            if k.startswith("request.headers.") and isinstance(v, str):
                headers.append(f"{k.split('request.headers.',1)[1]}: {v}")

        messages_text = []
        tags = []
        match_d = []
        rule_ids = []
        dat = []

        for m in src.get("messages", []) or []:
            det = m.get("details", {}) or {}
            if det.get("ruleId"):
                rule_ids.append(str(det.get("ruleId")))
            if m.get("message"):
                messages_text.append(m.get("message"))
            if det.get("tags"):
                tags.append(det.get("tags"))
            if det.get("match"):
                match_d.append(det.get("match"))
            if det.get("data"):
                dat.append(det.get("data"))

        out.append({
            "request_id": rid,
            "score": src.get("modsec.inbound_score"),
            "uri": src.get("request.uri"),
            "method": src.get("request.method"),

            # FIX: chỉ nhận body nếu thực sự là string
            "request_body": src.get("request.body") if isinstance(src.get("request.body"), str) else "",

            "request_headers": headers,
            "messages": messages_text,
            "rules": rule_ids,
            "datas": dat,

            "payload_location": payload.get("payload_location"),
            "payload_decoded": payload.get("payload_decoded"),
            "payload_detect": payload.get("payload_detect"),
            "payload_raw": payload.get("payload_raw"),

            "tags": tags,
            "match_d": match_d,
            "host": host,
        })

        rid += 1

    return out
