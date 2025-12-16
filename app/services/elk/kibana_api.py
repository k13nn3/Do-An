import requests

KIBANA_URL = "http://192.168.10.140:5601"
AUTH = ("elastic", "elastic")
HEADERS = {"Content-Type": "application/json", "kbn-xsrf": "true"}

def create_case(ip: str) -> str:
    body = {
        "title": f"WAF Case - {ip}",
        "description": "WAF alerts for this IP",
        "tags": [],
        "settings": {"syncAlerts": True},
        "owner": "securitySolution",
        "connector": {
            "id": "none",
            "name": "none",
            "type": ".none",
            "fields": None
        }
    }

    r = requests.post(
        f"{KIBANA_URL}/api/cases",
        json=body,
        headers=HEADERS,
        auth=AUTH,
        verify=False
    )
    r.raise_for_status()

    return r.json().get("id")


def attach_alert(case_id: str, alert_id: str):
    body = [
        {
            "type": "alert",
            "alertId": alert_id,
            "owner": "securitySolution",
            "index": ".internal.alerts-security.alerts-default-000002",
            "rule": {
                "id": "",
                "name": "WAF Security Detect Attack"
            }
        }
    ]

    r = requests.post(
        f"{KIBANA_URL}/internal/cases/{case_id}/attachments/_bulk_create",
        json=body,
        headers=HEADERS,
        auth=AUTH,
        verify=False
    )
    r.raise_for_status()

def get_case_version(case_id: str) -> str:
    """
    Lấy version của case từ Kibana.
    Version là bắt buộc khi PATCH case.
    """
    r = requests.get(
        f"{KIBANA_URL}/api/cases/{case_id}",
        headers=HEADERS,
        auth=AUTH,
        verify=False
    )
    r.raise_for_status()
    return r.json().get("version")


def close_case_in_kibana(case_id: str):
    """
    Đổi trạng thái case sang closed trên Kibana theo đúng format mới.
    """
    version = get_case_version(case_id)

    body = {
        "cases": [
            {
                "id": case_id,
                "status": "closed",
                "version": version
            }
        ]
    }

    r = requests.patch(
        f"{KIBANA_URL}/api/cases",
        json=body,
        headers=HEADERS,
        auth=AUTH,
        verify=False
    )
    r.raise_for_status()

    return True