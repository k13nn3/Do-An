import requests

WAF_API_URL = "http://192.168.10.138:5001"
WAF_API_TOKEN = "testkey123"

def list_ips(mode="whitelist"):
    """Liệt kê danh sách IP (whitelist hoặc blacklist) từ WAF API."""
    try:
        if mode not in ["whitelist", "blacklist"]:
            return "⚠️ Sai loại danh sách. Chỉ hỗ trợ whitelist hoặc blacklist."

        resp = requests.get(
            f"{WAF_API_URL}/{mode}/list",
            headers={"Authorization": f"Bearer {WAF_API_TOKEN}"},
            timeout=5
        )
        if resp.status_code != 200:
            return f"⚠️ Lỗi API WAF: {resp.status_code}"

        data_json = resp.json()
        ips = data_json.get(mode, [])
        total = data_json.get("total", len(ips))

        if not ips:
            icon = "📭"
            title = f"Danh sách {mode} IP hiện đang trống."
            return f"{icon} {title}"

        icon = "📜" if mode == "whitelist" else "🚫"
        title = "Whitelist" if mode == "whitelist" else "Blacklist"
        ip_list = "\n".join([f"• {ip}" for ip in ips])

        return f"*{icon} Danh sách {title} IP ({total} IP)*\n{ip_list}"

    except Exception as e:
        return f"⚠️ Không kết nối được API WAF: {e}"