import requests
from app.utils.helpers import is_valid_ip

WAF_API_URL = "http://192.168.10.138:5001"
WAF_API_TOKEN = "testkey123"

def delete_ip(ip_type, ip):
    """
    Xóa 1 IP khỏi whitelist hoặc blacklist.
    ip_type: 'ip_whitelist' hoặc 'ip_blacklist'
    ip: địa chỉ IP cần xóa
    """
    try:
        endpoint = "/whitelist/remove" if ip_type == "ip_whitelist" else "/blacklist/remove"
        
        if not is_valid_ip(ip):
            return f"⚠️ Địa chỉ IP không hợp lệ: {ip}"
        payload = {"ip": ip}

        resp = requests.post(
            f"{WAF_API_URL}{endpoint}",
            headers={
                "Authorization": f"Bearer {WAF_API_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=5
        )

        if resp.status_code == 200:
            return f"✅ Đã xóa IP `{ip}` khỏi {ip_type}."
        elif resp.status_code == 404:
            return f"⚠️ IP `{ip}` không tồn tại trong {ip_type}."
        else:
            return f"⚠️ Lỗi API WAF: {resp.status_code} — {resp.text}"

    except Exception as e:
        return f"⚠️ Không kết nối được API WAF: {e}"