import requests
from app.utils.helpers import is_valid_ip

WAF_API_URL = "http://192.168.10.138:5001"
WAF_API_TOKEN = "testkey123"


def deny_ip(ip):
    """Thêm 1 IP vào blacklist."""
    try:
        # --- Kiểm tra IP hợp lệ ---
        if not is_valid_ip(ip):
            return f"⚠️ Địa chỉ IP không hợp lệ: {ip}"

        payload = {"ip": ip}
        resp = requests.post(
            f"{WAF_API_URL}/blacklist/add",
            headers={
                "Authorization": f"Bearer {WAF_API_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=5
        )

        if resp.status_code == 200:
            return f"✅ Đã thêm IP `{ip}` vào blacklist."
        elif resp.status_code == 409:
            return f"⚠️ IP `{ip}` đã tồn tại trong blacklist."
        else:
            return f"⚠️ Lỗi API WAF: {resp.status_code} — {resp.text}"

    except Exception as e:
        return f"⚠️ Không kết nối được API WAF: {e}"
