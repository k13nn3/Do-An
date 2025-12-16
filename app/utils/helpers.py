import ipaddress

def get_nested_value(doc, path, default=0):
    keys = path.split('.')
    for key in keys:
        if isinstance(doc, dict) and key in doc:
            doc = doc[key]
        else:
            return default
    return doc or default

def is_valid_ip(ip: str) -> bool:
    """
    Kiểm tra định dạng địa chỉ IPv4 hoặc IPv6.
    Trả về True nếu hợp lệ, False nếu không.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False