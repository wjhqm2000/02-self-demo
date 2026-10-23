import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# 👉 把这里替换成你的 public.pem 全部内容
PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2DszZe9Nr8vucE59GUz3
DKB602hyecR71HVPxaTL1JYZCmO5cYQ/DEEUOekl01pQFcYD0SH/LUohIxdSbDNg
ZtD3YanWknkH3wffrlFcWrTCX/3fsVyPvzMpE/oxwz+8/tAvRVA6MrMPZeqxFkWp
SA01EHqEs6mZ1E0p4AgdJLX8Q9RcCcSdin7hUWs4xx7xJP4I++0uQfKcZHnDr1p2
zNa784fkYGzgYHDosfdzTnHhY9yp4sRwvg26H0ZnqwAwsC7X/YEYgcIc4NwOhFdf
KGfwDeZ0GP+U9ULTBxiAv7FuDRrZaNYNzVMTIcXypp7QXTRWcP035ajkKln3leKs
WQIDAQAB
-----END PUBLIC KEY-----
"""

def check_license(lic_file_path):
    with open(lic_file_path, "r", encoding="utf-8") as f:
        lic_data = json.load(f)

    # 严格序列化payload，和签名时保持一致
    payload_raw = json.dumps(lic_data["payload"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig_bytes = base64.b64decode(lic_data["signature"])

    pubkey = serialization.load_pem_public_key(PUB_KEY.encode("utf-8"))
    try:
        pubkey.verify(
            sig_bytes,
            payload_raw,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✅ RSA签名校验通过！")
        print("硬件指纹：", lic_data["payload"]["hw_fingerprint"])
        print("客户ID：", lic_data["payload"]["customer_id"])
        print("授权等级：", lic_data["payload"]["tier"])
        print("签发时间：", lic_data["payload"]["issued_at"])
        print("过期时间：", lic_data["payload"]["expires_at"])
    except Exception as err:
        print("❌ 签名校验失败：", err)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法：python check_lic.py 65916cfaa0141a01.lic")
    else:
        check_license(sys.argv[1])
