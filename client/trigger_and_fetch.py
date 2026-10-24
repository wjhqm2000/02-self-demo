"""Client-side activation flow — 卡密通验卡 + GitHub 签发 LICB V2 + 落盘。

流程（fail-closed：卡密通验不过绝不触发 GitHub）：
  Step 0  读 config.json（新增必填 card_code）
  Step 1  采集本机 5 项硬件快照 + 计算设备指纹 mid
          （与 compressed migration 的 hardware::collect_current_snapshot /
            fingerprint::get_device_fingerprint 逐字段同规则，见 DELIVERABLE 第 15 节）
  Step 2  调卡密通验卡（GET check.php，MD5 响应签名 + 120s 时间戳容差）
          失败即中止，不触发 GitHub
  Step 3  Phase 1 — repository_dispatch 触发 GHA，轮询 run 状态至 success
  Step 4  Phase 2 — 轮询 raw.githubusercontent.com 取 .lic（这里是 LICB V2 二进制）
  Step 5  校验 LICB V2 头 + RSA PKCS#1 v1.5 签名，通过后原样落盘（不做任何重序列化）

签名算法口径：RSA-2048 + RSASSA-PKCS1-v1_5 + SHA-256（与 C++ 客户端一致）。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import struct
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Run: pip install requests",
          file=sys.stderr)
    raise SystemExit(1)

from .verify_license import (
    DEFAULT_LICENSE_DIR,
    DEFAULT_LICENSE_FILE,
    canonical_json,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POLL_INTERVAL_PHASE1 = 5      # seconds between GHA run-status polls
POLL_INTERVAL_PHASE2 = 5      # seconds between raw URL polls
PHASE1_TIMEOUT = 180          # 3 minutes — covers GHA cold-start + queue
PHASE2_TIMEOUT = 60           # 1 minute — absorbs CDN propagation delay

DEFAULT_CONFIG_PATH = Path.home() / ".self-demo" / "config.json"

# ---------------------------------------------------------------------------
# 卡密通 V7.5 协议常量
# 对应 compressed migration/include/kami/kami_protocol.h:29-44
#   USER_ID / APP_NAME / SIGN_KEY / TIMESTAMP_TOLERANCE_SEC
# 域名与压缩项目 domain_router.cpp:24-26 一致（主 → 备 → 主 交替）
# ---------------------------------------------------------------------------
KAMI_PRIMARY_DOMAIN = "www.keyt.cn"
KAMI_BACKUP_DOMAIN = "keyt.srwz.net"
KAMI_USER_ID = "bengbu10086"
KAMI_APP_NAME = "a"
KAMI_SIGN_KEY = "ecc1b218ba2f23d5e8183e74c609a5d4"
KAMI_TS_TOLERANCE_SEC = 120

# ---------------------------------------------------------------------------
# 安全修复 #7（轻量防刷）：客户端硬编码的 HMAC 密钥。
# 必须与仓库 Secret DEMO_HMAC_SECRET 完全一致，否则 GHA 拒绝签名。
# 注意：这只是挡住"拿到 PAT 就随便刷授权"的路人，不防定向逆向。
# 部署时请改成你自己的随机值，并同步配置到仓库 Secrets。
# ---------------------------------------------------------------------------
DEMO_HMAC_SECRET = "k9sdfj239asdf"

# LICB V2 容器常量（与 compressed migration DELIVERABLE 第 15 节一致）
LICB_MAGIC = b"LICB"
LICB_VERSION = 2
LICB_HEADER_SIZE = 14          # 4 magic + 2 version + 4 payload_len + 4 sig_len
LICB_SIG_LEN = 256             # RSA-2048

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# 硬件快照采集（逐字段复刻 C++ hardware::collect_current_snapshot）
#
# C++ 规则来源：
#   include/hardware/snapshot.cpp:43-105   normalize_mac / normalize_uuid / normalize_field
#   include/hardware/snapshot.cpp:109-200  collect_current_snapshot
# 指纹输入串：src/fingerprint/fingerprint_impl.cpp:266-276
#   "D:{disk}|B:{board}|M:{mac}|C:{cpu}|U:{uuid}" → SHA-256 → 64 位小写 HEX
# ---------------------------------------------------------------------------

_PLACEHOLDER_FIELDS = {
    "n/a", "n.a.", "na",
    "default string", "defaultstring",
    "to be filled", "tobefilled",
    "not set", "notset",
    "not available", "notavailable",
    "not present", "notpresent",
    "unknown", "null", "none",
}

_BOARD_PLACEHOLDERS = {
    "", "to be filled", "to be filled by o.e.m.", "to be filled by oem",
    "default string", "default-string", "default system serial number",
    "system serial number", "system serial", "none", "not specified",
    "not available", "not present", "not defined", "unknown",
    "0", "1", "00000000", "ffffffff", "null",
}


def _ps_lines(command: str, timeout: int = 30) -> List[str]:
    """执行 PowerShell 并返回去空行后的 stdout（失败返回空列表）。"""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        if proc.returncode != 0:
            return []
        out = proc.stdout.replace("\ufeff", "")
        return [ln for ln in out.splitlines() if ln.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def _ps_first(command: str) -> str:
    lines = _ps_lines(command)
    return lines[0].strip() if lines else ""


def _normalize_field(value: str) -> str:
    """通用字段规范化 → 空/过短/已知占位符返回 NAN；否则保留原始大小写。"""
    v = (value or "").strip()
    if not v or len(v) <= 4:
        return "NAN"
    if v.lower() in _PLACEHOLDER_FIELDS:
        return "NAN"
    return v


def _normalize_uuid(value: str, available: bool = True) -> str:
    if not available:
        return "NAN"
    s = (value or "").strip()
    if len(s) < 30:
        return "NAN"
    s = s.lstrip("{<").rstrip("}>")
    if len(s) < 30:
        return "NAN"
    digits = s.replace("-", "").upper()
    if digits and (set(digits) == {"0"} or set(digits) == {"F"}):
        return "NAN"
    return s.upper()


def _normalize_mac(value: str) -> str:
    """'CC-96-E5-29-56-6C' → 'CC96E529566C'；全零/全 FF → NAN。"""
    hex_only = "".join(ch for ch in (value or "") if ch in "0123456789abcdefABCDEF")
    if len(hex_only) != 12:
        return "NAN"
    up = hex_only.upper()
    if up == "0" * 12 or up == "F" * 12:
        return "NAN"
    return up


def _cpu_id() -> str:
    """复刻 C++：vendor + "_" + brand + "_" + hex(model)。

    model() 见 include/os/windows/cpu_info.cpp:67-74：
        (eax & 0x3FFF) | ((eax & 0x3FF8000) >> 2) | ((ebx & 0xFF) << 24)
    Win32_Processor.ProcessorId = EDX(8 hex) + EAX(8 hex)，故 eax 可直接取出；
    EBX 低 8 位为 brand index，桌面/服务器 Intel、AMD 均为 0。
    """
    vendor = _ps_first("(Get-CimInstance Win32_Processor).Manufacturer")
    brand = _ps_first("(Get-CimInstance Win32_Processor).Name")
    proc_id = _ps_first("(Get-CimInstance Win32_Processor).ProcessorId")

    model_hex = ""
    if len(proc_id) == 16:
        try:
            eax = int(proc_id[8:16], 16)
            model = (eax & 0x3FFF) | ((eax & 0x3FF8000) >> 2) | (0 << 24)
            model_hex = format(model, "x")
        except ValueError:
            model_hex = ""

    if not vendor and not brand:
        return "NAN"
    combined = f"{vendor}_{brand}_{model_hex}"
    norm = _normalize_field(combined)
    return norm if norm != "NAN" else combined.strip()


def collect_hw_snapshot() -> Dict[str, str]:
    """采集 5 项硬件快照 → {"disk","board","mac","cpu","uuid"}（缺失为 "NAN"）。"""
    snap = {"disk": "NAN", "board": "NAN", "mac": "NAN",
            "cpu": "NAN", "uuid": "NAN"}

    # ① 硬盘 SN：C++ 取第一块 normalize 后有效的盘；都无效则取第一块原始值
    disk_serials = [ln.strip() for ln in
                    _ps_lines("(Get-CimInstance Win32_DiskDrive).SerialNumber")]
    disk_serials = [s for s in disk_serials if s]
    for sn in disk_serials:
        norm = _normalize_field(sn)
        if norm != "NAN":
            snap["disk"] = norm
            break
    if snap["disk"] == "NAN" and disk_serials:
        first = disk_serials[0].strip()
        if first:
            snap["disk"] = first

    # ② 主板 SN
    board_sn = _ps_first("(Get-CimInstance Win32_BaseBoard).SerialNumber").strip()
    if board_sn and board_sn.lower() not in _BOARD_PLACEHOLDERS:
        norm = _normalize_field(board_sn)
        if norm != "NAN":
            snap["board"] = norm

    # ③ MAC：第一个有效网卡（C++ getAdapterInfos 顺序，实测与 Get-NetAdapter 一致）
    for mac in _ps_lines("Get-NetAdapter | Select-Object -ExpandProperty MacAddress"):
        norm = _normalize_mac(mac.strip())
        if norm != "NAN":
            snap["mac"] = norm
            break

    # ④ CPU
    snap["cpu"] = _cpu_id()

    # ⑤ System UUID（SMBIOS Type 1，与 C++ DmiInfo 同源）
    uuid_raw = _ps_first("(Get-CimInstance Win32_ComputerSystemProduct).UUID")
    snap["uuid"] = _normalize_uuid(uuid_raw)

    return snap


def compute_device_fingerprint(snapshot: Dict[str, str]) -> str:
    """mid = SHA-256("D:x|B:x|M:x|C:x|U:x") 的 64 位小写 HEX。"""
    raw = "D:{disk}|B:{board}|M:{mac}|C:{cpu}|U:{uuid}".format(
        disk=snapshot.get("disk", "NAN"),
        board=snapshot.get("board", "NAN"),
        mac=snapshot.get("mac", "NAN"),
        cpu=snapshot.get("cpu", "NAN"),
        uuid=snapshot.get("uuid", "NAN"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 卡密通验卡（对应 kami_protocol.cpp / kami_provider.cpp）
# ---------------------------------------------------------------------------

def _url_encode(value: str) -> str:
    """等价于 C++ url_encode：unreserved = A-Za-z0-9-_.~，空格 → %20。"""
    return urllib.parse.quote(value, safe="-_.~")


def _kami_verify_response(raw: str, x_sign2: str) -> Tuple[str, str]:
    """校验响应签名 + 时间戳（kami_protocol.cpp:102-172）。

    返回 (verify_code, biz)：verify_code ∈
        ok / signature_invalid / timestamp_expired / parse_error
    """
    if not raw:
        return "parse_error", ""

    marker = "|sign="
    pos = raw.find(marker)
    if pos != -1:
        body_with_ts = raw[:pos]
        sign_in_body = raw[pos + len(marker):]
    else:
        body_with_ts = raw
        sign_in_body = ""

    # X-Sign2 头优先；否则用响应体 sign=
    server_sign = (x_sign2 or "").strip() or sign_in_body.strip()
    if not server_sign:
        return "signature_invalid", ""

    local_sign = hashlib.md5(
        (body_with_ts + KAMI_SIGN_KEY).encode("utf-8")
    ).hexdigest()
    if local_sign.lower() != server_sign.lower():
        return "signature_invalid", ""

    last_pipe = body_with_ts.rfind("|")
    if last_pipe == -1:
        return "parse_error", ""
    ts_str = body_with_ts[last_pipe + 1:].strip()
    if not ts_str.isdigit():
        return "parse_error", ""

    server_ts = int(ts_str)
    local_ts = int(time.time())
    if abs(server_ts - local_ts) > KAMI_TS_TOLERANCE_SEC:
        return "timestamp_expired", ""

    return "ok", body_with_ts[:last_pipe]


def _kami_parse_biz(biz: str) -> Dict[str, Any]:
    """解析业务体（kami_protocol.cpp:176-239 + kami_provider.cpp:167-190）。"""
    if "bypass" in biz:
        return {"ok": True, "card_type": "bypass", "permanent": True,
                "remaining_days": 0, "remaining_minutes": -1,
                "desc": "验证已关闭（bypass）"}

    if not biz.startswith("ok|"):
        if biz.startswith("error|"):
            parts = biz.split("|")
            code = parts[1] if len(parts) > 1 else "unknown_error"
            return {"ok": False, "error_code": code,
                    "error_message": _kami_error_text(code)}
        return {"ok": False, "error_code": "unknown_error",
                "error_message": "服务器响应格式错误"}

    parts = biz.split("|")

    # 永久卡：parts[1] 或 parts[2] == "permanent"
    if (len(parts) >= 2 and parts[1] == "permanent") or \
       (len(parts) >= 3 and parts[2] == "permanent"):
        return {"ok": True, "card_type": "permanent", "permanent": True,
                "remaining_days": 0, "remaining_minutes": -1,
                "desc": "永久有效"}

    # 限时卡：优先 parts[3]（剩余总分钟），否则 parts[1]（天数）
    total_mins = None
    card_type = ""
    if len(parts) >= 4 and parts[3].isdigit():
        total_mins = int(parts[3])
        card_type = "minute"
    elif len(parts) >= 2 and parts[1].isdigit():
        total_mins = int(parts[1]) * 1440
        card_type = "day"

    if total_mins is None or total_mins <= 0:
        return {"ok": False, "error_code": "unknown_error",
                "error_message": "无法解析卡密剩余时间"}

    days = total_mins // 1440
    minutes = total_mins % 60
    hours = (total_mins % 1440) // 60
    desc = f"剩余 {days} 天"
    if hours:
        desc += f" {hours} 小时"
    if minutes:
        desc += f" {minutes} 分钟"

    return {"ok": True, "card_type": card_type, "permanent": False,
            "remaining_days": days, "remaining_minutes": total_mins,
            "desc": desc}


_ERROR_TEXT = {
    "invalid_card": "卡密无效，请检查后重试",
    "expired": "卡密已过期",
    "banned": "卡密已被禁用，请联系卖家",
    "already_online": "该卡密已在其他设备在线，请先下线",
    "online_limit_reached": "在线设备数已满，请稍后再试",
    "device_mismatch": "设备不匹配，该卡密已绑定其他机器",
    "too_frequent": "验证过于频繁，请 50 秒后再试",
    "system_locked": "系统已被管理员锁死，请联系卖家",
    "missing_params": "请求参数不完整",
}


def _kami_error_text(code: str) -> str:
    return _ERROR_TEXT.get(code, "未知错误")


def verify_card_with_kami(card_code: str, machine_id: str) -> Dict[str, Any]:
    """调卡密通验卡。成功返回 {"ok":True,...}，失败返回 {"ok":False,...}。

    fail-closed：任何异常/验签失败/业务错误都返回 ok=False，调用方必须中止。
    """
    if not card_code or not machine_id:
        return {"ok": False, "error_code": "missing_params",
                "error_message": _kami_error_text("missing_params")}

    query = (
        "card=" + _url_encode(card_code)
        + "&mac=" + _url_encode(machine_id)
        + "&app=" + KAMI_APP_NAME
        + "&heart=1"
        + "&t=" + time.strftime("%Y%m%d%H%M%S", time.localtime())
        + "&_t=" + str(int(time.time()))
    )

    # 主 → 备 → 主；只有网络层错误才重试（签名/时间戳错误重试也不会变）
    last_error = {"ok": False, "error_code": "network_error",
                  "error_message": "网络请求失败，请检查网络连接"}
    for domain in (KAMI_PRIMARY_DOMAIN, KAMI_BACKUP_DOMAIN, KAMI_PRIMARY_DOMAIN):
        url = f"https://{domain}/kami/{KAMI_USER_ID}/check.php?{query}"
        try:
            resp = requests.get(url, timeout=(4, 15))
        except requests.RequestException:
            last_error = {"ok": False, "error_code": "network_error",
                          "error_message": "网络请求失败，请检查网络连接"}
            time.sleep(0.5)
            continue

        if resp.status_code != 200:
            last_error = {"ok": False, "error_code": f"http_{resp.status_code}",
                          "error_message": f"服务器返回 HTTP {resp.status_code}"}
            time.sleep(0.5)
            continue

        raw = (resp.text or "").strip()

        # 系统锁死优先判定（kami_provider.cpp:98-102）
        if "system_locked" in raw:
            return {"ok": False, "error_code": "system_locked",
                    "error_message": _kami_error_text("system_locked")}

        code, biz = _kami_verify_response(raw, resp.headers.get("X-Sign2", ""))
        if code == "signature_invalid":
            return {"ok": False, "error_code": code,
                    "error_message": "服务器响应签名校验失败（可能遭遇中间人篡改）"}
        if code == "timestamp_expired":
            return {"ok": False, "error_code": code,
                    "error_message": "本地时间与服务器相差过大，请校准系统时间"}
        if code != "ok":
            return {"ok": False, "error_code": code,
                    "error_message": "服务器响应格式错误"}

        parsed = _kami_parse_biz(biz)
        parsed["biz_body"] = biz
        return parsed

    return last_error


# ---------------------------------------------------------------------------
# HMAC 防刷（覆盖 client_payload 全部字段）
# ---------------------------------------------------------------------------

def _auth_message(payload: Dict[str, Any]) -> str:
    """auth 覆盖除 auth 自身外的全部字段，用 canonical_json 归一化。

    与 issuer/sign_license.py 的同名逻辑必须完全一致。
    """
    body = {k: v for k, v in payload.items() if k != "auth"}
    return canonical_json(body).decode("utf-8")


def _compute_auth(payload: Dict[str, Any]) -> str:
    return hmac.new(
        DEMO_HMAC_SECRET.encode("utf-8"),
        _auth_message(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: Optional[Path] = None) -> Dict[str, str]:
    p = path or DEFAULT_CONFIG_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"Config not found at {p}. "
            "Create it with keys: github_pat, repo_owner, repo_name, "
            "public_key_path, customer_id, tier, card_code"
        )
    data = json.loads(p.read_text(encoding="utf-8"))
    required = ("github_pat", "repo_owner", "repo_name",
                "public_key_path", "customer_id", "tier", "card_code")
    missing = [k for k in required if not data.get(k)]
    if missing:
        raise ValueError(f"config.json missing keys: {', '.join(missing)}")
    return data


def _hw_fp_to_key(mid: str) -> str:
    """文件名 key：稳定 16 位 hex（同一机器重复激活幂等覆盖）。"""
    return hashlib.sha256(mid.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# LICB V2 客户端校验 + 落盘（客户端绝不重新序列化 payload）
# ---------------------------------------------------------------------------

def _split_licb_v2(data: bytes) -> Tuple[bytes, bytes, str]:
    """拆 LICB V2 容器，返回 (payload, signature, error)。error 为空表示成功。"""
    if len(data) < LICB_HEADER_SIZE:
        return b"", b"", "文件太小，不是 LICB V2"
    if data[:4] != LICB_MAGIC:
        return b"", b"", "MAGIC 不匹配"
    version = struct.unpack("<H", data[4:6])[0]
    if version != LICB_VERSION:
        return b"", b"", f"不支持的版本 {version}"
    payload_len = struct.unpack("<I", data[6:10])[0]
    sig_len = struct.unpack("<I", data[10:14])[0]
    if sig_len != LICB_SIG_LEN:
        return b"", b"", f"签名长度非法 {sig_len}"
    if len(data) != LICB_HEADER_SIZE + payload_len + sig_len:
        return b"", b"", "文件长度与头部声明不一致"
    payload = data[LICB_HEADER_SIZE:LICB_HEADER_SIZE + payload_len]
    sig = data[LICB_HEADER_SIZE + payload_len:]
    return payload, sig, ""


def verify_licb_v2(data: bytes, public_key_pem_path: str | Path) -> Tuple[bool, str]:
    """本地校验 LICB V2：头结构 + RSA PKCS#1 v1.5 + SHA-256 签名。"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    payload, sig, err = _split_licb_v2(data)
    if err:
        return False, err

    try:
        pub = serialization.load_pem_public_key(Path(public_key_pem_path).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        return False, f"公钥加载失败: {exc}"

    try:
        pub.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False, "签名校验失败（文件被篡改或非官方签发）"
    except (ValueError, TypeError) as exc:
        return False, f"签名格式非法: {exc}"
    return True, ""


def _save_license(data: bytes) -> Path:
    DEFAULT_LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_LICENSE_FILE.write_bytes(data)   # 原样落盘，不做编码转换
    return DEFAULT_LICENSE_FILE


# ---------------------------------------------------------------------------
# Phase 1 — repository_dispatch + GHA run status polling
# ---------------------------------------------------------------------------

def _trigger_dispatch(owner: str, repo: str, pat: str,
                      client_payload: Dict[str, Any]) -> Optional[int]:
    """POST /repos/{owner}/{repo}/dispatches. Return run_id on success."""
    url = f"https://api.github.com/repos/{owner}/{repo}/dispatches"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {"event_type": "issue-license", "client_payload": client_payload}

    resp = requests.post(url, headers=headers, json=body, timeout=15)
    if resp.status_code != 204:
        print(f"  dispatch POST failed: HTTP {resp.status_code}", file=sys.stderr)
        print(f"  {resp.text[:500]}", file=sys.stderr)
        return None

    print("  dispatch accepted by GitHub. Waiting for run to be created...")

    key = client_payload["key"]
    list_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
    list_params = {"per_page": 10, "event": "repository_dispatch"}
    expected_title = f"issue-license {key}"

    for _ in range(20):  # 20 * 2s = 40s max wait for run creation
        time.sleep(2)
        try:
            resp2 = requests.get(list_url, headers=headers,
                                 params=list_params, timeout=15)
        except requests.RequestException:
            continue
        if resp2.status_code != 200:
            continue

        items = resp2.json().get("workflow_runs", [])
        for run in items:
            if run.get("display_title") == expected_title:
                print(f"  run #{run['id']} matched by display_title: {expected_title}")
                return run["id"]

    print("  run creation timed out — couldn't locate run with "
          f"display_title='{expected_title}'.", file=sys.stderr)
    return None


def _poll_run_status(owner: str, repo: str, pat: str, run_id: int,
                     timeout: int = PHASE1_TIMEOUT) -> Optional[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    deadline = time.monotonic() + timeout
    print(f"  phase 1: waiting for GHA run #{run_id} to finish "
          f"(timeout {timeout}s)...")

    while time.monotonic() < deadline:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"  run GET HTTP {resp.status_code}, retrying...")
            time.sleep(POLL_INTERVAL_PHASE1)
            continue

        run = resp.json()
        status = run.get("status")
        conclusion = run.get("conclusion")
        print(f"    run status={status}, conclusion={conclusion}")

        if status == "completed":
            return conclusion

        time.sleep(POLL_INTERVAL_PHASE1)

    print(f"  phase 1 timeout after {timeout}s — run still not completed.",
          file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Phase 2 — raw.githubusercontent.com polling（二进制，缓存穿透参数）
# ---------------------------------------------------------------------------

def _fetch_license_raw(owner: str, repo: str, key: str,
                       timeout: int = PHASE2_TIMEOUT) -> Optional[bytes]:
    """轮询 raw URL 直到 .lic 出现；返回**二进制**内容（LICB V2）。"""
    base = f"https://raw.githubusercontent.com/{owner}/{repo}/license-result/{key}.lic"
    deadline = time.monotonic() + timeout
    print(f"  phase 2: waiting for .lic file at raw URL "
          f"(timeout {timeout}s)...")

    while time.monotonic() < deadline:
        url = f"{base}?t={int(time.time())}"
        try:
            resp = requests.get(url, timeout=15)
        except requests.RequestException as exc:
            print(f"    network error: {exc}, retrying...")
            time.sleep(POLL_INTERVAL_PHASE2)
            continue

        if resp.status_code == 200:
            content = resp.content          # 必须用 content，不能用 text
            print(f"    .lic file fetched (HTTP 200, {len(content)} bytes)")
            return content

        if resp.status_code == 404:
            print("    HTTP 404 — file not yet propagated, retrying...")
        else:
            print(f"    HTTP {resp.status_code}, retrying...")

        time.sleep(POLL_INTERVAL_PHASE2)

    print(f"  phase 2 timeout after {timeout}s — .lic file never appeared.",
          file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def activate(config_path: Optional[Path] = None) -> int:
    """完整激活流程。返回 0 成功，非 0 失败（fail-closed）。"""
    try:
        cfg = load_config(config_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 1

    # --- Step 1: 本机指纹 + 硬件快照 ------------------------------------
    snapshot = collect_hw_snapshot()
    mid = compute_device_fingerprint(snapshot)
    key = _hw_fp_to_key(mid)

    print(f"device mid     : {mid}")
    print(f"filename key   : {key}")
    print("hw snapshot    : " + json.dumps(snapshot, ensure_ascii=False,
                                          sort_keys=True))
    print(f"customer       : {cfg['customer_id']}")
    print(f"tier           : {cfg['tier']}")
    print()

    # --- Step 2: 卡密通验卡（失败即中止，不触发 GitHub）------------------
    print("[step 2] 卡密通验卡...")
    kami = verify_card_with_kami(cfg["card_code"], mid)
    if not kami.get("ok"):
        print(f"  卡密验证未通过：{kami.get('error_message', '未知错误')} "
              f"(code={kami.get('error_code')})", file=sys.stderr)
        print("  已中止，未触发 GitHub 签发。", file=sys.stderr)
        return 1
    card_type = kami["card_type"]
    print(f"  验卡通过 ✓  card_type={card_type}  {kami.get('desc', '')}")
    if card_type in ("day", "minute"):
        print(f"  remaining_days={kami['remaining_days']} "
              f"remaining_minutes={kami['remaining_minutes']}")

    # --- Step 3: 组装 client_payload（HMAC 覆盖全部字段）-----------------
    client_payload: Dict[str, Any] = {
        "mid": mid,
        "card_type": card_type,
        "remaining_days": int(kami.get("remaining_days", 0)),
        "remaining_minutes": int(kami.get("remaining_minutes", -1)),
        "hw_snapshot": snapshot,
        "card_id": hashlib.sha256(cfg["card_code"].encode("utf-8")).hexdigest()[:16],
        "key": key,
        "customer_id": cfg["customer_id"],
        "tier": cfg["tier"],
    }
    client_payload["auth"] = _compute_auth(client_payload)

    # --- Step 4: Phase 1 -------------------------------------------------
    print("[phase 1] triggering GitHub Actions workflow...")
    run_id = _trigger_dispatch(
        cfg["repo_owner"], cfg["repo_name"], cfg["github_pat"], client_payload,
    )
    if run_id is None:
        return 1

    conclusion = _poll_run_status(
        cfg["repo_owner"], cfg["repo_name"], cfg["github_pat"], run_id,
    )
    if conclusion != "success":
        print(f"  GHA run finished with conclusion='{conclusion}'. "
              f"Expected 'success'.", file=sys.stderr)
        return 1
    print("  GHA run succeeded ✓")

    # --- Step 5: Phase 2 -------------------------------------------------
    print("[phase 2] fetching .lic (LICB V2) from raw.githubusercontent.com...")
    lic_bytes = _fetch_license_raw(cfg["repo_owner"], cfg["repo_name"], key)
    if lic_bytes is None:
        return 1

    # --- Step 6: 校验 + 原样落盘 -----------------------------------------
    print("[phase 3] verifying LICB V2 signature + persisting license...")
    ok, reason = verify_licb_v2(lic_bytes, cfg["public_key_path"])
    if not ok:
        print(f"  verification FAILED: {reason}", file=sys.stderr)
        return 1

    saved = _save_license(lic_bytes)
    print(f"  verified ✓ — saved to {saved}")
    print()
    print(f"Activation complete. card_type={card_type}, "
          f"eat={'0 (permanent)' if card_type == 'permanent' else 'computed from remaining time'}.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trigger_and_fetch",
        description="激活：卡密通验卡 → GHA 签发 LICB V2 → 拉取 → 校验 → 落盘。",
    )
    parser.add_argument(
        "--config", default=None,
        help=f"Path to config.json (default: {DEFAULT_CONFIG_PATH})",
    )
    args = parser.parse_args(argv)
    return activate(Path(args.config) if args.config else None)


if __name__ == "__main__":
    raise SystemExit(main())
