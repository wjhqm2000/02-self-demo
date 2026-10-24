"""License signing script — runs inside GitHub Actions (or locally for testing).

CRITICAL: canonical_json is imported from client.verify_license.  This is
THE single source of truth — the issuer and verifier MUST use identical
serialization, otherwise every signature will fail to verify.  If you ever
see a signature mismatch, first check that both sides are importing the SAME
canonical_json function (same file, same Python version).

Output format: LICB V2 binary (NOT a JSON envelope), byte-compatible with
compressed migration's ``license::verify_license_file_v2``:

    offset  len  field
    0x0000    4  MAGIC  "LICB"
    0x0004    2  VERSION = 2           (uint16 LE)
    0x0006    4  PAYLOAD_LENGTH = N    (uint32 LE)
    0x000A    4  SIG_LENGTH = 256      (uint32 LE)
    0x000E    N  payload  = canonical_json(payload) raw bytes
    0x000E+N 256 signature = RSA-2048 PKCS#1 v1.5 + SHA-256

Signature padding MUST be PKCS#1 v1.5 (NOT PSS) — the C++ client uses
BCrypt RSASSA-PKCS1-v1_5.

Flow inside GHA:
  1. Workflow sets env.RSA_PRIVATE_KEY from Secrets and env.CLIENT_PAYLOAD
     from github.event.client_payload.
  2. This script verifies the HMAC auth, validates the card payload
     (fail-closed: never silently falls back to "lifetime"), computes eat
     from the card type, signs, writes <key>.lic (raw LICB V2 bytes) to
     LICENSE_OUT_DIR.
  3. The workflow then commits and pushes the .lic to the ``license-result``
     branch with GITHUB_TOKEN.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Import canonical_json from the CLIENT module — single source of truth.
# This means GHA must checkout the full repo (both client/ and issuer/).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from client.verify_license import canonical_json  # noqa: E402 — after sys.path setup

# ---------------------------------------------------------------------------
# LICB V2 container constants (compressed migration DELIVERABLE §15.2)
# ---------------------------------------------------------------------------

LICB_MAGIC = b"LICB"
LICB_VERSION = 2
LICB_HEADER_SIZE = 14          # 4 magic + 2 version + 4 payload_len + 4 sig_len
LICB_SIG_LEN = 256             # RSA-2048
PAYLOAD_MAX_BYTES = 1024 * 1024

# Payload schema (DELIVERABLE §15.3)
PAYLOAD_FORMAT_VERSION = 2
DEFAULT_HW_THRESHOLD = 50
CARD_TYPES = ("permanent", "day", "minute", "bypass")
BYPASS_GRACE_DAYS = 3
SNAPSHOT_KEYS = ("disk", "board", "mac", "cpu", "uuid")

SECONDS_PER_DAY = 86400
SECONDS_PER_MINUTE = 60

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class LicenseRejected(ValueError):
    """Payload failed schema validation — refuse to sign (never default lifetime)."""


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def _load_private_key_from_string(pem_text: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA")
    return key


def _load_private_key_from_file(path: str | Path) -> rsa.RSAPrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA")
    return key


# ---------------------------------------------------------------------------
# Schema validation — strict, fail-closed
# ---------------------------------------------------------------------------

def _require_int(value: Any, name: str, *, positive: bool) -> int:
    """Accept real ints only; bool is an int subclass and must be rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LicenseRejected(f"字段 {name} 必须是整数，实际: {value!r}")
    if positive and value <= 0:
        raise LicenseRejected(f"字段 {name} 必须为正整数，实际: {value}")
    return value


def _validate_snapshot(bl: Any) -> Dict[str, str]:
    """bl 必须是恰好 5 个字符串字段的对象（缺失值用 "NAN"，不允许数组）。"""
    if not isinstance(bl, dict):
        raise LicenseRejected(f"字段 hw_snapshot 必须是对象，实际: {type(bl).__name__}")
    missing = [k for k in SNAPSHOT_KEYS if k not in bl]
    extra = [k for k in bl if k not in SNAPSHOT_KEYS]
    if missing or extra:
        raise LicenseRejected(
            f"hw_snapshot 字段不匹配：缺少 {missing}，多余 {extra}"
        )
    out: Dict[str, str] = {}
    for k in SNAPSHOT_KEYS:
        v = bl[k]
        if not isinstance(v, str) or not v:
            raise LicenseRejected(f"hw_snapshot.{k} 必须是非空字符串，实际: {v!r}")
        out[k] = v
    return out


def _require_str(cp: Dict[str, Any], name: str) -> str:
    v = cp.get(name)
    if not isinstance(v, str) or not v.strip():
        raise LicenseRejected(f"字段 {name} 缺失或不是非空字符串，实际: {v!r}")
    return v


def build_v2_payload(
    cp: Dict[str, Any],
    *,
    issued_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Build (and validate) the LICB V2 payload dict.

    `cp` is the client_payload uploaded by trigger_and_fetch.py:
        mid, card_type, remaining_days, remaining_minutes,
        hw_snapshot, card_id, key, customer_id, tier, auth

    eat rules (no hard-coded day counts anywhere):
        permanent → eat=0, perm=true
        day       → eat=iat+remaining_days*86400
        minute    → eat=iat+remaining_minutes*60
        bypass    → eat=iat+3*86400 (grace window), perm=false

    Any missing / mistyped field raises LicenseRejected — we NEVER fall back
    to "lifetime" on bad input.
    """
    if not isinstance(cp, dict):
        raise LicenseRejected(f"client_payload 必须是对象，实际: {type(cp).__name__}")

    card_type = cp.get("card_type")
    if not isinstance(card_type, str) or card_type not in CARD_TYPES:
        raise LicenseRejected(
            f"card_type 非法: {card_type!r}（仅接受 {'/'.join(CARD_TYPES)}）"
        )

    mid = _require_str(cp, "mid")
    if not _HEX64.match(mid):
        raise LicenseRejected(f"mid 必须是 64 位小写 HEX，实际: {mid!r}")

    card = cp.get("card_id") if cp.get("card_id") is not None else cp.get("card")
    if not isinstance(card, str) or not card.strip():
        raise LicenseRejected(f"字段 card_id 缺失或不是非空字符串，实际: {card!r}")
    if not 6 <= len(card) <= 128:
        raise LicenseRejected(f"card_id 长度非法（应为卡密脱敏哈希），实际: {card!r}")

    bl = _validate_snapshot(cp.get("hw_snapshot"))

    # thr 由签发侧固定：客户端不得调低阈值，否则可弱化硬件绑定。
    provided_thr = cp.get("thr")
    if provided_thr is not None:
        provided_thr = _require_int(provided_thr, "thr", positive=True)
        if provided_thr != DEFAULT_HW_THRESHOLD:
            raise LicenseRejected(
                f"thr 必须为 {DEFAULT_HW_THRESHOLD}（不允许客户端调低阈值），"
                f"实际: {provided_thr}"
            )
    thr = DEFAULT_HW_THRESHOLD

    now = int(time.time()) if issued_at is None else int(issued_at)
    if now <= 0:
        raise LicenseRejected(f"iat 非法: {now}")

    if card_type == "permanent":
        eat, perm = 0, True
    elif card_type == "day":
        days = _require_int(cp.get("remaining_days"), "remaining_days", positive=True)
        eat, perm = now + days * SECONDS_PER_DAY, False
    elif card_type == "minute":
        minutes = _require_int(
            cp.get("remaining_minutes"), "remaining_minutes", positive=True
        )
        eat, perm = now + minutes * SECONDS_PER_MINUTE, False
    else:  # bypass — 后台关闭验证，给 3 天宽限
        eat, perm = now + BYPASS_GRACE_DAYS * SECONDS_PER_DAY, False

    payload: Dict[str, Any] = {
        "v": PAYLOAD_FORMAT_VERSION,
        "mid": mid,
        "card": card,
        "iat": now,
        "eat": eat,
        "perm": perm,
        "thr": thr,
        "bl": {k: bl[k] for k in sorted(SNAPSHOT_KEYS)},
    }
    return payload


# ---------------------------------------------------------------------------
# LICB V2 assembly + signing
# ---------------------------------------------------------------------------

def sign_v2(payload: Dict[str, Any], private_key: rsa.RSAPrivateKey) -> bytes:
    """canonical_json(payload) → PKCS#1 v1.5 SHA-256 → LICB V2 bytes."""
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be RSA")

    raw = canonical_json(payload)          # SAME function as client verifier
    if len(raw) > PAYLOAD_MAX_BYTES:
        raise LicenseRejected(
            f"payload 超过上限：{len(raw)} > {PAYLOAD_MAX_BYTES} 字节"
        )

    sig = private_key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
    if len(sig) != LICB_SIG_LEN:
        raise RuntimeError(f"unexpected signature length: {len(sig)} (want 256)")

    header = (
        LICB_MAGIC
        + struct.pack("<H", LICB_VERSION)
        + struct.pack("<I", len(raw))
        + struct.pack("<I", len(sig))
    )
    return header + raw + sig


def issue_license(
    cp: Dict[str, Any],
    private_key: rsa.RSAPrivateKey,
    *,
    issued_at: Optional[int] = None,
) -> bytes:
    """Validate payload → build V2 payload → return raw LICB V2 bytes."""
    payload = build_v2_payload(cp, issued_at=issued_at)
    return sign_v2(payload, private_key)


# ---------------------------------------------------------------------------
# HMAC auth — covers EVERY client_payload field except "auth" itself
# ---------------------------------------------------------------------------

def _auth_message(cp: Dict[str, Any]) -> str:
    body = {k: v for k, v in cp.items() if k != "auth"}
    return canonical_json(body).decode("utf-8")


def _verify_hmac_auth(cp: Dict[str, Any]) -> None:
    """轻量防刷：重算 HMAC-SHA256 并恒时比对。

    与 client/trigger_and_fetch.py 的同名逻辑必须完全一致（同一 canonical_json）。
    """
    secret = os.environ.get("DEMO_HMAC_SECRET")
    if not secret:
        raise RuntimeError(
            "env DEMO_HMAC_SECRET not set — required in GHA mode (anti-abuse)"
        )
    provided = cp.get("auth", "")
    if not isinstance(provided, str):
        raise RuntimeError("HMAC auth field is not a string — rejecting dispatch")
    expected = hmac.new(
        secret.encode("utf-8"), _auth_message(cp).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise RuntimeError("HMAC auth check failed — rejecting dispatch")


# ---------------------------------------------------------------------------
# Top-level: read env vars, sign, write file
# ---------------------------------------------------------------------------

def sign_from_env() -> Path:
    """Entry point called inside GitHub Actions. Writes raw LICB V2 bytes."""
    pem_text = os.environ.get("RSA_PRIVATE_KEY")
    if not pem_text:
        raise RuntimeError("env RSA_PRIVATE_KEY not set — did you wire Secrets?")

    raw_payload = os.environ.get("CLIENT_PAYLOAD")
    if not raw_payload:
        raise RuntimeError("env CLIENT_PAYLOAD not set")

    try:
        cp = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"CLIENT_PAYLOAD is not valid JSON: {exc}")

    # 防刷校验在加载私钥之前：无授权请求直接死在门口
    _verify_hmac_auth(cp)

    key = _require_str(cp, "key")

    private_key = _load_private_key_from_string(pem_text)
    payload = build_v2_payload(cp)
    lic_bytes = sign_v2(payload, private_key)

    # 产物写到 LICENSE_OUT_DIR（GHA 里 = $RUNNER_TEMP），不污染 git 工作区，
    # 避免 checkout -f 被同名文件阻塞。
    out_dir = Path(os.environ.get("LICENSE_OUT_DIR", "."))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{key}.lic"
    out_path.write_bytes(lic_bytes)        # raw LICB V2, no JSON envelope

    print(f"Signed license written to {out_path}")
    print(f"  v            = {payload['v']}")
    print(f"  mid          = {payload['mid']}")
    print(f"  card         = {payload['card']}")
    print(f"  card_type    = {cp.get('card_type')}")
    print(f"  perm         = {payload['perm']}")
    print(f"  iat          = {payload['iat']}")
    print(f"  eat          = {payload['eat']}")
    print(f"  eat - iat    = {payload['eat'] - payload['iat']} seconds")
    print(f"  thr          = {payload['thr']}")
    print(f"  bl           = {json.dumps(payload['bl'], sort_keys=True)}")
    print(f"  file size    = {out_path.stat().st_size} bytes "
          f"(14 header + payload + 256 sig)")

    return out_path


# ---------------------------------------------------------------------------
# Local test CLI (NOT used by GHA — but useful for end-to-end local testing)
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    """CLI for local testing.

    Usage example:
        python issuer/sign_license.py \
            --private-key src/test/keys/test_only_private_1.pem \
            --payload-json '{"mid":"...","card_type":"day",...}' \
            --out out.lic
    """
    # If env vars are present (i.e., we ARE inside GHA), just run the env path.
    if os.environ.get("CLIENT_PAYLOAD") and os.environ.get("RSA_PRIVATE_KEY"):
        try:
            sign_from_env()
            return 0
        except Exception as exc:
            print(f"SIGN FAILED (env mode): {exc}", file=sys.stderr)
            return 1

    parser = argparse.ArgumentParser(
        prog="sign_license",
        description="Sign a LICB V2 license locally (for testing).",
    )
    parser.add_argument("--private-key", required=True,
                        help="Path to RSA private key .pem")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--payload-json", help="client_payload JSON string")
    src.add_argument("--payload-file", help="Path to client_payload JSON file")
    parser.add_argument("--out", default=None,
                        help="Output .lic path (default: <key>.lic)")
    parser.add_argument("--now", type=int, default=None,
                        help="Override iat (Unix seconds) for deterministic tests")
    args = parser.parse_args(argv)

    try:
        if args.payload_file:
            cp = json.loads(Path(args.payload_file).read_text(encoding="utf-8"))
        else:
            cp = json.loads(args.payload_json)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR loading payload: {exc}", file=sys.stderr)
        return 1

    # Local CLI: DEMO_HMAC_SECRET may be absent, but if present we verify.
    if os.environ.get("DEMO_HMAC_SECRET"):
        try:
            _verify_hmac_auth(cp)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    try:
        private_key = _load_private_key_from_file(args.private_key)
        payload = build_v2_payload(cp, issued_at=args.now)
        lic_bytes = sign_v2(payload, private_key)
    except LicenseRejected as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR signing: {exc}", file=sys.stderr)
        return 1

    key = cp.get("key")
    out = Path(args.out) if args.out else Path(f"{key}.lic")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(lic_bytes)

    print(f"Signed → {out} ({len(lic_bytes)} bytes)")
    print(f"  card_type = {cp.get('card_type')}")
    print(f"  iat       = {payload['iat']}")
    print(f"  eat       = {payload['eat']}")
    print(f"  perm      = {payload['perm']}")
    print(f"  eat - iat = {payload['eat'] - payload['iat']} seconds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
