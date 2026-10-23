"""License signing script — runs inside GitHub Actions (or locally for testing).

CRITICAL: canonical_json is imported from client.verify_license.  This is
THE single source of truth — the issuer and verifier MUST use identical
serialization, otherwise every signature will fail to verify.  If you ever
see a signature mismatch, first check that both sides are importing the SAME
canonical_json function (same file, same Python version).

Flow inside GHA:
  1. Workflow sets env.RSA_PRIVATE_KEY from Secrets and env.CLIENT_PAYLOAD
     from github.event.client_payload.
  2. This script parses those, builds the payload dict, signs it, writes
     <key>.lic to the current working directory.
  3. The workflow then commits and pushes the .lic to the ``license-result``
     branch with GITHUB_TOKEN.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Import canonical_json / hash_sensitive from the CLIENT module — single
# source of truth. This means GHA must checkout the full repo (both client/
# and issuer/).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from client.verify_license import (  # noqa: E402 — import after sys.path setup
    LICENSE_ALGORITHM,
    LICENSE_VERSION,
    TIMESTAMP_FORMAT,
    canonical_json,
    hash_sensitive,
    _utc_now,
)

# ---------------------------------------------------------------------------
# Helpers (adapted from Arnas-Verify demo_issuance.py)
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


def build_payload(
    *,
    app_id: str = "self-demo",
    hw_fingerprint: str,
    customer_id: str,
    tier: str = "pro",
    features: Optional[Dict[str, Any]] = None,
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,  # None = lifetime (null in JSON)
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the UNSIGNED payload dict.

    ``expires_at=None`` serializes to JSON ``null`` — meaning the license
    never expires (the "lifetime offline" promise).  The verifier skips
    expiry checks when expires_at is null.

    安全修复 #8（Payload 脱敏）：``hw_fingerprint`` 和 ``customer_id``
    传入的是明文，但写进 payload 前统一做 SHA-256 哈希。这样公开的
    .lic 文件不暴露客户身份和机器指纹原文；客户端验签时对本地值做
    同样的哈希再比对（hash_sensitive 由 client.verify_license 提供）。
    """
    now = _utc_now()
    if issued_at is None:
        issued_at = now.strftime(TIMESTAMP_FORMAT)
    if nonce is None:
        nonce = (
            base64.urlsafe_b64encode(secrets.token_bytes(16))
            .decode("ascii")
            .rstrip("=")
        )

    payload: Dict[str, Any] = {
        "app_id": app_id,
        "hw_fingerprint": hash_sensitive(hw_fingerprint),
        "customer_id": hash_sensitive(customer_id),
        "tier": tier,
        "issued_at": issued_at,
        "expires_at": expires_at,  # None → null → lifetime
        "features": features if features is not None else {},
        "nonce": nonce,
    }
    return payload


def sign_payload(
    payload: Dict[str, Any],
    private_key: rsa.RSAPrivateKey,
) -> Dict[str, Any]:
    """Sign a payload dict and return the full envelope dict.

    Signature covers canonical_json(payload) only.  ``version``,
    ``algorithm``, and ``signature`` itself are NOT signed — the verifier
    checks them before invoking the crypto primitive.
    """
    raw = canonical_json(payload)

    sig_bytes = private_key.sign(
        raw,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return {
        "version": LICENSE_VERSION,
        "algorithm": LICENSE_ALGORITHM,
        "payload": payload,
        "signature": base64.b64encode(sig_bytes).decode("ascii"),
    }


# ---------------------------------------------------------------------------
# Top-level: read env vars, sign, write file
# ---------------------------------------------------------------------------

def _verify_hmac_auth(cp: Dict[str, Any], hw_fp: str, key: str,
                      customer_id: str, tier: str) -> None:
    """安全修复 #7（轻量防刷）：校验客户端携带的 HMAC。

    客户端在 client_payload.auth 里携带
        HMAC-SHA256(DEMO_HMAC_SECRET, "hw_fp|key|customer_id|tier")
    GHA 用仓库 Secret 中的同一把密钥重算并比对，失败直接抛异常退出，
    不消耗签名算力。这是轻量方案：密钥硬编码在客户端，只为挡住
    "拿到 PAT 就随便刷授权" 的路人，不声称能防定向逆向。
    """
    secret = os.environ.get("DEMO_HMAC_SECRET")
    if not secret:
        raise RuntimeError(
            "env DEMO_HMAC_SECRET not set — required in GHA mode (anti-abuse)"
        )
    provided = cp.get("auth", "")
    msg = f"{hw_fp}|{key}|{customer_id}|{tier}"
    expected = hmac.new(
        secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise RuntimeError("HMAC auth check failed — rejecting dispatch")


def sign_from_env() -> Path:
    """Entry point called inside GitHub Actions."""
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

    # GHA client_payload fields (see workflow): hw_fp, key, customer_id, tier, auth
    hw_fp = cp.get("hw_fp") or cp.get("hw_fingerprint")
    key = cp.get("key")
    customer_id = cp.get("customer_id")
    tier = cp.get("tier", "pro")

    if not all([hw_fp, key, customer_id]):
        raise RuntimeError(
            f"CLIENT_PAYLOAD missing required fields. Got: {list(cp.keys())}"
        )

    # 防刷校验在加载私钥之前：无授权请求直接死在门口
    _verify_hmac_auth(cp, hw_fp, key, customer_id, tier)

    private_key = _load_private_key_from_string(pem_text)

    payload = build_payload(
        hw_fingerprint=hw_fp,
        customer_id=customer_id,
        tier=tier,
        expires_at=None,  # lifetime — null in JSON
    )

    envelope = sign_payload(payload, private_key)

    # 安全修复 #2：产物写到 LICENSE_OUT_DIR（GHA 里 = $RUNNER_TEMP），
    # 不污染 git 工作区，避免 checkout -f 被同名文件阻塞。
    out_dir = Path(os.environ.get("LICENSE_OUT_DIR", "."))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{key}.lic"
    out_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    print(f"Signed license written to {out_path}")
    print(f"  app_id       = {payload['app_id']}")
    print(f"  hw_fingerprint(sha256) = {payload['hw_fingerprint'][:16]}...")
    print(f"  customer_id(sha256)    = {payload['customer_id'][:16]}...")
    print(f"  tier         = {payload['tier']}")
    print(f"  expires_at   = {payload['expires_at']}")
    print(f"  file size    = {out_path.stat().st_size} bytes")

    return out_path


# ---------------------------------------------------------------------------
# Local test CLI (NOT used by GHA — but useful for end-to-end local testing)
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    """CLI for local testing.

    Usage example:
        python issuer/sign_license.py \
            --private-key demo_keys/private.pem \
            --hw-fp "DESKTOP-TEST:MAC0011223344:CPUi7" \
            --key "a7f3b92e4c1d8a6f" \
            --customer "order-001" \
            --tier pro
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
        description="Sign a license locally (for testing).",
    )
    parser.add_argument("--private-key", required=True,
                        help="Path to RSA private key .pem")
    parser.add_argument("--hw-fp", required=True,
                        help="hw_fingerprint string to bind")
    parser.add_argument("--key", required=True,
                        help="filename key (sha256[:16] hex)")
    parser.add_argument("--customer", required=True,
                        help="customer_id / order number")
    parser.add_argument("--tier", default="pro", choices=["pro", "basic", "trial"],
                        help="license tier")
    parser.add_argument("--expires", default=None,
                        help="expiry timestamp YYYY-MM-DDTHH:MM:SSZ (omit = lifetime)")
    args = parser.parse_args(argv)

    try:
        private_key = _load_private_key_from_file(args.private_key)
    except Exception as exc:
        print(f"ERROR loading private key: {exc}", file=sys.stderr)
        return 1

    payload = build_payload(
        hw_fingerprint=args.hw_fp,
        customer_id=args.customer,
        tier=args.tier,
        expires_at=args.expires,
    )

    envelope = sign_payload(payload, private_key)

    out = Path(f"{args.key}.lic")
    out.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    print(f"Signed → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
