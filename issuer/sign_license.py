"""License signing script (V2) — runs inside GitHub Actions (or locally).

V2 format (matches CLUMSY C++ client src/license/license/license_file.cpp):
  LICB binary header: MAGIC(4=b"LICB") | VERSION(2=2) | PAYLOAD_LEN(4) | SIG_LEN(2) | SIG(M) | PAYLOAD(N)
  Signature: RSA-2048 PKCS#1 v1.5 + SHA-256
  Serialization: canonical_json_clumsy (ensure_ascii=False, compact, sorted keys)

CRITICAL: canonical_json_clumsy is imported from client.verify_license.  This is
THE single source of truth — the issuer and verifier MUST use identical
serialization, otherwise every signature will fail to verify.  If you ever
see a signature mismatch, first check that both sides are importing the SAME
canonical_json_clumsy function (same file, same Python version).

Flow inside GHA:
  1. Workflow sets env.RSA_PRIVATE_KEY from Secrets and env.CLIENT_PAYLOAD
     from github.event.client_payload.
  2. This script parses those, builds the CLUMSY payload dict, signs it,
     writes <key>.lic (binary) to LICENSE_OUT_DIR.
  3. The workflow then commits and pushes the .lic to the ``license-result``
     branch with GITHUB_TOKEN.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Import canonical_json_clumsy from the CLIENT module — single source of truth.
# This means GHA must checkout the full repo (both client/ and issuer/).
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from client.verify_license import (  # noqa: E402 — import after sys.path setup
    canonical_json_clumsy,
)

# ---------------------------------------------------------------------------
# LICB V2 binary format constants (must match C++ license_file.cpp)
# ---------------------------------------------------------------------------

LICB_MAGIC = b"LICB"
LICB_VERSION = 2


# ---------------------------------------------------------------------------
# Key loading helpers
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
# Payload builder (CLUMSY V2 fields)
# ---------------------------------------------------------------------------

def build_clumsy_payload(
    *,
    machine_id: str,
    card_code: str,
    baseline: Dict[str, str],
    issued_at: Optional[int] = None,
    expires_at: int = 0,
    permanent: bool = True,
    threshold: int = 50,
) -> Dict[str, Any]:
    """Build the UNSIGNED CLUMSY V2 payload dict.

    Field contract (must match C++ license_file.cpp parse logic):
      v     : schema version (1)
      mid   : device fingerprint (64-hex, from fingerprint::get_device_fingerprint)
      card  : card code string
      iat   : issued-at Unix seconds (int)
      eat   : expires-at Unix seconds (int, 0 = lifetime)
      perm  : permanent flag (bool); when true, eat should be 0
      thr   : hardware score threshold (int, default 50)
      bl    : baseline snapshot dict with keys disk/board/mac/cpu/uuid

    The baseline ``bl`` stores raw hardware values.  The C++ client computes
    a weighted score against the current snapshot at verify time; mismatches
    below the threshold are tolerated (e.g. one replaced disk).
    """
    if issued_at is None:
        issued_at = int(time.time())

    return {
        "v": 1,
        "mid": machine_id,
        "card": card_code,
        "iat": issued_at,
        "eat": expires_at,
        "perm": permanent,
        "thr": threshold,
        "bl": {
            "disk":  baseline.get("disk",  "NAN"),
            "board": baseline.get("board", "NAN"),
            "mac":   baseline.get("mac",   "NAN"),
            "cpu":   baseline.get("cpu",   "NAN"),
            "uuid":  baseline.get("uuid",  "NAN"),
        },
    }


# ---------------------------------------------------------------------------
# Signing (RSA-2048 PKCS#1 v1.5 + SHA-256)
# ---------------------------------------------------------------------------

def sign_clumsy_payload(
    payload: Dict[str, Any],
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    """Sign a CLUMSY payload and return the raw RSA signature bytes.

    Signature covers canonical_json_clumsy(payload) only.
    Uses PKCS#1 v1.5 padding to match C++ signature_verifier.cpp
    (BCRYPT_PAD_PKCS1).
    """
    raw = canonical_json_clumsy(payload)
    sig_bytes = private_key.sign(
        raw,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return sig_bytes


def pack_licb(payload_bytes: bytes, sig_bytes: bytes) -> bytes:
    """Assemble the LICB V2 binary file.

    Layout: MAGIC(4) | VERSION(2 LE) | PAYLOAD_LEN(4 LE) | SIG_LEN(2 LE) | SIG | PAYLOAD
    """
    header = (
        LICB_MAGIC
        + struct.pack("<H", LICB_VERSION)
        + struct.pack("<I", len(payload_bytes))
        + struct.pack("<H", len(sig_bytes))
        + sig_bytes
    )
    return header + payload_bytes


# ---------------------------------------------------------------------------
# HMAC anti-abuse check (lightweight)
# ---------------------------------------------------------------------------

def _verify_hmac_auth(cp: Dict[str, Any], mid: str, key: str, card: str) -> None:
    """Lightweight anti-abuse: verify client-supplied HMAC.

    Client carries in client_payload.auth:
        HMAC-SHA256(DEMO_HMAC_SECRET, "mid|key|card")
    GHA recomputes with the same secret from repo Secrets and compares.
    Failure aborts before any crypto work.  This is a lightweight gate:
    the secret is hard-coded in the client, it only stops casual abuse
    (anyone with a PAT spamming licenses), not targeted reversing.
    """
    secret = os.environ.get("DEMO_HMAC_SECRET")
    if not secret:
        raise RuntimeError(
            "env DEMO_HMAC_SECRET not set — required in GHA mode (anti-abuse)"
        )
    provided = cp.get("auth", "")
    msg = f"{mid}|{key}|{card}"
    expected = hmac.new(
        secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise RuntimeError("HMAC auth check failed — rejecting dispatch")


# ---------------------------------------------------------------------------
# Top-level: read env vars, sign, write binary file
# ---------------------------------------------------------------------------

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

    # GHA client_payload fields (see workflow): mid, key, card, bl, iat, eat, perm, thr, auth
    mid = cp.get("mid")
    key = cp.get("key")
    card = cp.get("card")
    bl = cp.get("bl", {}) or {}

    if not all([mid, key, card]):
        raise RuntimeError(
            f"CLIENT_PAYLOAD missing required fields (mid/key/card). Got: {list(cp.keys())}"
        )

    # Anti-abuse check before loading the private key
    _verify_hmac_auth(cp, mid, key, card)

    private_key = _load_private_key_from_string(pem_text)

    payload = build_clumsy_payload(
        machine_id=mid,
        card_code=card,
        baseline=bl,
        issued_at=cp.get("iat"),
        expires_at=int(cp.get("eat", 0)),
        permanent=bool(cp.get("perm", True)),
        threshold=int(cp.get("thr", 50)),
    )

    raw = canonical_json_clumsy(payload)
    sig = sign_clumsy_payload(payload, private_key)
    licb_bytes = pack_licb(raw, sig)

    # Write binary to LICENSE_OUT_DIR (GHA = $RUNNER_TEMP), keep git workspace clean
    out_dir = Path(os.environ.get("LICENSE_OUT_DIR", "."))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{key}.lic"
    out_path.write_bytes(licb_bytes)

    print(f"Signed V2 license written to {out_path}")
    print(f"  mid          = {mid[:16]}...")
    print(f"  card         = {card}")
    print(f"  iat          = {payload['iat']}")
    print(f"  eat          = {payload['eat']}")
    print(f"  perm         = {payload['perm']}")
    print(f"  thr          = {payload['thr']}")
    print(f"  payload len  = {len(raw)} bytes")
    print(f"  sig len      = {len(sig)} bytes")
    print(f"  file size    = {out_path.stat().st_size} bytes")

    return out_path


# ---------------------------------------------------------------------------
# Local test CLI (NOT used by GHA — but useful for end-to-end local testing)
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    """CLI for local testing.

    Usage example:
        python issuer/sign_license.py \\
            --private-key test_private.pem \\
            --mid "219b54ce5f23d42d2e805e64347e807efd9c30fc09d319c80a2a2747eb828e20" \\
            --key "a7f3b92e4c1d8a6f" \\
            --card "CARD-001" \\
            --disk "0000_0000_0000_0002." --board "07D4211_N81E641146" \\
            --mac "D843AE15B143" --cpu "GenuineIntel_..." --uuid "4AA3EC8B-..."
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
        description="Sign a CLUMSY V2 license locally (for testing).",
    )
    parser.add_argument("--private-key", required=True,
                        help="Path to RSA-2048 private key .pem")
    parser.add_argument("--mid", required=True,
                        help="machine id / device fingerprint (64-hex)")
    parser.add_argument("--key", required=True,
                        help="filename key (sha256(mid)[:16] hex)")
    parser.add_argument("--card", required=True,
                        help="card code string")
    parser.add_argument("--disk", default="NAN", help="baseline disk SN")
    parser.add_argument("--board", default="NAN", help="baseline board SN")
    parser.add_argument("--mac", default="NAN", help="baseline MAC hex")
    parser.add_argument("--cpu", default="NAN", help="baseline CPU id")
    parser.add_argument("--uuid", default="NAN", help="baseline system UUID")
    parser.add_argument("--eat", type=int, default=0,
                        help="expires-at Unix seconds (0 = lifetime)")
    parser.add_argument("--perm", action="store_true", default=True,
                        help="permanent license (default)")
    parser.add_argument("--thr", type=int, default=50,
                        help="hardware score threshold")
    parser.add_argument("--out", default=None,
                        help="output path (default: <key>.lic)")
    args = parser.parse_args(argv)

    try:
        private_key = _load_private_key_from_file(args.private_key)
    except Exception as exc:
        print(f"ERROR loading private key: {exc}", file=sys.stderr)
        return 1

    baseline = {
        "disk": args.disk, "board": args.board, "mac": args.mac,
        "cpu": args.cpu, "uuid": args.uuid,
    }
    payload = build_clumsy_payload(
        machine_id=args.mid,
        card_code=args.card,
        baseline=baseline,
        expires_at=args.eat,
        permanent=args.perm,
        threshold=args.thr,
    )

    raw = canonical_json_clumsy(payload)
    sig = sign_clumsy_payload(payload, private_key)
    licb_bytes = pack_licb(raw, sig)

    out = Path(args.out) if args.out else Path(f"{args.key}.lic")
    out.write_bytes(licb_bytes)
    print(f"Signed V2 license → {out} ({len(licb_bytes)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
