"""Client-side license verification.

This is the verification-only module that ships with the application.
It loads a signed license JSON, verifies its RSA-PSS-SHA256 signature
against a trusted public key embedded in the package, checks app_id
binding, hw_fingerprint binding, and expiry.

Canonical JSON is defined HERE as the single source of truth — the
issuer side (issuer/sign_license.py) imports this exact function so
signer and verifier cannot drift apart.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------------------------------------------------------------------
# Constants — single source of truth
# ---------------------------------------------------------------------------

LICENSE_VERSION = 1
LICENSE_ALGORITHM = "RSA-PSS-SHA256"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# GHA cold-start can take 10-60s, occasionally queued runs longer.
# 10 minutes covers the realistic skew between issuer wall-clock
# and client wall-clock.
ISSUED_AT_LEEWAY = timedelta(minutes=10)

# Default locations the verifier looks for a saved license file.
DEFAULT_LICENSE_DIR = Path.home() / ".self-demo"
DEFAULT_LICENSE_FILE = DEFAULT_LICENSE_DIR / "license.lic"

# ---------------------------------------------------------------------------
# Canonical JSON — THE single canonicalization function.
# Signer and verifier MUST both call this exact implementation.
# ---------------------------------------------------------------------------

def canonical_json(payload: Dict[str, Any]) -> bytes:
    """Serialize a JSON object deterministically for signing/verifying.

    Rules (narrowed from RFC 8785 / JCS to what we actually use):
      - Compact separators: no space after ``:`` or ``,``
      - Keys sorted ascending (UTF-8 byte order, which matches Python str sort)
      - UTF-8 encoding
      - No NaN / Infinity (not valid JSON anyway)
    """
    return json.dumps(
        payload, separators=(",", ":"), sort_keys=True, allow_nan=False
    ).encode("utf-8")


def hash_sensitive(value: str) -> str:
    """SHA-256 hex digest of a privacy-sensitive claim.

    The issuer stores ONLY the digests of ``customer_id`` and
    ``hw_fingerprint`` inside the signed payload, so the public .lic file
    never exposes them in plaintext. Both sides hash locally and compare
    digests. Signer imports this from here — single source of truth.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LicenseDocument:
    """The signed claims inside a license payload."""

    app_id: str
    customer_id: str
    tier: str
    hw_fingerprint: str
    issued_at: str
    expires_at: Optional[str]  # None = never expires (lifetime)
    features: Dict[str, Any]
    nonce: str

    @staticmethod
    def from_dict(payload: Dict[str, Any]) -> "LicenseDocument":
        _REQUIRED_STR = ("app_id", "customer_id", "tier", "hw_fingerprint",
                         "issued_at", "nonce")
        _REQUIRED = _REQUIRED_STR + ("features",)
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
        missing = [n for n in _REQUIRED if n not in payload]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        for n in _REQUIRED_STR:
            if not isinstance(payload[n], str):
                raise ValueError(f"field '{n}' must be a string")
        if not isinstance(payload["features"], dict):
            raise ValueError("field 'features' must be an object")
        ea = payload.get("expires_at")
        if ea is not None and not isinstance(ea, str):
            raise ValueError("field 'expires_at' must be string or null")
        return LicenseDocument(
            app_id=payload["app_id"],
            customer_id=payload["customer_id"],
            tier=payload["tier"],
            hw_fingerprint=payload["hw_fingerprint"],
            issued_at=payload["issued_at"],
            expires_at=ea,
            features=payload["features"],
            nonce=payload["nonce"],
        )

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "app_id": self.app_id,
            "customer_id": self.customer_id,
            "tier": self.tier,
            "hw_fingerprint": self.hw_fingerprint,
            "issued_at": self.issued_at,
            "features": self.features,
            "nonce": self.nonce,
        }
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        else:
            d["expires_at"] = None
        return d


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: Optional[str] = None

    def __bool__(self) -> bool:
        return self.ok


_VALID = VerificationResult(True)


def _fail(reason: str) -> VerificationResult:
    return VerificationResult(False, reason)


# ---------------------------------------------------------------------------
# Low-level primitives
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    # Reject non-canonical forms e.g. single-digit months.
    if parsed.strftime(TIMESTAMP_FORMAT) != value:
        raise ValueError(f"timestamp not in exact format: {value!r}")
    return parsed


def _load_public_key(path: str | Path) -> rsa.RSAPublicKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Public key must be RSA")
    return key


# ---------------------------------------------------------------------------
# Envelope + signature check (runs BEFORE any payload interpretation)
# ---------------------------------------------------------------------------

def _check_envelope_and_signature(
    doc: Any, public_key_path: str | Path
) -> VerificationResult:
    if not isinstance(doc, dict):
        return _fail("malformed document: not a JSON object")

    payload = doc.get("payload")
    signature = doc.get("signature")
    if not isinstance(payload, dict):
        return _fail("malformed document: 'payload' must be an object")
    if not isinstance(signature, str):
        return _fail("malformed document: 'signature' must be a string")

    version = doc.get("version")
    # Exact int check: bool/float equal-comparing to 1 must not pass.
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != LICENSE_VERSION
    ):
        return _fail(f"unsupported version: {version!r}")

    algorithm = doc.get("algorithm")
    if algorithm != LICENSE_ALGORITHM:
        return _fail(f"unsupported algorithm: {algorithm!r}")

    public_key = _load_public_key(public_key_path)

    try:
        sig_bytes = base64.b64decode(signature.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        return _fail("signature is not valid base64")

    try:
        raw = canonical_json(payload)
    except (TypeError, ValueError, RecursionError):
        return _fail("payload is not canonically serializable JSON")

    try:
        public_key.verify(
            sig_bytes,
            raw,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return _fail("signature verification failed")

    return _VALID


# ---------------------------------------------------------------------------
# Full public API
# ---------------------------------------------------------------------------

def check_license_document(
    doc: Dict[str, Any],
    *,
    public_key_path: str | Path,
    app_id: str,
    hw_fingerprint: Optional[str] = None,
) -> VerificationResult:
    """Full verification pipeline.

    Order is load-bearing: envelope → version → algorithm → signature
    → payload shape → app_id match → hw_fingerprint match → issued_at
    (with leeway) → expires_at. Signature check MUST run first so a
    forged document never reaches business-logic code.
    """
    result = _check_envelope_and_signature(doc, public_key_path)
    if not result:
        return result

    try:
        document = LicenseDocument.from_dict(doc["payload"])
    except ValueError as exc:
        return _fail(f"invalid payload: {exc}")

    if document.app_id != app_id:
        return _fail(
            f"app_id mismatch: expected '{app_id}', got '{document.app_id}'"
        )

    if hw_fingerprint is not None and document.hw_fingerprint != hash_sensitive(hw_fingerprint):
        return _fail(
            "hw_fingerprint mismatch: license is bound to a different machine"
        )

    try:
        issued_dt = _parse_timestamp(document.issued_at)
    except ValueError:
        return _fail(
            "invalid issued_at format: expected YYYY-MM-DDTHH:MM:SSZ (UTC)"
        )

    # expires_at can be None → lifetime license, skip expiry check.
    expires_dt: Optional[datetime] = None
    if document.expires_at is not None:
        try:
            expires_dt = _parse_timestamp(document.expires_at)
        except ValueError:
            return _fail(
                "invalid expires_at format: expected YYYY-MM-DDTHH:MM:SSZ (UTC) or null"
            )

    now = _utc_now()
    if issued_dt > now + ISSUED_AT_LEEWAY:
        return _fail("issued_at is in the future (beyond clock-skew leeway)")

    if expires_dt is not None and now > expires_dt:
        return _fail(f"license expired at {document.expires_at}")

    return _VALID


def check_license_file(
    path: str | Path,
    public_key_path: str | Path,
    *,
    app_id: str,
    hw_fingerprint: Optional[str] = None,
) -> VerificationResult:
    try:
        text = Path(path).read_bytes().decode("utf-8-sig")
    except OSError as exc:
        return _fail(f"cannot read license file: {exc}")
    except UnicodeDecodeError:
        return _fail("license file is not valid UTF-8")

    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return _fail("license file is not valid JSON")

    return check_license_document(
        doc,
        public_key_path=public_key_path,
        app_id=app_id,
        hw_fingerprint=hw_fingerprint,
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_license",
        description="Verify a signed offline license file.",
    )
    parser.add_argument(
        "--license",
        default=str(DEFAULT_LICENSE_FILE),
        help=f"Path to .lic file (default: {DEFAULT_LICENSE_FILE})",
    )
    parser.add_argument(
        "--public-key",
        required=True,
        help="Path to trusted RSA public key (.pem)",
    )
    parser.add_argument(
        "--app-id",
        default="self-demo",
        help="Expected app_id bound in the license (default: self-demo)",
    )
    parser.add_argument(
        "--hw-fp",
        default=None,
        help="Current machine's hw_fingerprint to verify binding (optional)",
    )
    args = parser.parse_args(argv)

    try:
        result = check_license_file(
            args.license,
            args.public_key,
            app_id=args.app_id,
            hw_fingerprint=args.hw_fp,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: public key or file load error: {exc}", file=sys.stderr)
        return 1

    if result:
        print(f"OK   : valid license for app '{args.app_id}'")
        return 0

    print(f"FAIL : {result.reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
