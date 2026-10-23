"""Client-side activation flow.

Two-phase polling strategy:

  Phase 1  — Trigger the workflow via repository_dispatch, then poll
             GitHub Actions API until the run reaches ``success``.
             5s interval, 180s timeout.  Catches GHA cold-start + queue.

  Phase 2  — Once the run is confirmed successful, poll the raw.githubusercontent.com
             URL for the .lic file.  5s interval, 60s timeout.  Catches
             CDN propagation delay.  Every request appends ``?t=<epoch>``
             to bust any remaining CDN cache.

  After fetch: local verification with the bundled public key.  Only on
  success do we persist the file to ``~/.self-demo/license.lic``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Run: pip install requests",
          file=sys.stderr)
    raise SystemExit(1)

from .hardware_fingerprint import get_fingerprint
from .verify_license import (
    DEFAULT_LICENSE_DIR,
    DEFAULT_LICENSE_FILE,
    check_license_document,
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
# 安全修复 #7（轻量防刷）：客户端硬编码的 HMAC 密钥。
# 必须与仓库 Secret DEMO_HMAC_SECRET 完全一致，否则 GHA 拒绝签名。
# 注意：这只是挡住"拿到 PAT 就随便刷授权"的路人，不防定向逆向。
# 部署时请改成你自己的随机值，并同步配置到仓库 Secrets。
# ---------------------------------------------------------------------------
DEMO_HMAC_SECRET = "k9sdfj239asdf"


def _compute_auth(hw_fp: str, key: str, customer: str, tier: str) -> str:
    msg = f"{hw_fp}|{key}|{customer}|{tier}"
    return hmac.new(
        DEMO_HMAC_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Config loading (PAT + repo info — user supplies locally, NEVER hard-coded)
# ---------------------------------------------------------------------------

def load_config(path: Optional[Path] = None) -> Dict[str, str]:
    p = path or DEFAULT_CONFIG_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"Config not found at {p}. "
            "Create it with keys: github_pat, repo_owner, repo_name, "
            "public_key_path, customer_id, tier"
        )
    data = json.loads(p.read_text(encoding="utf-8"))
    required = ("github_pat", "repo_owner", "repo_name",
                "public_key_path", "customer_id", "tier")
    missing = [k for k in required if not data.get(k)]
    if missing:
        raise ValueError(f"config.json missing keys: {', '.join(missing)}")
    return data


# ---------------------------------------------------------------------------
# Filename key derivation (hw_fingerprint → sha256[:16] hex)
# ---------------------------------------------------------------------------

def _hw_fp_to_key(hw_fp: str) -> str:
    """Stable 16-hex key from the hw_fingerprint."""
    return hashlib.sha256(hw_fp.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Phase 1 — repository_dispatch + GHA run status polling
# ---------------------------------------------------------------------------

def _trigger_dispatch(owner: str, repo: str, pat: str,
                      hw_fp: str, key: str, customer: str, tier: str) -> Optional[int]:
    """POST /repos/{owner}/{repo}/dispatches. Return run_id on success."""
    # repository_dispatch 端点，不是 workflow_dispatch 端点。
    # URL 模式: /repos/{owner}/{repo}/dispatches
    url = f"https://api.github.com/repos/{owner}/{repo}/dispatches"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = {
        "event_type": "issue-license",
        "client_payload": {
            "hw_fp": hw_fp,
            "key": key,
            "customer_id": customer,
            "tier": tier,
            "auth": _compute_auth(hw_fp, key, customer, tier),
        },
    }

    resp = requests.post(url, headers=headers, json=body, timeout=15)
    if resp.status_code != 204:
        print(f"  dispatch POST failed: HTTP {resp.status_code}", file=sys.stderr)
        print(f"  {resp.text[:500]}", file=sys.stderr)
        return None

    print("  dispatch accepted by GitHub. Waiting for run to be created...")

    # 安全修复 #5：workflow 里设置了
    #   run-name: issue-license ${{ github.event.client_payload.key }}
    # GitHub 会把它作为 run 的 display_title。这里按 display_title 精确
    # 匹配 key，不再靠时间窗口猜，避免多个用户同时激活时串号。
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
    """Poll run until terminal conclusion or timeout. Return conclusion or None."""
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
        status = run.get("status")       # queued, in_progress, completed
        conclusion = run.get("conclusion")  # success, failure, cancelled, ...

        print(f"    run status={status}, conclusion={conclusion}")

        if status == "completed":
            return conclusion

        time.sleep(POLL_INTERVAL_PHASE1)

    print(f"  phase 1 timeout after {timeout}s — run still not completed.",
          file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Phase 2 — raw.githubusercontent.com polling with cache-buster
# ---------------------------------------------------------------------------

def _fetch_license_raw(owner: str, repo: str, key: str,
                       timeout: int = PHASE2_TIMEOUT) -> Optional[str]:
    """Poll raw URL until the .lic file appears or timeout. Return JSON text."""
    base = f"https://raw.githubusercontent.com/{owner}/{repo}/license-result/{key}.lic"
    deadline = time.monotonic() + timeout
    print(f"  phase 2: waiting for .lic file at raw URL "
          f"(timeout {timeout}s)...")

    while time.monotonic() < deadline:
        # Critical: append timestamp to bust GitHub CDN cache.
        url = f"{base}?t={int(time.time())}"
        try:
            resp = requests.get(url, timeout=15)
        except requests.RequestException as exc:
            print(f"    network error: {exc}, retrying...")
            time.sleep(POLL_INTERVAL_PHASE2)
            continue

        if resp.status_code == 200:
            print(f"    .lic file fetched (HTTP 200, {len(resp.text)} bytes)")
            return resp.text

        if resp.status_code == 404:
            print(f"    HTTP 404 — file not yet propagated, retrying...")
        else:
            print(f"    HTTP {resp.status_code}, retrying...")

        time.sleep(POLL_INTERVAL_PHASE2)

    print(f"  phase 2 timeout after {timeout}s — .lic file never appeared.",
          file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Persist + verify
# ---------------------------------------------------------------------------

def _save_license(lic_text: str) -> Path:
    DEFAULT_LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_LICENSE_FILE.write_text(lic_text, encoding="utf-8")
    return DEFAULT_LICENSE_FILE


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def activate(config_path: Optional[Path] = None) -> int:
    """Run the full activation flow. Return 0 on success, 1 on failure."""
    try:
        cfg = load_config(config_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 1

    hw_fp = get_fingerprint()
    key = _hw_fp_to_key(hw_fp)

    print(f"hw_fingerprint: {hw_fp}")
    print(f"filename key   : {key}")
    print(f"customer       : {cfg['customer_id']}")
    print(f"tier           : {cfg['tier']}")
    print()

    # --- Phase 1 ------------------------------------------------------------
    print("[phase 1] triggering GitHub Actions workflow...")
    run_id = _trigger_dispatch(
        cfg["repo_owner"], cfg["repo_name"], cfg["github_pat"],
        hw_fp, key, cfg["customer_id"], cfg["tier"],
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

    # --- Phase 2 ------------------------------------------------------------
    print("[phase 2] fetching .lic file from raw.githubusercontent.com...")
    lic_text = _fetch_license_raw(cfg["repo_owner"], cfg["repo_name"], key)
    if lic_text is None:
        return 1

    # --- Verify + persist ---------------------------------------------------
    print("[phase 3] verifying signature + persisting license...")
    try:
        doc = json.loads(lic_text)
    except json.JSONDecodeError:
        print("  fetched file is not valid JSON", file=sys.stderr)
        return 1

    result = check_license_document(
        doc,
        public_key_path=cfg["public_key_path"],
        app_id="self-demo",
        hw_fingerprint=hw_fp,
    )

    if not result:
        print(f"  verification FAILED: {result.reason}", file=sys.stderr)
        return 1

    saved = _save_license(lic_text)
    print(f"  verified ✓ — saved to {saved}")
    print()
    print("Activation complete.  This machine is now licensed for lifetime offline use.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trigger_and_fetch",
        description="Activate: trigger GHA signing → fetch .lic → verify → persist.",
    )
    parser.add_argument(
        "--config", default=None,
        help=f"Path to config.json (default: {DEFAULT_CONFIG_PATH})",
    )
    args = parser.parse_args(argv)
    return activate(Path(args.config) if args.config else None)


if __name__ == "__main__":
    raise SystemExit(main())
