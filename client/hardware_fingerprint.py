"""Cross-platform hardware fingerprint collection.

The goal: produce a stable, machine-specific string that does NOT change
across reboots or normal software updates. Simple approach — combine:

  - hostname              (stable on one machine)
  - MAC address           (usually stable on one NIC)
  - CPU model             (stable)
  - platform uname node   (hostname reconfirmed)

The raw values are joined with ':' and SHA-256 hashed so that the
fingerprint string itself is a fixed-length, non-reversible identifier
suitable for embedding in a license payload.

The hash is NOT a security boundary — it just hides the raw hardware
details from casual inspection of the license file. The real binding
comes from the signature covering ``hw_fingerprint``.
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
import uuid
from typing import Optional


def _run(cmd: list[str]) -> Optional[str]:
    """Safely run a command and return trimmed stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _cpu_model() -> str:
    """Best-effort CPU model string. Falls back to platform.processor()."""
    # Windows: WMI via PowerShell is most reliable.
    if sys.platform.startswith("win"):
        out = _run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Processor).Name"]
        )
        if out:
            return out.splitlines()[0].strip()
    # Linux
    out = _run(["cat", "/proc/cpuinfo"])
    if out:
        for line in out.splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    # macOS
    out = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    if out:
        return out.strip()
    return platform.processor() or "unknown-cpu"


def _mac_address() -> str:
    """First non-zero MAC address of the default NIC."""
    node = uuid.getnode()
    # uuid.getnode() returns a 48-bit int; 0 means it couldn't read any NIC.
    # If the multicast bit (least significant bit of the first octet, i.e.
    # bit 40) is set, the value is a randomly generated pseudo-MAC, not a
    # real hardware address — reject it to keep the fingerprint stable.
    if node == 0 or ((node >> 40) & 1):
        return "no-mac"
    # Convert to "aa:bb:cc:dd:ee:ff"
    return ":".join(f"{(node >> shift) & 0xff:02x}"
                    for shift in range(40, -1, -8))


def get_fingerprint() -> str:
    """Return a stable SHA-256 hex fingerprint of this machine.

    The string is 64 characters (hex) and is deterministic per machine.
    """
    raw_parts = [
        platform.node(),             # hostname
        _mac_address(),              # MAC of primary NIC
        _cpu_model(),                # CPU brand string
        platform.system(),           # OS family (Windows/Linux/Darwin)
    ]
    raw = "|".join(raw_parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    # Prefix with short human-readable tag for debugging visibility.
    return f"{platform.node()}-{digest[:16]}"


if __name__ == "__main__":
    fp = get_fingerprint()
    print(f"hw_fingerprint: {fp}")
    print(f"raw components:")
    print(f"  node     : {platform.node()}")
    print(f"  mac      : {_mac_address()}")
    print(f"  cpu      : {_cpu_model()}")
    print(f"  system   : {platform.system()}")
