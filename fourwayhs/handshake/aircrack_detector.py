from __future__ import annotations

import subprocess
from pathlib import Path

from .aircrack_parser import parse_handshake_count
from .detector import HandshakeDetector, HandshakeResult


class AircrackDetector(HandshakeDetector):
    def detect(self, cap_path: Path, bssid: str) -> HandshakeResult:
        if not cap_path.exists() or cap_path.stat().st_size == 0:
            return HandshakeResult(bssid=bssid, detected=False, count=0)
        result = subprocess.run(
            ["aircrack-ng", "-a2", "-b", bssid, str(cap_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        count = parse_handshake_count(result.stdout)
        return HandshakeResult(bssid=bssid, detected=count > 0, count=count)
