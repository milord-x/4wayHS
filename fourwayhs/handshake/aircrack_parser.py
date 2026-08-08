from __future__ import annotations

import re

_HANDSHAKE_COUNT_RE = re.compile(r"WPA \((\d+) handshake")


def parse_handshake_count(aircrack_stdout: str) -> int:
    """Extract the handshake count from `aircrack-ng -a2 -b <bssid> <cap>` stdout.

    Isolated from AircrackDetector so a future aircrack-ng output format
    change only requires updating this function and its fixtures, not the
    detector or its subprocess-calling code.
    """
    match = _HANDSHAKE_COUNT_RE.search(aircrack_stdout)
    return int(match.group(1)) if match else 0
