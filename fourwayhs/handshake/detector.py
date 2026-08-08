from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class HandshakeResult:
    bssid: str
    detected: bool
    count: int


class HandshakeDetector:
    def detect(self, cap_path: Path, bssid: str) -> HandshakeResult:
        raise NotImplementedError
