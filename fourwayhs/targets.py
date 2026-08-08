from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .discovery import AccessPoint


class TargetState(str, Enum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    CAPTURING = "CAPTURING"
    NO_HANDSHAKE = "NO_HANDSHAKE"
    HANDSHAKE_FOUND = "HANDSHAKE_FOUND"
    VALIDATED = "VALIDATED"
    COMPLETED = "COMPLETED"


@dataclass
class Target:
    ap: AccessPoint
    required_handshakes: int = 1
    state: TargetState = TargetState.DISCOVERED
    handshake_count: int = 0
    capture_file: str | None = None
    start_time: str | None = None
    end_time: str | None = None

    @property
    def done(self) -> bool:
        return self.handshake_count >= self.required_handshakes


def select_targets(
    aps: list[AccessPoint], indices: list[int], required_handshakes: int = 1
) -> list[Target]:
    targets = []
    for i in indices:
        ap = aps[i - 1]
        targets.append(Target(ap=ap, required_handshakes=required_handshakes, state=TargetState.QUEUED))
    return targets


def print_queue(targets: list[Target]) -> None:
    print("\nTARGET QUEUE\n")
    for i, t in enumerate(targets, 1):
        print(f"{i}. {t.ap.ssid}")
