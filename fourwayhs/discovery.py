from __future__ import annotations

import csv
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int
    frequency: int
    security: str
    signal: int
    first_seen: str
    last_seen: str
    handshake_status: str = "NOT CAPTURED"


def scan(monitor_interface: str, duration: int, work_dir: Path) -> list[AccessPoint]:
    work_dir.mkdir(parents=True, exist_ok=True)
    prefix = work_dir / "scan"

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--output-format",
            "csv",
            "-w",
            str(prefix),
            monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(duration)
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5)

    csv_path = prefix.with_name(prefix.name + "-01.csv")
    if not csv_path.exists():
        print(f"\n[DEBUG] No CSV produced at {csv_path}")
        siblings = sorted(p.name for p in work_dir.glob("scan*"))
        print(f"[DEBUG] Files in {work_dir}: {siblings}")
        return []

    text = csv_path.read_text(encoding="utf-8-sig", errors="replace")
    return _parse_csv(text)


def _parse_csv(text: str) -> list[AccessPoint]:
    ap_block = text.strip("\r\n").split("\r\n\r\n")[0].split("\n\n")[0]
    reader = csv.reader(ap_block.splitlines())
    rows = [r for r in reader if r]
    if not rows:
        return []

    header = [h.strip() for h in rows[0]]
    aps = []
    for row in rows[1:]:
        if len(row) < len(header):
            continue
        rec = dict(zip(header, [c.strip() for c in row]))
        bssid = rec.get("BSSID", "")
        if not bssid:
            continue
        ssid = rec.get("ESSID", "") or "<hidden>"
        try:
            channel = int(rec.get("channel", 0))
        except ValueError:
            channel = 0
        try:
            signal = int(rec.get("Power", -100))
        except ValueError:
            signal = -100

        aps.append(
            AccessPoint(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                frequency=2407 + channel * 5,
                security=rec.get("Privacy", "").strip() or "OPEN",
                signal=signal,
                first_seen=rec.get("First time seen", ""),
                last_seen=rec.get("Last time seen", ""),
            )
        )
    return aps


def print_networks(aps: list[AccessPoint]) -> None:
    print(f"\nNETWORKS FOUND: {len(aps)}\n")
    print(f"{'#':<3} {'SSID':<20} {'BSSID':<19} {'CH':<4} {'SECURITY':<10} SIGNAL")
    for i, ap in enumerate(aps, 1):
        print(
            f"{i:<3} {ap.ssid:<20} {ap.bssid:<19} {ap.channel:<4} "
            f"{ap.security:<10} {ap.signal}dBm"
        )
