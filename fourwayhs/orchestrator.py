from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from . import capture, discovery, monitor, preflight, report
from .capture import AbortRequested
from .targets import Target, TargetState, select_targets


class PreflightFailed(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(
    scan_duration: int = 15,
    capture_timeout: int = 60,
    required_handshakes: int = 1,
    work_dir: Path = Path("."),
    deauth: bool = False,
) -> None:
    tmp_dir = work_dir / "tmp"
    captures_dir = work_dir / "captures"

    report.print_banner()

    pf = preflight.run_preflight()
    preflight.print_preflight(pf)
    if not pf.ok:
        raise PreflightFailed("Preflight checks failed.")

    mon_if = monitor.enable_monitor_mode(pf.interface)
    print(f"\n{pf.interface} -> monitor mode -> {mon_if}\n")

    try:
        aps = discovery.scan(mon_if, scan_duration, tmp_dir)
        discovery.print_networks(aps)
        if not aps:
            print("\nNo networks found. Exiting.")
            return

        indices = prompt_target_selection(aps)
        if not indices:
            print("\nNo targets selected. Exiting.")
            return

        targets = select_targets(aps, indices, required_handshakes)

        channels = {}
        for t in targets:
            channels.setdefault(t.ap.channel, []).append(t)

        for channel, group in channels.items():
            try:
                run_channel(mon_if, channel, group, tmp_dir, captures_dir, capture_timeout, len(aps), targets, deauth)
            except AbortRequested:
                print("\n\n[QUIT] Stopping toolkit safely, restoring system state...")
                for t in group:
                    t.end_time = now()
                break

        report.print_final_report(len(aps), targets)
        report.write_report_json(work_dir / "report.json", targets)

    finally:
        cleanup(tmp_dir)
        monitor.disable_monitor_mode(mon_if, pf.interface)
        monitor.restore_services()


def prompt_target_selection(aps: list) -> list[int]:
    discovery_targets_view(aps)
    raw = input("\nSelect targets (e.g. 1,3,5 or 1-10 or 1-5,8,10-12): ").strip()
    if not raw:
        return []
    indices = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.strip().isdigit() and hi.strip().isdigit():
                lo, hi = int(lo), int(hi)
                for idx in range(lo, hi + 1):
                    if 1 <= idx <= len(aps):
                        indices.append(idx)
        elif part.isdigit():
            idx = int(part)
            if 1 <= idx <= len(aps):
                indices.append(idx)
    seen = set()
    return [i for i in indices if not (i in seen or seen.add(i))]


def discovery_targets_view(aps: list) -> None:
    print("\nDISCOVERED NETWORKS\n")
    for i, ap in enumerate(aps, 1):
        print(
            f"[{i}] {ap.ssid}\n    BSSID: {ap.bssid}\n    Channel: {ap.channel}\n"
            f"    Security: {ap.security}\n    Status: {ap.handshake_status}\n"
        )


def run_channel(
    mon_if: str,
    channel: int,
    group: list[Target],
    tmp_dir: Path,
    captures_dir: Path,
    capture_timeout: int,
    networks_found: int,
    targets: list[Target],
    deauth: bool = False,
) -> None:
    for t in group:
        t.start_time = now()
        t.state = TargetState.CAPTURING

    report.render_dashboard(mon_if, networks_found, targets)

    def on_tick(ch, elapsed, timeout, found, total):
        print(report.render_progress_line((ch, elapsed, timeout, found, total)))

    cap_path = capture.capture_channel(
        mon_if, channel, group, tmp_dir, capture_timeout, on_tick=on_tick, deauth=deauth
    )

    for t in group:
        if t.state == TargetState.HANDSHAKE_FOUND and capture.validate(cap_path, t):
            dest = capture.save_result_copy(cap_path, captures_dir, t)
            t.capture_file = str(dest)
            t.state = TargetState.COMPLETED if t.done else TargetState.VALIDATED
        else:
            t.state = TargetState.NO_HANDSHAKE
        t.end_time = now()

    capture.discard(cap_path)
    report.render_dashboard(mon_if, networks_found, targets)


def cleanup(tmp_dir: Path) -> None:
    if not tmp_dir.exists():
        return
    for f in tmp_dir.glob("*"):
        try:
            f.unlink()
        except OSError:
            pass
