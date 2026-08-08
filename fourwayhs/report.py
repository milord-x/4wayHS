from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .targets import Target, TargetState

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "logo.html"
_SPAN_RE = re.compile(
    r'<span style="color:#([0-9A-Fa-f]{6})(?:;background-color:#([0-9A-Fa-f]{6}))?">(.*?)</span>'
)


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _html_logo_to_ansi(html: str) -> str:
    pre_start = html.find(">") + 1
    pre_end = html.rfind("</pre>")
    body = html[pre_start:pre_end]

    out = []
    for line in body.split("\n"):
        for fg_hex, bg_hex, text in _SPAN_RE.findall(line):
            fr, fg_, fb = _hex_to_rgb(fg_hex)
            codes = [f"38;2;{fr};{fg_};{fb}"]
            if bg_hex:
                br, bgc, bb = _hex_to_rgb(bg_hex)
                codes.append(f"48;2;{br};{bgc};{bb}")
            out.append(f"\x1b[{';'.join(codes)}m{text}\x1b[0m")
        out.append("\n")
    return "".join(out).rstrip("\n")

STATE_MARK = {
    "COMPLETED": "[green]✓[/]",
    "VALIDATED": "[green]✓[/]",
    "HANDSHAKE_FOUND": "[green]✓[/]",
    "CAPTURING": "[yellow]◉[/]",
    "NO_HANDSHAKE": "[red]✗[/]",
    "QUEUED": "[dim]○[/]",
    "DISCOVERED": "[dim]○[/]",
}

_USE_COLOR = sys.stdout.isatty()
_console = Console()
_live: Live | None = None


def print_banner() -> None:
    try:
        html = _LOGO_PATH.read_text(encoding="utf-8")
    except OSError:
        return

    logo = _html_logo_to_ansi(html)
    if not _USE_COLOR:
        logo = _ANSI_RE.sub("", logo)

    sys.stdout.write("\n" + logo + "\n\n")
    sys.stdout.flush()


def _build_dashboard(
    monitor_interface: str,
    networks_found: int,
    targets: list[Target],
    channel_progress: tuple | None = None,
) -> Panel:
    completed = sum(1 for t in targets if t.state == TargetState.COMPLETED)
    pending = len(targets) - completed

    summary = Text()
    summary.append(f"Adapter: {monitor_interface}   ")
    summary.append("Mode: MONITOR\n")
    summary.append(
        f"Networks found: {networks_found}   Targets: {len(targets)}   "
        f"Completed: {completed}   Pending: {pending}"
    )

    table = Table(show_header=True, header_style="bold", expand=True, box=None)
    table.add_column("", width=2)
    table.add_column("SSID", overflow="ellipsis", max_width=20)
    table.add_column("Handshakes", justify="center")
    table.add_column("State")
    for t in targets:
        mark = STATE_MARK.get(t.state.value, "[dim]○[/]")
        table.add_row(mark, t.ap.ssid, f"{t.handshake_count}/{t.required_handshakes}", t.state.value)

    parts = [summary, table]

    if channel_progress is not None:
        channel, elapsed, timeout, found, total = channel_progress
        width = 30
        filled = min(width, int(width * elapsed / timeout)) if timeout > 0 else 0
        bar = "#" * filled + "-" * (width - filled)
        parts.append(Text(f"CH{channel} [{bar}] {elapsed}s/{timeout}s  handshakes {found}/{total}"))

    parts.append(Text("[q + Enter] quit safely and restore system", style="dim"))

    return Panel(Group(*parts), title="WIFI HANDSHAKE CAPTURE TOOL", border_style="dark_red")


def render_dashboard(
    monitor_interface: str,
    networks_found: int,
    targets: list[Target],
    channel_progress: tuple | None = None,
) -> None:
    global _live
    panel = _build_dashboard(monitor_interface, networks_found, targets, channel_progress)
    if _live is None:
        _live = Live(panel, console=_console, refresh_per_second=4)
        _live.start()
    else:
        _live.update(panel)


def stop_dashboard() -> None:
    global _live
    if _live is not None:
        _live.stop()
        _live = None


def print_final_report(networks_found: int, targets: list[Target]) -> None:
    completed = [t for t in targets if t.state == TargetState.COMPLETED]
    found = [t for t in targets if t.handshake_count > 0]
    not_found = [t for t in targets if t.handshake_count == 0]

    print("\nSCAN COMPLETE\n")
    print(f"Networks discovered: {networks_found}")
    print(f"Targets selected:    {len(targets)}")
    print(f"Completed:           {len(completed)}")
    print("\nHandshake results:")
    print(f"    Found:            {len(found)}")
    print(f"    Not found:        {len(not_found)}")
    print("\nCaptures:")
    print(f"    {len(found)} validated files")
    print("\nOutput:\n    captures/")


def write_report_json(path: Path, targets: list[Target], session_id: str, log_file: str | None = None) -> None:
    from . import __version__

    targets_data = []
    for t in targets:
        targets_data.append(
            {
                "ssid": t.ap.ssid,
                "bssid": t.ap.bssid,
                "channel": t.ap.channel,
                "security": t.ap.security,
                "capture_status": t.state.value,
                "handshake_count": t.handshake_count,
                "capture_filename": t.capture_file,
                "start_time": t.start_time,
                "end_time": t.end_time,
            }
        )
    data = {
        "session_id": session_id,
        "tool_version": __version__,
        "log_file": log_file,
        "targets": targets_data,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
