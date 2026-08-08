from __future__ import annotations

import json
import re
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

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
    "COMPLETED": "✓",
    "VALIDATED": "✓",
    "HANDSHAKE_FOUND": "✓",
    "CAPTURING": "◉",
    "NO_HANDSHAKE": "✗",
    "QUEUED": "○",
    "DISCOVERED": "○",
}

_USE_COLOR = sys.stdout.isatty()
DARK_RED = "\x1b[38;5;88m"
RESET = "\x1b[0m"


def _redborder(line: str) -> str:
    if not _USE_COLOR:
        return line
    return line.replace("║", f"{DARK_RED}║{RESET}").replace("╔", f"{DARK_RED}╔").replace(
        "╗", f"╗{RESET}"
    ).replace("╠", f"{DARK_RED}╠").replace("╣", f"╣{RESET}").replace(
        "╚", f"{DARK_RED}╚"
    ).replace("╝", f"╝{RESET}")


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


def _width() -> int:
    return max(60, min(shutil.get_terminal_size((60, 20)).columns, 78))


def _bar(current: int, total: int, width: int = 20) -> str:
    if total <= 0:
        filled = 0
    else:
        filled = min(width, int(width * current / total))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _row(content: str, w: int) -> str:
    return "║" + content[: w - 2].ljust(w - 2) + "║"


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    return text[: width - 1] + "…"


def render_progress_line(channel_progress: tuple) -> str:
    channel, elapsed, timeout, found, total = channel_progress
    bar = _bar(elapsed, timeout)
    return f"  CH{channel} {bar} {elapsed}s/{timeout}s  handshakes {found}/{total}"


def render_dashboard(
    monitor_interface: str,
    networks_found: int,
    targets: list[Target],
    channel_progress: tuple | None = None,
) -> None:
    w = _width()
    completed = sum(1 for t in targets if t.state == TargetState.COMPLETED)
    pending = len(targets) - completed

    lines = []
    lines.append("╔" + "═" * (w - 2) + "╗")
    lines.append("║" + "WIFI HANDSHAKE CAPTURE TOOL".center(w - 2) + "║")
    lines.append("╠" + "═" * (w - 2) + "╣")
    lines.append(_row(f" Adapter: {monitor_interface}", w))
    lines.append(_row(" Mode: MONITOR", w))
    lines.append(_row(f" Networks found: {networks_found}", w))
    lines.append(_row(f" Targets: {len(targets)}", w))
    lines.append(_row(f" Completed: {completed}", w))
    lines.append(_row(f" Pending: {pending}", w))
    lines.append("╠" + "═" * (w - 2) + "╣")
    lines.append(_row(" TARGETS", w))
    lines.append(_row("", w))
    for t in targets:
        mark = STATE_MARK.get(t.state.value, "○")
        ssid = _truncate(t.ap.ssid, 16)
        hs = f"{t.handshake_count}/{t.required_handshakes}".ljust(5)
        row = f" {mark} {ssid} {hs} {t.state.value:<16}"
        lines.append(_row(row, w))
    lines.append(_row("", w))

    if channel_progress is not None:
        channel, elapsed, timeout, found, total = channel_progress
        lines.append("╠" + "═" * (w - 2) + "╣")
        bar = _bar(elapsed, timeout)
        row = f" CH{channel} {bar} {elapsed}s/{timeout}s  handshakes {found}/{total}"
        lines.append(_row(row, w))

    lines.append("╠" + "═" * (w - 2) + "╣")
    lines.append(_row(" [q + Enter] quit safely and restore system", w))
    lines.append("╚" + "═" * (w - 2) + "╝")

    sys.stdout.write("\n".join(_redborder(l) for l in lines) + "\n")
    sys.stdout.flush()


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


def write_report_json(path: Path, targets: list[Target]) -> None:
    data = []
    for t in targets:
        data.append(
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
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
