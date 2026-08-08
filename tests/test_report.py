from __future__ import annotations

import io
from contextlib import redirect_stdout

from fourwayhs import report
from fourwayhs.discovery import AccessPoint
from fourwayhs.targets import Target, TargetState


def _make_target(state=TargetState.CAPTURING, handshake_count=0, required=1):
    ap = AccessPoint(
        ssid="Yana", bssid="20:98:D8:11:DE:EE", channel=3, frequency=2422,
        security="WPA2", signal=-40, first_seen="", last_seen="",
    )
    return Target(ap=ap, required_handshakes=required, state=state, handshake_count=handshake_count)


def test_render_dashboard_does_not_raise():
    t = _make_target()
    buf = io.StringIO()
    with redirect_stdout(buf):
        report.render_dashboard("wlan0mon", 5, [t])
        report.render_dashboard("wlan0mon", 5, [t], (3, 10, 60, 0, 1))
        report.stop_dashboard()


def test_print_final_report_counts():
    completed = _make_target(state=TargetState.COMPLETED, handshake_count=1)
    not_found = _make_target(state=TargetState.NO_HANDSHAKE, handshake_count=0)

    buf = io.StringIO()
    with redirect_stdout(buf):
        report.print_final_report(2, [completed, not_found])
    output = buf.getvalue()

    assert "Networks discovered: 2" in output
    assert "Targets selected:    2" in output
    assert "Found:            1" in output
    assert "Not found:        1" in output


if __name__ == "__main__":
    test_render_dashboard_does_not_raise()
    test_print_final_report_counts()
    print("OK: report tests passed")
