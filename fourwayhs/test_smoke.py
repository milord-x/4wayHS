from __future__ import annotations

from pathlib import Path

from fourwayhs.capture import safe_name
from fourwayhs.discovery import _parse_csv
from fourwayhs.targets import InvalidTransition, Target, TargetState, select_targets
from fourwayhs.report import write_report_json

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

SAMPLE_CSV_LF = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "20:98:D8:11:DE:EE, 2026-01-01 00:00:00, 2026-01-01 00:01:00, 3, 54, WPA2, "
    "CCMP, PSK, -40, 10, 0, 0.0.0.0, 4, Yana, \n"
    "\n\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
)

SAMPLE_CSV_CRLF = SAMPLE_CSV_LF.replace("\n", "\r\n")


def test_safe_name():
    assert safe_name("My Wi-Fi", "20:98:D8:11:DE:EE") == "My_Wi-Fi_20-98-D8-11-DE-EE"
    assert safe_name("a/b:c", "AA:BB:CC:DD:EE:FF") == "a_b_c_AA-BB-CC-DD-EE-FF"


def test_parse_csv_lf():
    aps = _parse_csv(SAMPLE_CSV_LF)
    assert len(aps) == 1
    assert aps[0].ssid == "Yana"
    assert aps[0].bssid == "20:98:D8:11:DE:EE"
    assert aps[0].channel == 3
    assert aps[0].security == "WPA2"


def test_parse_csv_crlf():
    aps = _parse_csv(SAMPLE_CSV_CRLF)
    assert len(aps) == 1
    assert aps[0].ssid == "Yana"


def test_parse_csv_with_bom():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        csv_path = Path(d) / "scan-01.csv"
        csv_path.write_bytes(b"\xef\xbb\xbf" + SAMPLE_CSV_LF.encode("utf-8"))
        text = csv_path.read_text(encoding="utf-8-sig", errors="replace")
        aps = _parse_csv(text)
        assert len(aps) == 1
        assert aps[0].ssid == "Yana"


def test_parse_csv_with_leading_blank_line():
    aps = _parse_csv("\n" + SAMPLE_CSV_LF)
    assert len(aps) == 1
    assert aps[0].ssid == "Yana"


def test_select_targets_and_report():
    import tempfile

    aps = _parse_csv(SAMPLE_CSV_LF)
    targets = select_targets(aps, [1], required_handshakes=2)
    assert targets[0].state == TargetState.QUEUED
    assert targets[0].required_handshakes == 2
    assert not targets[0].done
    targets[0].handshake_count = 2
    assert targets[0].done

    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.json"
        write_report_json(out, targets, session_id="test-session")
        assert out.exists()
        assert "Yana" in out.read_text(encoding="utf-8")


def test_parse_csv_fixture_basic():
    text = (FIXTURES_DIR / "airodump-basic.csv").read_text(encoding="utf-8")
    aps = _parse_csv(text)
    assert len(aps) == 3
    ssids = {ap.ssid for ap in aps}
    assert ssids == {"Yana", "Office", "Guest"}
    guest = next(ap for ap in aps if ap.ssid == "Guest")
    assert guest.security == "OPN"


def test_parse_csv_fixture_hidden_ssid():
    text = (FIXTURES_DIR / "airodump-hidden-ssid.csv").read_text(encoding="utf-8")
    aps = _parse_csv(text)
    assert len(aps) == 1
    assert aps[0].ssid == "<hidden>"
    assert aps[0].bssid == "DE:AD:BE:EF:00:01"


def test_target_state_machine_valid_path():
    aps = _parse_csv(SAMPLE_CSV_LF)
    t = select_targets(aps, [1], required_handshakes=1)[0]
    assert t.state == TargetState.QUEUED
    t.transition(TargetState.CAPTURING)
    t.transition(TargetState.HANDSHAKE_FOUND)
    t.transition(TargetState.COMPLETED)
    assert t.state == TargetState.COMPLETED


def test_target_state_machine_rejects_invalid_jump():
    aps = _parse_csv(SAMPLE_CSV_LF)
    t = select_targets(aps, [1], required_handshakes=1)[0]
    try:
        t.transition(TargetState.COMPLETED)
        assert False, "expected InvalidTransition"
    except InvalidTransition:
        pass
    assert t.state == TargetState.QUEUED


def test_target_state_machine_no_handshake_retry():
    aps = _parse_csv(SAMPLE_CSV_LF)
    t = select_targets(aps, [1], required_handshakes=1)[0]
    t.transition(TargetState.CAPTURING)
    t.transition(TargetState.NO_HANDSHAKE)
    t.transition(TargetState.CAPTURING)
    t.transition(TargetState.HANDSHAKE_FOUND)
    assert t.state == TargetState.HANDSHAKE_FOUND


if __name__ == "__main__":
    test_safe_name()
    test_parse_csv_lf()
    test_parse_csv_crlf()
    test_parse_csv_with_bom()
    test_parse_csv_with_leading_blank_line()
    test_select_targets_and_report()
    test_parse_csv_fixture_basic()
    test_parse_csv_fixture_hidden_ssid()
    test_target_state_machine_valid_path()
    test_target_state_machine_rejects_invalid_jump()
    test_target_state_machine_no_handshake_retry()
    print("OK: all smoke tests passed")
