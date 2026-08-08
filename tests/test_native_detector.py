from __future__ import annotations

from pathlib import Path

from fourwayhs.native_backend import NativeLinuxBackend

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BSSID = "20:98:D8:11:DE:EE"
OTHER_BSSID = "AA:AA:AA:AA:AA:AA"

_backend = NativeLinuxBackend()


def test_no_cap_file():
    result = _backend.detect_handshake(FIXTURES_DIR / "does-not-exist.cap", BSSID)
    assert result.count == 0
    assert not result.detected


def test_partial_handshake_m1_m2_only():
    result = _backend.detect_handshake(FIXTURES_DIR / "handshake-m1-m2.cap", BSSID)
    assert result.count == 0
    assert not result.detected


def test_partial_handshake_m1_m2_m3():
    result = _backend.detect_handshake(FIXTURES_DIR / "handshake-m1-m2-m3.cap", BSSID)
    assert result.count == 0
    assert not result.detected


def test_complete_handshake():
    result = _backend.detect_handshake(FIXTURES_DIR / "handshake-complete.cap", BSSID)
    assert result.count == 1
    assert result.detected


def test_two_independent_exchanges():
    result = _backend.detect_handshake(FIXTURES_DIR / "multiple-handshakes.cap", BSSID)
    assert result.count == 2
    assert result.detected


def test_wrong_bssid_not_matched():
    result = _backend.detect_handshake(FIXTURES_DIR / "unrelated-eapol.cap", BSSID)
    assert result.count == 0
    assert not result.detected

    result_other = _backend.detect_handshake(FIXTURES_DIR / "unrelated-eapol.cap", OTHER_BSSID)
    assert result_other.count == 1
    assert result_other.detected


if __name__ == "__main__":
    test_no_cap_file()
    test_partial_handshake_m1_m2_only()
    test_partial_handshake_m1_m2_m3()
    test_complete_handshake()
    test_two_independent_exchanges()
    test_wrong_bssid_not_matched()
    print("OK: native detector tests passed")
