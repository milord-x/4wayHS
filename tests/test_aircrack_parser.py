from __future__ import annotations

from pathlib import Path

from fourwayhs.handshake.aircrack_parser import parse_handshake_count

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def test_parses_single_handshake():
    assert parse_handshake_count(_read("aircrack_output_1.txt")) == 1


def test_parses_multiple_handshakes():
    assert parse_handshake_count(_read("aircrack_output_2.txt")) == 3


def test_zero_handshakes():
    assert parse_handshake_count(_read("aircrack_output_no_handshake.txt")) == 0


def test_no_network_found():
    assert parse_handshake_count(_read("aircrack_output_no_network.txt")) == 0


def test_empty_output():
    assert parse_handshake_count("") == 0


if __name__ == "__main__":
    test_parses_single_handshake()
    test_parses_multiple_handshakes()
    test_zero_handshakes()
    test_no_network_found()
    test_empty_output()
    print("OK: aircrack parser tests passed")
