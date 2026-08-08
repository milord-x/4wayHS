from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from fourwayhs.handshake.aircrack_detector import AircrackDetector

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _fake_completed(stdout: str):
    class Result:
        pass

    r = Result()
    r.stdout = stdout
    r.returncode = 0
    return r


def test_detect_missing_cap_file():
    detector = AircrackDetector()
    result = detector.detect(Path("/nonexistent/file.cap"), "20:98:D8:11:DE:EE")
    assert not result.detected
    assert result.count == 0


def test_detect_parses_subprocess_output():
    detector = AircrackDetector()
    stdout = (FIXTURES_DIR / "aircrack_output_2.txt").read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as d:
        cap_path = Path(d) / "test.cap"
        cap_path.write_bytes(b"fake-cap-data")

        with patch("subprocess.run", return_value=_fake_completed(stdout)):
            result = detector.detect(cap_path, "20:98:D8:11:DE:EE")

    assert result.detected
    assert result.count == 3


if __name__ == "__main__":
    test_detect_missing_cap_file()
    test_detect_parses_subprocess_output()
    print("OK: aircrack detector tests passed")
