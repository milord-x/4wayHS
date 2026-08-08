from __future__ import annotations

import tempfile
from pathlib import Path

from fourwayhs.orchestrator import cleanup


def test_cleanup_removes_files_in_tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        tmp_dir = Path(d) / "tmp"
        tmp_dir.mkdir()
        (tmp_dir / "scan-01.csv").write_text("data")
        (tmp_dir / "channel-6-01.cap").write_bytes(b"data")

        cleanup(tmp_dir)

        assert list(tmp_dir.glob("*")) == []


def test_cleanup_missing_dir_is_noop():
    with tempfile.TemporaryDirectory() as d:
        missing = Path(d) / "does-not-exist"
        cleanup(missing)  # must not raise


if __name__ == "__main__":
    test_cleanup_removes_files_in_tmp_dir()
    test_cleanup_missing_dir_is_noop()
    print("OK: orchestrator tests passed")
