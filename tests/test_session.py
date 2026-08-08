from __future__ import annotations

import tempfile
from pathlib import Path

from fourwayhs.__main__ import make_session_id


def test_make_session_id_first_run_of_day():
    with tempfile.TemporaryDirectory() as d:
        sessions_dir = Path(d)
        session_id = make_session_id(sessions_dir)
        assert session_id.endswith("_001")


def test_make_session_id_increments_on_collision():
    with tempfile.TemporaryDirectory() as d:
        sessions_dir = Path(d)
        first = make_session_id(sessions_dir)
        (sessions_dir / first).mkdir()
        second = make_session_id(sessions_dir)
        assert second != first
        assert second.endswith("_002")


if __name__ == "__main__":
    test_make_session_id_first_run_of_day()
    test_make_session_id_increments_on_collision()
    print("OK: session tests passed")
