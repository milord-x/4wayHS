from __future__ import annotations

import tempfile
from pathlib import Path

from fourwayhs.__main__ import load_config


def test_load_config_basic():
    with tempfile.TemporaryDirectory() as d:
        cfg_path = Path(d) / "config.toml"
        cfg_path.write_text('scan_duration = 20\nrequired_handshakes = 3\n', encoding="utf-8")
        data = load_config(cfg_path)
        assert data == {"scan_duration": 20, "required_handshakes": 3}


def test_load_config_work_dir_becomes_path():
    with tempfile.TemporaryDirectory() as d:
        cfg_path = Path(d) / "config.toml"
        cfg_path.write_text('work_dir = "/tmp/foo"\n', encoding="utf-8")
        data = load_config(cfg_path)
        assert data["work_dir"] == Path("/tmp/foo")


def test_load_config_rejects_unknown_key():
    with tempfile.TemporaryDirectory() as d:
        cfg_path = Path(d) / "config.toml"
        cfg_path.write_text('bogus_key = 1\n', encoding="utf-8")
        try:
            load_config(cfg_path)
            assert False, "expected ValueError"
        except ValueError:
            pass


def test_load_config_accepts_backend_key():
    with tempfile.TemporaryDirectory() as d:
        cfg_path = Path(d) / "config.toml"
        cfg_path.write_text('backend = "native"\n', encoding="utf-8")
        data = load_config(cfg_path)
        assert data == {"backend": "native"}


if __name__ == "__main__":
    test_load_config_basic()
    test_load_config_work_dir_becomes_path()
    test_load_config_rejects_unknown_key()
    test_load_config_accepts_backend_key()
    print("OK: config tests passed")
