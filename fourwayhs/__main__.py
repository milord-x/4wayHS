from __future__ import annotations

import argparse
import sys
import tomllib
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .orchestrator import PreflightFailed, run

CONFIG_KEYS = {
    "scan_duration",
    "capture_timeout",
    "required_handshakes",
    "work_dir",
    "interface",
    "deauth",
    "backend",
}


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self.streams:
            s.flush()


def load_config(path: Path) -> dict:
    with path.open("rb") as f:
        data = tomllib.load(f)
    unknown = set(data) - CONFIG_KEYS
    if unknown:
        raise ValueError(f"Unknown config key(s): {', '.join(sorted(unknown))}")
    if "work_dir" in data:
        data["work_dir"] = Path(data["work_dir"])
    return data


def make_session_id(sessions_dir: Path) -> str:
    date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")
    n = 1
    while (sessions_dir / f"{date_prefix}_{n:03d}").exists():
        n += 1
    return f"{date_prefix}_{n:03d}"


def main() -> None:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", type=Path, default=None)
    config_args, remaining = config_parser.parse_known_args()

    parser = argparse.ArgumentParser(prog="4wayHS", description="Wi-Fi Handshake Capture Toolkit")
    parser.add_argument("--config", type=Path, default=None, help="Path to TOML config file")
    parser.add_argument("--scan-duration", type=int, default=15, help="Discovery scan duration (s)")
    parser.add_argument("--capture-timeout", type=int, default=60, help="Per-target capture timeout (s)")
    parser.add_argument("--required-handshakes", type=int, default=1, help="Handshakes required per target")
    parser.add_argument("--work-dir", type=Path, default=Path("."), help="Working directory")
    parser.add_argument("--interface", default=None, help="Wi-Fi interface to use (e.g. wlan1)")
    parser.add_argument(
        "--backend",
        choices=["aircrack", "native"],
        default="aircrack",
        help="Capture backend: aircrack-ng suite (default) or native (scapy, no aircrack-ng)",
    )
    parser.add_argument(
        "--deauth",
        action="store_true",
        help="Send broadcast deauth frames to force client reassociation (active attack, own networks only)",
    )

    if config_args.config:
        parser.set_defaults(**load_config(config_args.config))

    args = parser.parse_args(remaining)

    sessions_dir = args.work_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    session_id = make_session_id(sessions_dir)
    session_dir = sessions_dir / session_id
    session_dir.mkdir(parents=True)

    log_path = session_dir / "run.log"
    log_file = open(log_path, "w", encoding="utf-8")
    sys.stdout = Tee(sys.__stdout__, log_file)
    sys.stderr = Tee(sys.__stderr__, log_file)

    latest_link = sessions_dir / "latest"
    try:
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(session_id)
    except OSError:
        pass

    try:
        run(
            scan_duration=args.scan_duration,
            capture_timeout=args.capture_timeout,
            required_handshakes=args.required_handshakes,
            work_dir=args.work_dir,
            deauth=args.deauth,
            interface=args.interface,
            backend_name=args.backend,
            session_id=session_id,
            session_dir=session_dir,
            log_file=str(log_path),
        )
    except PreflightFailed as e:
        print(f"\n[ERROR]\n{e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    finally:
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        log_file.close()


if __name__ == "__main__":
    main()
