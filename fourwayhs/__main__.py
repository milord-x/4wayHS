from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from .orchestrator import PreflightFailed, run


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


def main() -> None:
    parser = argparse.ArgumentParser(prog="4wayHS", description="Wi-Fi Handshake Capture Toolkit")
    parser.add_argument("--scan-duration", type=int, default=15, help="Discovery scan duration (s)")
    parser.add_argument("--capture-timeout", type=int, default=60, help="Per-target capture timeout (s)")
    parser.add_argument("--required-handshakes", type=int, default=1, help="Handshakes required per target")
    parser.add_argument("--work-dir", type=Path, default=Path("."), help="Working directory")
    parser.add_argument(
        "--deauth",
        action="store_true",
        help="Send broadcast deauth frames to force client reassociation (active attack, own networks only)",
    )
    args = parser.parse_args()

    log_dir = args.work_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = open(log_dir / "last_run.log", "w", encoding="utf-8")
    sys.stdout = Tee(sys.__stdout__, log_file)
    sys.stderr = Tee(sys.__stderr__, log_file)

    try:
        run(
            scan_duration=args.scan_duration,
            capture_timeout=args.capture_timeout,
            required_handshakes=args.required_handshakes,
            work_dir=args.work_dir,
            deauth=args.deauth,
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
