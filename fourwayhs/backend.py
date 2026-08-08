from __future__ import annotations

from pathlib import Path

from .discovery import AccessPoint
from .targets import Target


class WiFiBackend:
    name: str = "backend"

    def enable_monitor_mode(self, interface: str) -> str:
        raise NotImplementedError

    def disable_monitor_mode(self, monitor_interface: str, base_interface: str | None = None) -> None:
        raise NotImplementedError

    def scan(self, monitor_interface: str, duration: int, work_dir: Path) -> list[AccessPoint]:
        raise NotImplementedError

    def capture_channel(
        self,
        monitor_interface: str,
        channel: int,
        targets: list[Target],
        tmp_dir: Path,
        timeout: int,
        poll_interval: int = 5,
        on_tick=None,
        deauth: bool = False,
    ) -> Path:
        raise NotImplementedError

    def send_deauth(self, monitor_interface: str, bssid: str, count: int = 5) -> None:
        raise NotImplementedError

    def detect_handshake(self, cap_path: Path, bssid: str):
        raise NotImplementedError


class AircrackBackend(WiFiBackend):
    name = "aircrack"

    def enable_monitor_mode(self, interface: str) -> str:
        from . import monitor

        return monitor.enable_monitor_mode(interface)

    def disable_monitor_mode(self, monitor_interface: str, base_interface: str | None = None) -> None:
        from . import monitor

        monitor.disable_monitor_mode(monitor_interface, base_interface)

    def scan(self, monitor_interface: str, duration: int, work_dir: Path) -> list[AccessPoint]:
        from . import discovery

        return discovery.scan(monitor_interface, duration, work_dir)

    def capture_channel(
        self,
        monitor_interface: str,
        channel: int,
        targets: list[Target],
        tmp_dir: Path,
        timeout: int,
        poll_interval: int = 5,
        on_tick=None,
        deauth: bool = False,
    ) -> Path:
        from . import capture

        return capture.capture_channel(
            monitor_interface, channel, targets, tmp_dir, timeout,
            poll_interval=poll_interval, on_tick=on_tick, deauth=deauth,
        )

    def send_deauth(self, monitor_interface: str, bssid: str, count: int = 5) -> None:
        from . import capture

        capture.send_deauth(monitor_interface, bssid, count)

    def detect_handshake(self, cap_path: Path, bssid: str):
        from .capture import _detector

        return _detector.detect(cap_path, bssid)


def get_backend(name: str) -> WiFiBackend:
    if name == "aircrack":
        return AircrackBackend()
    if name == "native":
        from .native_backend import NativeLinuxBackend

        return NativeLinuxBackend()
    raise ValueError(f"Unknown backend: {name}")
