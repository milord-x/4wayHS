from __future__ import annotations

import re
import subprocess
import time

from .preflight import CONFLICTING_SERVICES


class MonitorModeError(Exception):
    pass


def stop_conflicting_services() -> None:
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, text=True)


def restore_services(was_running: list[str]) -> None:
    """Restore each conflicting service to the state it had before the
    toolkit ran, instead of unconditionally starting all of them."""
    for svc in CONFLICTING_SERVICES:
        action = "start" if svc in was_running else "stop"
        subprocess.run(["systemctl", action, svc], capture_output=True, text=True)


def _interface_exists(interface: str) -> bool:
    result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True)
    return result.returncode == 0


def enable_monitor_mode(interface: str) -> str:
    stop_conflicting_services()

    for _ in range(5):
        if _interface_exists(interface):
            break
        time.sleep(1)

    result = subprocess.run(
        ["airmon-ng", "start", interface], capture_output=True, text=True
    )
    output = result.stdout + result.stderr

    mon_interface = _parse_monitor_interface(output) or f"{interface}mon"

    for _ in range(5):
        if is_monitor_mode(mon_interface):
            return mon_interface
        time.sleep(1)

    subprocess.run(["airmon-ng", "stop", mon_interface], capture_output=True, text=True)
    subprocess.run(["ip", "link", "set", interface, "down"], capture_output=True, text=True)
    subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], capture_output=True, text=True)
    subprocess.run(["ip", "link", "set", interface, "up"], capture_output=True, text=True)

    for _ in range(5):
        if is_monitor_mode(interface):
            return interface
        time.sleep(1)

    raise MonitorModeError(
        "Unable to enable monitor mode.\n"
        "Reason: Driver does not support monitor mode, "
        "or interface name differs from expected.\n\n"
        f"airmon-ng output:\n{output}"
    )


def _parse_monitor_interface(airmon_output: str) -> str | None:
    match = re.search(r"monitor mode vif enabled for \S+ on \S*?\]([^\s)]+)", airmon_output)
    if match:
        return match.group(1)
    match = re.search(r"monitor mode enabled on (\S+)", airmon_output)
    if match:
        return match.group(1)
    return None


def is_monitor_mode(interface: str) -> bool:
    result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True)
    if result.returncode != 0:
        return False
    return "type monitor" in result.stdout


def disable_monitor_mode(mon_interface: str, base_interface: str | None = None) -> None:
    subprocess.run(["airmon-ng", "stop", mon_interface], capture_output=True, text=True)
    if base_interface:
        if is_monitor_mode(base_interface):
            subprocess.run(["ip", "link", "set", base_interface, "down"], capture_output=True, text=True)
            subprocess.run(["iw", "dev", base_interface, "set", "type", "managed"], capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", base_interface, "up"], capture_output=True, text=True)
