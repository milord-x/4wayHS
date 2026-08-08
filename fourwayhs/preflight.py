from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field


REQUIRED_TOOLS = ["airmon-ng", "airodump-ng", "aircrack-ng", "iw", "ip"]
CONFLICTING_SERVICES = ["NetworkManager", "wpa_supplicant", "iwd"]


@dataclass
class PreflightResult:
    interface: str | None
    driver: str | None
    monitor_capable: bool
    has_root: bool
    missing_tools: list[str] = field(default_factory=list)
    running_services: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(
            self.interface
            and self.monitor_capable
            and self.has_root
            and not self.missing_tools
        )


def find_wifi_interface() -> str | None:
    out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface"):
            return line.split()[1]
    return None


def get_driver(interface: str) -> str | None:
    link = f"/sys/class/net/{interface}/device/driver"
    try:
        return os.path.basename(os.readlink(link))
    except OSError:
        return None


def supports_monitor_mode(interface: str) -> bool:
    out = subprocess.run(["iw", "phy"], capture_output=True, text=True).stdout
    return "monitor" in out.lower()


def check_tools() -> list[str]:
    return [t for t in REQUIRED_TOOLS if shutil.which(t) is None]


def check_services() -> list[str]:
    running = []
    for svc in CONFLICTING_SERVICES:
        r = subprocess.run(
            ["systemctl", "is-active", "--quiet", svc],
        )
        if r.returncode == 0:
            running.append(svc)
    return running


def run_preflight() -> PreflightResult:
    interface = find_wifi_interface()
    driver = get_driver(interface) if interface else None
    monitor_capable = supports_monitor_mode(interface) if interface else False
    has_root = os.geteuid() == 0
    missing_tools = check_tools()
    running_services = check_services()

    return PreflightResult(
        interface=interface,
        driver=driver,
        monitor_capable=monitor_capable,
        has_root=has_root,
        missing_tools=missing_tools,
        running_services=running_services,
    )


def print_preflight(result: PreflightResult) -> None:
    print("[PRECHECK]\n")
    print(f"Wi-Fi interface: {result.interface or 'NOT FOUND'}")
    print(f"Driver: {result.driver or 'unknown'}")
    print(f"Monitor mode: {'AVAILABLE' if result.monitor_capable else 'UNAVAILABLE'}")
    print(f"Privileges: {'OK' if result.has_root else 'MISSING (need root)'}")
    if result.missing_tools:
        print(f"Missing tools: {', '.join(result.missing_tools)}")
    print()
    for svc in CONFLICTING_SERVICES:
        state = "RUNNING" if svc in result.running_services else "stopped"
        print(f"{svc}: {state}")
    print()
    if result.ok:
        print("Preparing capture environment...")
    else:
        print("[ERROR] Preflight failed, see above.")
