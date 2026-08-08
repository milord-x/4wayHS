from __future__ import annotations

import os
from pathlib import Path

from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.l2 import LLC, SNAP
from scapy.all import wrpcap


def _eapol_key_frame(msg_num: int, replay_counter: int, src: str, dst: str, bssid: str):
    key_ack = 1 if msg_num in (1, 3) else 0
    has_mic = 0 if msg_num == 1 else 1
    install = 1 if msg_num == 3 else 0
    secure = 1 if msg_num in (3, 4) else 0
    key = EAPOL_KEY(
        key_descriptor_type=2,
        key_type=1,
        key_ack=key_ack,
        has_key_mic=has_mic,
        install=install,
        secure=secure,
        key_replay_counter=replay_counter,
        key_nonce=os.urandom(32),
    )
    eapol = EAPOL(version=2, type=3) / key
    dot11 = Dot11(type=2, subtype=0, addr1=dst, addr2=src, addr3=bssid)
    return dot11 / LLC() / SNAP(OUI=0, code=0x888E) / eapol


def handshake_messages(bssid: str, client: str, replay_base: int, messages: list[int]):
    frames = []
    for msg_num in messages:
        replay_counter = replay_base if msg_num in (1, 2) else replay_base + 1
        src = bssid if msg_num in (1, 3) else client
        dst = client if msg_num in (1, 3) else bssid
        frames.append(_eapol_key_frame(msg_num, replay_counter, src, dst, bssid))
    return frames


def write_fixture(path: Path, frames: list) -> None:
    wrpcap(str(path), frames)


def build_all_fixtures(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bssid = "20:98:D8:11:DE:EE"
    other_bssid = "AA:AA:AA:AA:AA:AA"
    client = "AA:BB:CC:DD:EE:FF"

    write_fixture(
        out_dir / "handshake-complete.cap",
        handshake_messages(bssid, client, 10, [1, 2, 3, 4]),
    )
    write_fixture(
        out_dir / "handshake-m1-m2.cap",
        handshake_messages(bssid, client, 10, [1, 2]),
    )
    write_fixture(
        out_dir / "handshake-m1-m2-m3.cap",
        handshake_messages(bssid, client, 10, [1, 2, 3]),
    )
    write_fixture(
        out_dir / "multiple-handshakes.cap",
        handshake_messages(bssid, client, 10, [1, 2, 3, 4])
        + handshake_messages(bssid, client, 20, [1, 2, 3, 4]),
    )
    write_fixture(
        out_dir / "unrelated-eapol.cap",
        handshake_messages(other_bssid, client, 10, [1, 2, 3, 4]),
    )


if __name__ == "__main__":
    build_all_fixtures(Path(__file__).parent / "fixtures")
    print("fixtures written")
