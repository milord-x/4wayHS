from __future__ import annotations

from unittest.mock import patch

from fourwayhs import monitor


def test_restore_services_starts_only_previously_running():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return None

    with patch("subprocess.run", side_effect=fake_run):
        monitor.restore_services(["NetworkManager"])

    actions = {cmd[2]: cmd[1] for cmd in calls}
    assert actions["NetworkManager"] == "start"
    assert actions["wpa_supplicant"] == "stop"
    assert actions["iwd"] == "stop"


def test_restore_services_stops_all_when_none_were_running():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return None

    with patch("subprocess.run", side_effect=fake_run):
        monitor.restore_services([])

    assert all(cmd[1] == "stop" for cmd in calls)


if __name__ == "__main__":
    test_restore_services_starts_only_previously_running()
    test_restore_services_stops_all_when_none_were_running()
    print("OK: monitor tests passed")
