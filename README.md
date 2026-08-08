<p align="center">
  <img alt="4wayHS" src="assets/logo.webp" width="550">
</p>

<p align="center">
  <b>WPA/WPA2 4-way handshake capture toolkit</b><br>
  Default cybersecurity toolkit for wireless network auditing.
</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.12%2B-blue">
  <img alt="platform" src="https://img.shields.io/badge/platform-linux-informational">
  <img alt="kali" src="https://img.shields.io/badge/Kali-557C94?logo=kalilinux&logoColor=fff">
  <img alt="blackarch" src="https://img.shields.io/badge/BlackArch-000000?logo=arch-linux&logoColor=fff">
  <img alt="parrot" src="https://img.shields.io/badge/Parrot%20OS-15D8CD?logoColor=fff">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="status" src="https://img.shields.io/badge/status-active-success">
</p>

---

## What it is

4wayHS is an automated orchestrator around the `aircrack-ng` suite. It puts a
Wi-Fi adapter into monitor mode, scans for nearby access points, lets you
pick targets, then listens per-channel until it captures and validates a
WPA/WPA2 4-way handshake – saving only confirmed `.cap` files and restoring
your system afterward.

It does not crack passwords. It captures and validates handshakes for
offline analysis with tools like `aircrack-ng`/`hashcat`, which you run
separately.

## Features

- Full system preflight check (interface, driver, monitor mode, privileges, conflicting services)
- Automatic monitor mode setup with chipset-specific fallback (Intel iwlwifi/CNVi)
- Wi-Fi discovery with a numbered target picker (`1,3,5`, `1-10`, `1-5,8,10-12`)
- Channel-batched capture – one listener per channel covers every target on it at once
- Live dashboard with per-channel progress bar
- Dead-AP detection (skips targets that vanish instead of burning the full timeout)
- Optional `--deauth` to force client reassociation (own networks only)
- Automatic cleanup and full system restore on exit, `q`, or Ctrl+C
- JSON report + full run log per session

## Requirements

- Linux with a Wi-Fi adapter that supports monitor mode
- `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aircrack-ng`, `aireplay-ng`)
- `iw`, `ip` (iproute2)
- Python 3.12+
- root privileges (monitor mode requires it)

```bash
sudo pacman -S aircrack-ng iw iproute2   # Arch / BlackArch
sudo apt install aircrack-ng iw iproute2 # Debian/Ubuntu / Kali / Parrot
```

Tested on: **Kali Linux**, **BlackArch**, **Parrot OS**, and vanilla **Arch Linux**.

## Install

```bash
git clone https://github.com/<your-username>/4wayHS.git
cd 4wayHS
```

No Python dependencies beyond the standard library – nothing to `pip install`.

Optional: drop a `wayhs` launcher on your `$PATH`:

```bash
cat > ~/.local/bin/wayhs << 'EOF'
#!/usr/bin/env bash
cd /path/to/4wayHS || exit 1
exec sudo -n python3 -m fourwayhs "$@"
EOF
chmod +x ~/.local/bin/wayhs
```

## Usage

```bash
sudo python3 -m fourwayhs --scan-duration 15 --capture-timeout 60
```

| Flag | Default | Description |
|---|---|---|
| `--scan-duration` | 15 | Seconds spent scanning for nearby networks |
| `--capture-timeout` | 60 | Seconds to wait per channel before giving up |
| `--required-handshakes` | 1 | Handshakes required per target |
| `--work-dir` | `.` | Where `tmp/`, `captures/`, `logs/`, `report.json` are written |
| `--deauth` | off | Broadcast deauth to force reassociation (active attack – own networks only) |

While running, press `q` + Enter at any time to abort safely – the toolkit
restores your network interface and services before exiting.

## Output

```
captures/
└── SSID_AA-BB-CC-DD-EE-FF.cap   # validated handshakes only

report.json                      # per-target results
logs/last_run.log                # full log of the last run
```

## Legal

This tool captures 4-way handshakes for **your own networks or networks you
have explicit authorization to test**. The `--deauth` flag performs an
active attack (deauthentication) and is a real disruption to the target
network – using it against a network you don't own or don't have written
permission to test is illegal in most jurisdictions. You are responsible
for how you use this tool.

## License

MIT – see [LICENSE](LICENSE).
