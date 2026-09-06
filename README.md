# N8 — MAC Changer + Analyzer

MAC address randomization, OUI lookup, vendor identification, and persistence.

## Overview

This project implements a MAC address management tool that:
- Changes MAC addresses on network interfaces (Linux/macOS)
- Generates random locally-administered MAC addresses
- Identifies vendors via OUI database lookup
- Analyzes MAC address characteristics
- Persists MAC configurations for persistence across reboots

## Features

- **MAC changing**: Change interface MAC via ip/ifconfig commands
- **Random generation**: Create random unicast, locally-administered MACs
- **OUI lookup**: Identify vendor from 80+ OUI entries
- **MAC analysis**: Detect locally administered, multicast, etc.
- **Persistence**: Save/restore MAC configs
- **Cross-platform**: Linux and macOS support

## Installation

No external dependencies — uses only the Python standard library.

## Usage

```bash
# Offline validation harness (default): validate MAC formats, generate random,
# print ioctl/netlink command sequence - no privileges, no interface touched
python3 mac_changer.py --harness

# Validate a MAC format (offline)
python3 mac_changer.py --validate 00:11:22:33:44:55

# Analyze any MAC address (offline)
python3 mac_changer.py --analyze 00:11:22:33:44:55

# List interfaces and current MACs
python3 mac_changer.py --list

# Show current MAC
python3 mac_changer.py --interface lab-eth0 --current

# Dry-run: print the ioctl/netlink sequence without changing anything
python3 mac_changer.py --interface lab-eth0 --set 00:11:22:33:44:55

# Actually change to a random MAC (--live, root required)
sudo python3 mac_changer.py --interface lab-eth0 --live --random

# Set a specific lab MAC (--live, root required)
sudo python3 mac_changer.py --interface lab-eth0 --live --set 00:11:22:33:44:55
```

The default (no args / `--harness`) runs a fully unprivileged offline harness
that validates MAC formats, generates+re-checks a random locally-administered
MAC, does OUI lookup, and prints the exact ioctl(2)/netlink command sequence a
live change would issue. Interface changes are gated behind `--live`.

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (00:11:22:33:44:55).

1. **Prepare a spare virtual NIC** (e.g. a VM with a dedicated `lab-eth0`).
2. Record the original MAC: `python3 mac_changer.py --interface lab-eth0 --current`.
3. Dry-run first: `python3 mac_changer.py --interface lab-eth0 --set 00:11:22:33:44:55`
   — confirm it only prints the ioctl/netlink sequence and changes nothing.
4. Apply: `sudo python3 mac_changer.py --interface lab-eth0 --live --set 00:11:22:33:44:55`.
5. Verify: `--current` shows `00:11:22:33:44:55`; `ip link show lab-eth0` matches;
   the VM still reaches the lab network after a link bounce.
6. Restore the original MAC and verify connectivity is normal.

## Metrics

Deterministic, unprivileged, offline:

- `python3 -m unittest discover -s tests` — unit tests (exit 0)
- MAC format validation: valid/normalized/rejected cases
- Random MAC generation re-validates as locally-administered unicast
- OUI lookup resolves lab/default vendors
- ioctl/netlink command sequence printed for documented change path
- Harness exit code: `0` on success, `1` on failure

## License

MIT

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
