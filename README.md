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
# List interfaces and current MACs
python3 mac_changer.py --list

# Show current MAC
python3 mac_changer.py --interface eth0 --current

# Change to random MAC (requires root)
sudo python3 mac_changer.py --interface eth0 --random

# Set specific MAC (requires root)
sudo python3 mac_changer.py --interface eth0 --set AA:BB:CC:DD:EE:FF

# Change and persist
sudo python3 mac_changer.py --interface eth0 --random --persist

# Analyze any MAC address
python3 mac_changer.py --analyze AA:BB:CC:DD:EE:FF
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N8 — MAC Changer + Analyzer       ║
╚═══════════════════════════════════════╝

[+] Network interfaces:
  eth0            MAC: AA:BB:CC:DD:EE:FF (Intel)
  wlan0           MAC: 12:34:56:78:9A:BC (Unknown)

  MAC Analysis: AA:BB:CC:DD:EE:FF
  ========================================
  Vendor:             Intel
  Type:               Locally Administered
  Unicast/Multicast:  Unicast
  Locally Administered: Yes
```

## Legal Disclaimer

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
