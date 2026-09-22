> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N8 — MAC Changer + Analyzer

MAC address randomization, OUI vendor lookup, interface analysis, and
persistence for privacy and wireless security testing on Linux and macOS — with
a fully offline, privilege-free validation harness.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/n8-mac-changer)](#)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n8-mac-changer)](#)

## Why this project

MAC (Media Access Control) addresses are hardware identifiers burned into
network interfaces, and changing them is a core technique in privacy work and
authorized wireless testing. Security analysts and privacy-conscious users need
to understand how interfaces advertise their identity, how vendors can be
fingerprinted from the OUI prefix, and how locally-administered addresses
signal intentionally randomized identity. This tool teaches those concepts
through a real, deterministic implementation: format validation, random
locally-administered unicast generation, OUI vendor lookup, address analysis,
and persistence. Every operation is documented for your own lab only, and live
changes are gated behind an explicit `--live` flag.

## Features

- **MAC changing** — change an interface MAC via `ip` (Linux) / `ifconfig`
  (macOS)
- **Random generation** — create locally-administered unicast MACs that
  re-validate on generation
- **OUI lookup** — identify vendor from an 80+ entry OUI database
- **MAC analysis** — detect locally-administered, unicast, and multicast
  characteristics and MAC type
- **Persistence** — save/restore MAC configurations to a JSON file
- **Offline harness** — the default mode validates formats, generation, and
  analysis with no privileges and no interface touched
- **ioctl(2)/netlink documentation** — prints the exact command sequence a live
  change would issue
- **Live mode gated** — applying a MAC change requires `--live` and root

## Quickstart

Prerequisites: Python 3.8+ (stdlib only). Live changes require root.

```bash
# Offline validation harness (default)
python3 firmware/mac_changer.py --harness

# Analyze any MAC address
python3 firmware/mac_changer.py --analyze 00:11:22:33:44:55

# List interfaces and current MACs with vendor
python3 firmware/mac_changer.py --list

# Show current MAC of an interface
python3 firmware/mac_changer.py --interface lab-eth0 --current

# Dry-run: print the ioctl/netlink sequence without changing anything
python3 firmware/mac_changer.py --interface lab-eth0 --set 00:11:22:33:44:55 --dry-run

# Apply a random locally-administered MAC (root + authorized own-lab only)
sudo python3 firmware/mac_changer.py --interface lab-eth0 --live --random

# Set a specific MAC and persist it
sudo python3 firmware/mac_changer.py --interface lab-eth0 --live --set 00:11:22:33:44:55 --persist

# Run the unit tests
python3 -m unittest discover -s tests
```

## Live lab test plan

> Authorized own-lab use only. Use documented placeholders (`00:11:22:33:44:55`,
> `lab-eth0`).

1. Record the original MAC: `python3 firmware/mac_changer.py --interface lab-eth0 --current`.
2. Dry-run first: `python3 firmware/mac_changer.py --interface lab-eth0 --set 00:11:22:33:44:55 --dry-run` — confirm it only prints the sequence and changes nothing.
3. Apply: `sudo python3 firmware/mac_changer.py --interface lab-eth0 --live --set 00:11:22:33:44:55`.
4. Verify with `--current` and `ip link show lab-eth0`; confirm lab connectivity after a link bounce.
5. Restore the original MAC and verify connectivity again.

## Project structure

- `firmware/mac_changer.py` — full implementation (parser, generator, analyzer,
  changer, harness)
- `tests/test_mac_changer.py` — deterministic offline unit tests

## Documentation

- [ETHICS.md](ETHICS.md) — intended use and user responsibility
- [SCOPE.md](SCOPE.md) — authorized-testing checklist
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities in this repo
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute safely

## Contributing

Contributions for legitimate lab, education, and privacy use are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Educational and authorized-testing use only;
provided **AS IS**, without warranty.