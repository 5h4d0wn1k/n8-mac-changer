#!/usr/bin/env python3
"""
N8 - MAC Changer + Analyzer
MAC address randomization, OUI lookup, vendor identification, and persistence.
"""

import subprocess
import random
import json
import sys
import os
import re
import argparse
import platform


OUI_DATABASE = {
    '00:00:0C': 'Cisco', '00:01:42': 'Cisco', '00:03:6B': 'Cisco',
    '00:0A:41': 'Cisco', '00:0B:BE': 'Cisco', '00:0D:BC': 'Cisco',
    '00:13:10': 'Cisco', '00:17:0E': 'Cisco', '00:19:AA': 'Cisco',
    '00:1A:A1': 'Cisco', '00:1B:0D': 'Cisco', '00:1C:0E': 'Cisco',
    '00:1E:4A': 'Cisco', '00:21:55': 'Cisco', '00:23:04': 'Cisco',
    '00:24:50': 'Cisco', '00:25:45': 'Cisco', '00:26:0A': 'Cisco',
    '00:40:96': 'Cisco', '00:50:56': 'VMware', '00:0C:29': 'VMware',
    '00:05:69': 'VMware', '00:1C:14': 'VMware', '00:0F:4B': 'Oracle',
    '08:00:27': 'Oracle VirtualBox', '0A:00:27': 'Oracle VirtualBox',
    '52:54:00': 'QEMU/KVM', '00:16:3E': 'Xen',
    '00:15:5D': 'Microsoft Hyper-V', '00:0D:3A': 'Microsoft Azure',
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi', 'D8:3A:DD': 'Raspberry Pi',
    '00:1A:2B': 'Cisco Linksys', '00:23:CD': 'Cisco Linksys',
    'C0:56:27': 'Netgear', '00:1F:33': 'Netgear',
    '00:1E:58': 'D-Link', '1C:7E:E5': 'D-Link',
    '00:18:E7': 'NETGEAR', '00:24:B2': 'NETGEAR',
    '00:26:F2': 'Netgear', 'A4:2B:8C': 'Netgear',
    '00:90:4C': 'Epigram', '00:0E:8F': 'Netgear',
    '3C:22:FB': 'Apple', 'A8:5C:2C': 'Apple',
    'F0:18:98': 'Apple', 'AC:DE:48': 'Apple',
    '00:1A:11': 'Google', '3C:5A:B4': 'Google',
    '54:60:09': 'Google', 'F4:F5:D8': 'Google',
    '68:C4:4D': 'Motorola', '00:1E:58': 'D-Link',
    '00:21:91': 'D-Link', 'C8:3A:35': 'Tenda',
    '00:B0:52': 'Atheros', '00:13:E8': 'Atheros',
    '18:A6:F7': 'TP-Link', '50:C7:BF': 'TP-Link',
    'C0:25:E9': 'TP-Link', 'EC:08:6B': 'TP-Link',
    '00:1D:D8': 'Hewlett-Packard', '00:17:A4': 'Hewlett-Packard',
    '00:08:22': 'InPro', '00:80:77': 'Tektronix',
    '00:D0:2D': 'Quantum', '00:E0:4C': 'Realtek',
    '52:54:AB': 'Realtek', '00:02:B3': 'Intel',
    '00:13:02': 'Intel', '00:15:17': 'Intel',
    '00:1E:65': 'Intel', '00:24:D7': 'Intel',
    '3C:97:0E': 'Intel', '40:A6:D9': 'Intel',
    '68:05:CA': 'Intel', '8C:8D:28': 'Intel',
    'A4:4C:C8': 'Intel', 'B4:69:AF': 'Intel',
    'CC:3D:82': 'Intel', 'F8:63:3F': 'Intel',
    '00:06:5A': 'Gateway', '00:11:11': 'Actiontec',
    '00:15:E9': 'Sagem', '00:12:17': 'Sagem',
    '00:1F:9F': 'Sagem', '00:24:8C': 'Sagem',
}


class MACChanger:
    """MAC address changing and analysis tool."""

    def __init__(self):
        self.system = platform.system()
        self.interface = None
        self.original_mac = None

    @staticmethod
    def parse_mac(mac_str):
        """Parse MAC string to normalized format."""
        mac = mac_str.strip().upper()
        mac = re.sub(r'[^0-9A-F]', '', mac)
        if len(mac) != 12:
            return None
        return ':'.join(mac[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def generate_random_mac(unicast=True, locally_administered=True):
        """Generate a random MAC address."""
        first_octet = random.randint(0x00, 0xFF)
        if locally_administered:
            first_octet |= 0x02
        else:
            first_octet &= 0xFE
        if unicast:
            first_octet &= ~0x01
        else:
            first_octet |= 0x01

        octets = [first_octet]
        for _ in range(5):
            octets.append(random.randint(0x00, 0xFF))
        return ':'.join(f'{o:02X}' for o in octets)

    @staticmethod
    def lookup_oui(mac):
        """Look up OUI vendor from MAC address."""
        oui = mac.upper()[:8]
        if oui in OUI_DATABASE:
            return OUI_DATABASE[oui]
        prefix = ':'.join(oui.split(':')[:3])
        if prefix in OUI_DATABASE:
            return OUI_DATABASE[prefix]
        for key, vendor in OUI_DATABASE.items():
            if mac.upper().startswith(key):
                return vendor
        return 'Unknown'

    def get_current_mac(self, interface):
        """Get current MAC address of an interface."""
        try:
            if self.system == 'Linux':
                result = subprocess.run(
                    ['ip', 'link', 'show', interface],
                    capture_output=True, text=True, timeout=5)
                match = re.search(r'link/ether\s+([0-9a-fA-F:]{17})',
                                  result.stdout)
                if match:
                    return self.parse_mac(match.group(1))
            elif self.system == 'Darwin':
                result = subprocess.run(
                    ['ifconfig', interface],
                    capture_output=True, text=True, timeout=5)
                match = re.search(r'ether\s+([0-9a-fA-F:]{17})',
                                  result.stdout)
                if match:
                    return self.parse_mac(match.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def list_interfaces(self):
        """List available network interfaces."""
        interfaces = []
        try:
            if self.system == 'Linux':
                result = subprocess.run(
                    ['ip', '-o', 'link', 'show'],
                    capture_output=True, text=True, timeout=5)
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        name = parts[1].strip()
                        if name not in ('lo',):
                            mac = self.get_current_mac(name)
                            interfaces.append({
                                'name': name, 'mac': mac,
                                'vendor': self.lookup_oui(mac) if mac else 'N/A'
                            })
            elif self.system == 'Darwin':
                result = subprocess.run(
                    ['networksetup', '-listallhardwareports'],
                    capture_output=True, text=True, timeout=5)
                current_name = None
                for line in result.stdout.split('\n'):
                    if 'Hardware Port:' in line:
                        current_name = line.split(':', 1)[1].strip()
                    elif 'Ethernet Address:' in line and current_name:
                        mac_match = re.search(
                            r'([0-9a-fA-F:]{17})', line)
                        if mac_match:
                            mac = self.parse_mac(mac_match.group(1))
                            interfaces.append({
                                'name': current_name, 'mac': mac,
                                'vendor': self.lookup_oui(mac) if mac else 'N/A'
                            })
                        current_name = None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return interfaces

    def change_mac_linux(self, interface, new_mac):
        """Change MAC on Linux using ip command."""
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'down'],
                           check=True, capture_output=True, timeout=5)
            subprocess.run(['ip', 'link', 'set', interface,
                            'address', new_mac],
                           check=True, capture_output=True, timeout=5)
            subprocess.run(['ip', 'link', 'set', interface, 'up'],
                           check=True, capture_output=True, timeout=5)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error: {e.stderr.decode() if e.stderr else e}")
            return False

    def change_mac_osx(self, interface, new_mac):
        """Change MAC on macOS."""
        try:
            subprocess.run(['ifconfig', interface, 'ether', new_mac],
                           check=True, capture_output=True, timeout=5)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error: {e.stderr.decode() if e.stderr else e}")
            return False

    def change_mac(self, interface, new_mac):
        """Change MAC address of specified interface."""
        new_mac = self.parse_mac(new_mac)
        if not new_mac:
            print(f"[-] Invalid MAC address format")
            return False

        self.interface = interface
        self.original_mac = self.get_current_mac(interface)

        print(f"[+] Changing MAC on {interface}")
        print(f"    Current: {self.original_mac}")
        print(f"    New:     {new_mac}")
        print(f"    Vendor:  {self.lookup_oui(new_mac)}")

        if self.system == 'Linux':
            return self.change_mac_linux(interface, new_mac)
        elif self.system == 'Darwin':
            return self.change_mac_osx(interface, new_mac)
        else:
            print(f"[-] Unsupported OS: {self.system}")
            return False

    def persist_mac(self, interface, mac, filepath='/etc/macchanger.conf'):
        """Save MAC configuration for persistence."""
        config = {'interface': interface, 'mac': mac}
        try:
            with open(filepath, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"[+] Configuration saved to {filepath}")
            return True
        except OSError as e:
            print(f"[-] Cannot write config: {e}")
            return False

    def load_persisted(self, filepath='/etc/macchanger.conf'):
        """Load persisted MAC configuration."""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def analyze_mac(self, mac):
        """Analyze a MAC address for characteristics."""
        mac = self.parse_mac(mac)
        if not mac:
            return None

        first = int(mac.replace(':', '')[:2], 16)
        locally_administered = bool(first & 0x02)
        unicast = not bool(first & 0x01)
        multicast = bool(first & 0x01)

        return {
            'mac': mac,
            'vendor': self.lookup_oui(mac),
            'locally_administered': locally_administered,
            'unicast': unicast,
            'multicast': multicast,
            'type': 'Locally Administered' if locally_administered
                    else 'Globally Unique (OUI)',
        }

    def print_analysis(self, mac):
        """Print formatted MAC analysis."""
        result = self.analyze_mac(mac)
        if not result:
            print(f"[-] Invalid MAC: {mac}")
            return

        print(f"\n  MAC Analysis: {result['mac']}")
        print(f"  {'='*40}")
        print(f"  Vendor:             {result['vendor']}")
        print(f"  Type:               {result['type']}")
        print(f"  Unicast/Multicast:  {'Unicast' if result['unicast'] else 'Multicast'}")
        print(f"  Locally Administered: {'Yes' if result['locally_administered'] else 'No'}")

    @staticmethod
    def validate_mac(mac):
        """Validate a MAC string; return normalized form or None."""
        return MACChanger.parse_mac(mac)

    @staticmethod
    def ioctl_commands(interface, new_mac):
        """Print the ioctl(2)/netlink command sequence a live change uses.

        Pure informational output (no actual interface touched). Linux changes
        the MAC via SIOCSIFHWADDR ioctl or `ip link` netlink; this shows the
        exact low-level sequence for lab documentation.
        """
        normalized = MACChanger.parse_mac(new_mac)
        if not normalized:
            return False
        cmds = [
            f"ioctl(SOCK_DGRAM, SIOCGIFFLAGS, ifr={interface})",
            f"ioctl(SOCK_DGRAM, SIOCSIFHWADDR, ifr={interface}, "
            f"hwaddr={normalized})",
            f"# equivalent netlink equivalent (ip link set {interface} "
            f"address {normalized})",
        ]
        for c in cmds:
            print(f"  {c}")
        return True

    @staticmethod
    def print_offline_report():
        """Offline harness: validate MAC formats and print change commands.

        No interface is touched and no privileges are required. Exercises the
        real parse/validate/generate code paths deterministically.
        """
        ok = True
        m = MACChanger
        inst = MACChanger()

        def verify(label, cond, detail=''):
            nonlocal ok
            print(f'  [{"PASS" if cond else "FAIL"}] {label} {detail}')
            ok = ok and cond

        print('=== N8 MAC Changer: offline validation harness ===')

        good = '00:11:22:33:44:55'
        verify('parse valid MAC', m.parse_mac(good) == good, good)
        verify('normalize lowercase/hyphen',
               m.parse_mac('00-11-22-33-44-55') == good)
        verify('normalize no separator',
               m.parse_mac('001122334455') == good)
        verify('reject short MAC', m.parse_mac('0011223344') is None)
        verify('reject bad hex', m.parse_mac('00:11:22:33:44:zz') is None)

        g = m.generate_random_mac()
        verify('generated MAC is valid+locally administered',
               m.parse_mac(g) == g and int(g.split(':')[0], 16) & 0x02,
               g)

        a = inst.analyze_mac('02:00:00:00:00:01')
        verify('analyze type locally administered',
               a['type'] == 'Locally Administered')
        verify('analyze unicast', a['unicast'] is True)
        verify('OUI lookup for lab/default vendor',
               inst.lookup_oui('08:00:27:ab:cd:ef') == 'Oracle VirtualBox')

        print('\n--- ioctl/netlink command sequence (documentation, no apply) ---')
        if m.ioctl_commands('lab-eth0', good):
            verify('ioctl command sequence printed', True, good)

        print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
        return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description='N8 — MAC Changer + Analyzer (offline validate/harness '
                    '+ gated live change)')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline validation harness (default)')
    parser.add_argument('--list', action='store_true',
                        help='List network interfaces')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--set', help='Set specific MAC address')
    parser.add_argument('--random', action='store_true',
                        help='Set random MAC address')
    parser.add_argument('--analyze', help='Analyze a MAC address')
    parser.add_argument('--validate', action='store_true',
                        help='Validate a MAC address format')
    parser.add_argument('--dry-run', '--show', action='store_true',
                        help='Only print the ioctl/netlink commands, '
                             'do not change anything (default-safe)')
    parser.add_argument('--live', action='store_true',
                        help='Actually change the MAC on the interface')
    parser.add_argument('--current', action='store_true',
                        help='Show current MAC')
    parser.add_argument('--persist', action='store_true',
                        help='Save MAC to config file')
    parser.add_argument('--restore', action='store_true',
                        help='Restore persisted MAC')

    args = parser.parse_args()
    changer = MACChanger()

    # Default to the offline harness when nothing interface-touching is asked.
    if args.harness or not any([args.list, args.analyze, args.validate,
                                args.interface]):
        sys.exit(changer.print_offline_report())

    if args.validate:
        mac = args.analyze or ''
        normalized = changer.validate_mac(mac)
        if normalized is None:
            print(f"[-] Invalid MAC: {mac!r}")
            sys.exit(1)
        print(f"[+] Valid MAC: {normalized}")
        changer.print_analysis(normalized)
        sys.exit(0)

    if args.analyze:
        changer.print_analysis(args.analyze)
        sys.exit(0)

    print("╔═══════════════════════════════════════╗")
    print("║     N8 — MAC Changer + Analyzer       ║")
    print("╚═══════════════════════════════════════╝")

    if args.list:
        print("\n[+] Network interfaces:")
        for iface in changer.list_interfaces():
            print(f"  {iface['name']:15s} MAC: {iface['mac']} "
                  f"({iface['vendor']})")
        sys.exit(0)

    if not args.interface:
        print("[-] --interface required (use --list to see options)")
        sys.exit(1)

    if args.current:
        mac = changer.get_current_mac(args.interface)
        if mac:
            print(f"\n  {args.interface}: {mac}")
            print(f"  Vendor: {changer.lookup_oui(mac)}")
        else:
            print(f"[-] Could not read MAC for {args.interface}")
        sys.exit(0)

    # Live MAC change is gated behind --live; otherwise show the commands.
    if not args.live:
        target = args.set or changer.generate_random_mac()
        print(f"[+] Would change {args.interface} to {target} "
              f"(dry-run). Re-run with --live to apply.")
        print("  Command sequence (documentation):")
        sys.exit(0 if changer.ioctl_commands(args.interface, target) else 1)

    if args.set:
        if changer.change_mac(args.interface, args.set):
            print(f"[+] MAC changed successfully")
            if args.persist:
                changer.persist_mac(args.interface, args.set)
    elif args.random:
        new_mac = changer.generate_random_mac()
        print(f"[+] Generated random MAC: {new_mac}")
        if changer.change_mac(args.interface, new_mac):
            print(f"[+] MAC changed successfully")
            if args.persist:
                changer.persist_mac(args.interface, new_mac)
    elif args.restore:
        config = changer.load_persisted()
        if config and config['interface'] == args.interface:
            changer.change_mac(args.interface, config['mac'])
        else:
            print("[-] No valid persisted config found")
    else:
        print("[-] Specify --set, --random, --current, or --restore")
    sys.exit(0)


if __name__ == '__main__':
    main()
