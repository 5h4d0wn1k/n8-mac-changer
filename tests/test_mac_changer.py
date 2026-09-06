#!/usr/bin/env python3
"""Offline unit tests for the N8 MAC changer: MAC format validation,
random generation, OUI lookup, and the ioctl/netlink dry-run reporting."""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from mac_changer import MACChanger  # noqa: E402


class TestMACValidation(unittest.TestCase):
    def test_parse_valid(self):
        self.assertEqual(MACChanger.parse_mac('00:11:22:33:44:55'),
                         '00:11:22:33:44:55')

    def test_parse_normalizes_separators(self):
        self.assertEqual(MACChanger.parse_mac('00-11-22-33-44-55'),
                         '00:11:22:33:44:55')
        self.assertEqual(MACChanger.parse_mac('001122334455'),
                         '00:11:22:33:44:55')

    def test_parse_rejects_short(self):
        self.assertIsNone(MACChanger.parse_mac('00:11:22:33:44'))

    def test_parse_rejects_bad_hex(self):
        self.assertIsNone(MACChanger.parse_mac('00:11:22:33:44:zz'))

    def test_validate_mac(self):
        self.assertEqual(MACChanger.validate_mac('001122334455'),
                         '00:11:22:33:44:55')
        self.assertIsNone(MACChanger.validate_mac('nope'))


class TestGenerateRandom(unittest.TestCase):
    def test_generated_is_valid(self):
        mac = MACChanger.generate_random_mac()
        self.assertEqual(MACChanger.parse_mac(mac), mac)

    def test_generated_locally_administered(self):
        mac = MACChanger.generate_random_mac()
        first = int(mac.split(':')[0], 16)
        self.assertTrue(first & 0x02)

    def test_generated_unicast(self):
        mac = MACChanger.generate_random_mac()
        first = int(mac.split(':')[0], 16)
        self.assertFalse(first & 0x01)


class TestAnalyze(unittest.TestCase):
    def test_local_type(self):
        a = MACChanger().analyze_mac('02:00:00:00:00:01')
        self.assertEqual(a['type'], 'Locally Administered')
        self.assertTrue(a['locally_administered'])

    def test_oui_lookup(self):
        self.assertEqual(MACChanger.lookup_oui('08:00:27:AB:CD:EF'),
                         'Oracle VirtualBox')

    def test_invalid_returns_none(self):
        self.assertIsNone(MACChanger().analyze_mac('zz:00'))

    def test_unicast_flag(self):
        a = MACChanger().analyze_mac('00:11:22:33:44:55')
        self.assertTrue(a['unicast'])


class TestOfflineReport(unittest.TestCase):
    def test_ioctl_commands_layout(self):
        cmds = []
        out = []
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            ok = MACChanger.ioctl_commands('lab-eth0', '00:11:22:33:44:55')
        text = buf.getvalue()
        self.assertTrue(ok)
        self.assertIn('SIOCGIFFLAGS', text)
        self.assertIn('SIOCSIFHWADDR', text)
        self.assertIn('lab-eth0', text)

    def test_ioctl_invalid_mac(self):
        self.assertFalse(MACChanger.ioctl_commands('lab-eth0', 'bad'))

    def test_harness_exit_code_zero(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'mac_changer.py'), '--harness'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0)
        self.assertIn('[RESULT] PASS', r.stdout)


class TestGatekeepingLive(unittest.TestCase):
    def test_change_requires_live(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'mac_changer.py'),
             '--interface', 'lab-eth0', '--set', '00:11:22:33:44:55'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0)
        self.assertIn('dry-run', r.stdout)
        self.assertIn('--live', r.stdout)


if __name__ == '__main__':
    unittest.main()
