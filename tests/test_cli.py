import unittest
from unittest.mock import patch

from phantom_eye.cli import _parse_neighbor_line, render_scan, render_table
from phantom_eye.scanner import ScanResult, parse_ports, validate_private_network


class NeighborParsingTests(unittest.TestCase):
    def test_parses_standard_line(self):
        device = _parse_neighbor_line("192.168.1.12 dev wlan0 lladdr AA:BB:CC:DD:EE:FF REACHABLE")
        self.assertEqual(device.ip, "192.168.1.12")
        self.assertEqual(device.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(device.interface, "wlan0")
        self.assertEqual(device.state, "REACHABLE")

    def test_ignores_non_ip_lines(self):
        self.assertIsNone(_parse_neighbor_line("Failed to send flush request: Invalid argument"))
        self.assertIsNone(_parse_neighbor_line("default dev eth0"))

    def test_rendering_does_not_leak_phone_data(self):
        device = _parse_neighbor_line("10.0.0.2 dev eth0 lladdr 00:11:22:33:44:55 STALE")
        output = render_table([device])
        self.assertIn("10.0.0.2", output)
        self.assertNotIn("phone", output.lower())


class ScannerSafetyTests(unittest.TestCase):
    def test_private_network_is_allowed(self):
        self.assertEqual(str(validate_private_network("192.168.1.0/30")), "192.168.1.0/30")

    def test_public_network_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_private_network("8.8.8.0/24")

    def test_large_network_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_private_network("10.0.0.0/8")

    def test_port_parser(self):
        self.assertEqual(parse_ports("443,22,443"), [22, 443])
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_scan_rendering(self):
        output = render_scan([ScanResult("192.168.1.2", 22, "ssh", "open")])
        self.assertIn("192.168.1.2", output)
        self.assertIn("ssh", output)


if __name__ == "__main__":
    unittest.main()
