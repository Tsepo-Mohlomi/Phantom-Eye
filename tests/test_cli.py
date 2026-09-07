import unittest
from unittest.mock import patch

from phantom_eye.cli import _parse_neighbor_line, render_table


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


if __name__ == "__main__":
    unittest.main()
