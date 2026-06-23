from __future__ import annotations

import unittest

from loopback_litmus.ports import parse_address_port, parse_lsof, parse_ss


class PortParserTests(unittest.TestCase):
    def test_parse_lsof_listener(self) -> None:
        output = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Python  1234 ilia    4u  IPv4  0xabc      0t0  TCP 127.0.0.1:18789 (LISTEN)
"""
        listeners = parse_lsof(output)
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0].bind_address, "127.0.0.1")
        self.assertEqual(listeners[0].port, 18789)
        self.assertEqual(listeners[0].process, "Python")
        self.assertEqual(listeners[0].pid, "1234")

    def test_parse_ss_listener(self) -> None:
        output = 'LISTEN 0 4096 0.0.0.0:8765 0.0.0.0:* users:(("python",pid=42,fd=3))\n'
        listeners = parse_ss(output)
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0].bind_address, "0.0.0.0")
        self.assertEqual(listeners[0].port, 8765)
        self.assertEqual(listeners[0].process, "python")
        self.assertEqual(listeners[0].pid, "42")

    def test_parse_address_port(self) -> None:
        self.assertEqual(parse_address_port("[::1]:9000"), ("::1", 9000))
        self.assertEqual(parse_address_port("*:9001"), ("0.0.0.0", 9001))


if __name__ == "__main__":
    unittest.main()
