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

    def test_parse_lsof_handles_wildcard_and_ipv6_listener_rows(self) -> None:
        output = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node     2468 ilia   18u  IPv4  0xabc      0t0  TCP *:6277 (LISTEN)
mcpd     3579 ilia    5u  IPv6  0xdef      0t0  TCP [::1]:7331 (LISTEN)
"""
        listeners = parse_lsof(output)

        self.assertEqual([listener.bind_address for listener in listeners], ["0.0.0.0", "::1"])
        self.assertEqual([listener.port for listener in listeners], [6277, 7331])
        self.assertEqual([listener.process for listener in listeners], ["node", "mcpd"])
        self.assertEqual([listener.pid for listener in listeners], ["2468", "3579"])

    def test_parse_ss_listener(self) -> None:
        output = 'LISTEN 0 4096 0.0.0.0:8765 0.0.0.0:* users:(("python",pid=42,fd=3))\n'
        listeners = parse_ss(output)
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0].bind_address, "0.0.0.0")
        self.assertEqual(listeners[0].port, 8765)
        self.assertEqual(listeners[0].process, "python")
        self.assertEqual(listeners[0].pid, "42")

    def test_parse_ss_handles_ipv6_missing_process_and_non_listen_rows(self) -> None:
        output = """LISTEN 0 4096 [::1]:7331 [::]:* users:(("node",pid=123,fd=9))
LISTEN 0 128 127.0.0.1:6277 0.0.0.0:*
ESTAB 0 0 127.0.0.1:5000 127.0.0.1:6000 users:(("curl",pid=44,fd=7))
"""
        listeners = parse_ss(output)

        self.assertEqual(len(listeners), 2)
        self.assertEqual(listeners[0].bind_address, "::1")
        self.assertEqual(listeners[0].port, 7331)
        self.assertEqual(listeners[0].process, "node")
        self.assertEqual(listeners[0].pid, "123")
        self.assertEqual(listeners[1].bind_address, "127.0.0.1")
        self.assertEqual(listeners[1].port, 6277)
        self.assertIsNone(listeners[1].process)
        self.assertIsNone(listeners[1].pid)

    def test_parse_address_port(self) -> None:
        self.assertEqual(parse_address_port("[::1]:9000"), ("::1", 9000))
        self.assertEqual(parse_address_port("[::]:9000"), ("0.0.0.0", 9000))
        self.assertEqual(parse_address_port("*:9001"), ("0.0.0.0", 9001))


if __name__ == "__main__":
    unittest.main()
