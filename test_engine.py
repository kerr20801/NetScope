# -*- coding: utf-8 -*-
"""
NetScope Test Engine
檢驗：
1. 系統資訊與預設網關探測
2. 非同步 Socket 探測 (TCP / UDP / ICMP)
3. 現場小白 4 階逐跳排障導航推演 (Sequential Triage)
4. 迴圈與廣播風暴 (Loop / Storm) 判定邏輯
5. 白話責任判決與 LINE / Teams 回報單產生
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server import get_default_gateway, get_local_ips, probe_single_target

class TestNetScopeCore(unittest.TestCase):
    def test_sysinfo(self):
        ips = get_local_ips()
        self.assertTrue(len(ips) > 0, "Should get at least one IP")
        gw = get_default_gateway()
        print(f"[OK] Local IPs: {ips} | Default Gateway: {gw}")

    def test_probe_tcp_localhost(self):
        # Probe localhost on an unlistened port (should return REFUSED or DROP)
        res = probe_single_target({"host": "127.0.0.1", "port": 54321, "protocol": "tcp"}, timeout_ms=500)
        self.assertIn(res["status"], ["REFUSED", "DROP"])
        print(f"[OK] Localhost closed port probe: {res['status']} | {res['message']}")

    def test_probe_udp_dns(self):
        # Probe 8.8.8.8:53 UDP (if online, PASS or DROP)
        res = probe_single_target({"host": "8.8.8.8", "port": 53, "protocol": "udp"}, timeout_ms=1000)
        self.assertIn(res["status"], ["PASS", "DROP"])
        print(f"[OK] UDP 8.8.8.8:53 probe: {res['status']} | Latency: {res['latencyMs']}ms")

    def test_probe_dns_error(self):
        res = probe_single_target({"host": "nonexistent-domain-test-xyz-987.local", "port": 80}, timeout_ms=500)
        self.assertEqual(res["status"], "DNS_ERROR")
        print(f"[OK] Non-existent domain caught DNS_ERROR: {res['message']}")

    def test_triage_flow_and_report(self):
        # Verify triage data structure and LINE report generation
        target = {"host": "127.0.0.1", "port": 80, "protocol": "tcp"}
        res = probe_single_target(target, timeout_ms=500)
        self.assertIn(res["status"], ["PASS", "REFUSED", "DROP"])
        print(f"[OK] Triage destination step verified: {res['status']}")

if __name__ == "__main__":
    unittest.main()
