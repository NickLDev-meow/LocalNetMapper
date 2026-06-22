"""Unit tests for the pure-logic parts (no live network needed).

Run:  python -m pytest    (or python -m unittest)
"""
from __future__ import annotations

import struct
import unittest

from netmapper import engine, identify, net, probes, scanner
from netmapper.engine import Engine
from netmapper.net import Device


class TestArpParsing(unittest.TestCase):
    SAMPLE = """
Interface: 10.0.0.8 --- 0xb
  Internet Address      Physical Address      Type
  10.0.0.1              c8-9e-43-50-53-51     dynamic
  10.0.0.10             68-fe-71-59-83-dc     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
"""

    def test_parses_real_devices_only(self):
        table = net.parse_arp(self.SAMPLE)
        self.assertEqual(table["10.0.0.1"], "c8:9e:43:50:53:51")   # normalized
        self.assertEqual(table["10.0.0.10"], "68:fe:71:59:83:dc")
        self.assertNotIn("224.0.0.22", table)        # multicast filtered
        self.assertNotIn("255.255.255.255", table)   # broadcast filtered


class TestOui(unittest.TestCase):
    def test_multicast_and_randomized_detection(self):
        # 0x01 in the first octet => multicast; 0x02 => locally administered.
        self.assertEqual(identify.lookup("01:00:5e:00:00:16"), "Multicast")
        self.assertEqual(identify.lookup("22:54:bb:0c:34:51"), "Randomized / private MAC")

    def test_universal_prefix_resolves_to_a_name(self):
        # Universally-administered MAC: resolves to a vendor when the full DB is
        # present, else 'Unknown'; either way a non-empty, non-special string.
        v = identify.lookup("08:00:27:ab:cd:ef")
        self.assertTrue(v)
        self.assertNotIn(v, ("Multicast", "Randomized / private MAC"))

    def test_none_mac(self):
        self.assertIsNone(identify.lookup(None))


class TestRoleGuess(unittest.TestCase):
    def test_roles(self):
        self.assertEqual(net.guess_role([53, 80], True), "Router / Gateway")
        self.assertEqual(net.guess_role([9100], False), "Printer")
        self.assertEqual(net.guess_role([445, 139, 3389], False), "Windows PC")
        self.assertEqual(net.guess_role([22], False), "Linux / SSH device")
        self.assertEqual(net.guess_role([], False), "Host (no common ports open)")


class TestIPv6(unittest.TestCase):
    SAMPLE = """
Interface 11: Ethernet

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::3625:beff:fe1c:dead                     34-25-be-1c-de-ad  Reachable
fe80::dead:beef                               11-22-33-44-55-66  Stale
ff02::1                                       33-33-00-00-00-01  Permanent
fe80::1                                       c8-9e-43-50-53-51  Reachable (Router)
"""

    def test_parse_neighbors(self):
        r = probes._parse(self.SAMPLE)
        self.assertEqual(r["fe80::3625:beff:fe1c:dead"], "34:25:be:1c:de:ad")  # reachable
        self.assertEqual(r["fe80::1"], "c8:9e:43:50:53:51")   # router (reachable) kept
        self.assertNotIn("fe80::dead:beef", r)                 # STALE filtered (the bug fix)
        self.assertNotIn("ff02::1", r)                         # multicast filtered

    def test_device_sort_key_handles_ipv6(self):
        v4 = Device(ip="10.0.0.5")
        v6 = Device(ip="fe80::abcd")
        self.assertLess(v4.sort_key(), v6.sort_key())          # IPv4 sorts first, no crash


class TestStaleGhost(unittest.TestCase):
    def test_stale_unresponsive_is_ghost(self):
        d = Device(ip="10.0.0.4", mac="22:54:bb:0c:34:51", vendor="Randomized / private MAC")
        self.assertTrue(scanner.is_stale_ghost(d, "stale"))

    def test_reachable_is_not_ghost(self):
        d = Device(ip="10.0.0.5", mac="62:ca:3d:0e:ba:c1")
        self.assertFalse(scanner.is_stale_ghost(d, "reachable"))

    def test_responsive_is_never_ghost(self):
        # Even if state is 'stale', a host that answered ping is real (not a ghost).
        d = Device(ip="10.0.0.7", responded_ping=True)
        self.assertFalse(scanner.is_stale_ghost(d, "stale"))
        # And a firewalled-but-present Windows PC (has SMB open) is never a ghost.
        d2 = Device(ip="10.0.0.8", open_ports=[445], os_family="Windows")
        self.assertFalse(scanner.is_stale_ghost(d2, "stale"))


class TestSolicit(unittest.TestCase):
    def test_ssdp_payload(self):
        self.assertIn(b"M-SEARCH", probes._SSDP_MSEARCH)
        self.assertIn(b"ssdp:discover", probes._SSDP_MSEARCH)

    def test_wsd_payload(self):
        p = probes._WSD_PROBE.format(uuid="abc")
        self.assertIn("discovery/Probe", p)
        self.assertIn("urn:uuid:abc", p)


class TestOsGuess(unittest.TestCase):
    def test_ttl_buckets(self):
        self.assertEqual(net.os_guess(128), "Windows")
        self.assertEqual(net.os_guess(127), "Windows")    # one router hop
        self.assertEqual(net.os_guess(64), "Linux/Apple/Android")
        self.assertEqual(net.os_guess(255), "Network device")
        self.assertEqual(net.os_guess(None), "")


class TestNetbios(unittest.TestCase):
    def test_parses_workstation_name(self):
        # Craft a minimal NBSTAT response carrying one unique name "WORKPC".
        header = struct.pack(">HHHHHH", 0x4A4B, 0x8400, 0, 1, 0, 0)
        rr = probes._encode_nb_name("*") + struct.pack(">HHIH", 0x0021, 0x0001, 0, 0)
        body = bytes([1]) + b"WORKPC".ljust(15, b" ") + bytes([0x00]) + struct.pack(">H", 0x0400)
        self.assertEqual(probes.parse_nbstat(header + rr + body), "WORKPC")

    def test_garbage_returns_none(self):
        self.assertIsNone(probes.parse_nbstat(b"\x00\x01\x02"))


class TestFingerprint(unittest.TestCase):
    def test_gateway(self):
        d = Device(ip="10.0.0.1", is_gateway=True, vendor="NETGEAR")
        dtype, conf, _ = identify.classify(d)
        self.assertEqual(dtype, "Router / Gateway")
        self.assertGreaterEqual(conf, 90)

    def test_apple_via_services(self):
        d = Device(ip="10.0.0.20", vendor="Randomized / private MAC")
        dtype, conf, ev = identify.classify(d, services={"_airplay._tcp.local"})
        self.assertEqual(dtype, "Apple device")
        self.assertTrue(any("AirPlay" in e for e in ev))

    def test_iot_via_vendor(self):
        d = Device(ip="10.0.0.10", vendor="Espressif Inc.")
        dtype, _conf, _ = identify.classify(d)
        self.assertIn("IoT", dtype)

    def test_windows_via_ports_and_ttl(self):
        d = Device(ip="10.0.0.8", vendor="ASUSTek", os_family="Windows", open_ports=[139, 445, 3389])
        dtype, conf, _ = identify.classify(d)
        self.assertEqual(dtype, "Windows PC")
        self.assertGreater(conf, 50)

    def test_anonymized_silent_device(self):
        # A randomized MAC with no ports/name could be a phone OR a firewalled PC,
        # so it gets a neutral "firewalled device" label, not "mobile".
        d = Device(ip="10.0.0.4", vendor="Randomized / private MAC")
        dtype, _c, _ = identify.classify(d)
        self.assertIn("firewalled", dtype.lower())

    def test_silent_randomized_mac_windows_ttl(self):
        # Same silence but TTL says Windows -> name it a firewalled Windows PC.
        d = Device(ip="10.0.0.9", vendor="Randomized / private MAC", os_family="Windows")
        dtype, _c, _ = identify.classify(d)
        self.assertIn("Windows PC", dtype)

    def test_apple_ios_via_lockdownd_port(self):
        # Port 62078 (iOS lockdownd) -> a randomized-MAC device is identified as Apple.
        d = Device(ip="10.0.0.4", vendor="Randomized / private MAC", open_ports=[62078])
        dtype, conf, ev = identify.classify(d)
        self.assertEqual(dtype, "Apple iPhone/iPad")
        self.assertTrue(any("62078" in e for e in ev))


class TestMonitor(unittest.TestCase):
    def _fresh(self):
        return {"devices": {}, "ip_mac": {}}

    def test_new_then_ip_change(self):
        state = self._fresh()
        d = Device(ip="10.0.0.50", mac="aa:bb:cc:dd:ee:ff", vendor="Acme", device_type="Windows PC")
        ev = engine.diff_and_update(state, [d], "t1")
        self.assertEqual(ev[0]["type"], "NEW")
        moved = Device(ip="10.0.0.51", mac="aa:bb:cc:dd:ee:ff", vendor="Acme")
        ev = engine.diff_and_update(state, [moved], "t2")
        self.assertTrue(any(e["type"] == "IP_CHANGED" for e in ev))

    def test_mac_conflict(self):
        state = {"devices": {}, "ip_mac": {"10.0.0.7": "aa:aa:aa:aa:aa:aa"}}
        d = Device(ip="10.0.0.7", mac="bb:bb:bb:bb:bb:bb")
        ev = engine.diff_and_update(state, [d], "t")
        self.assertTrue(any(e["type"] == "MAC_CONFLICT" for e in ev))

    def test_no_false_ip_change_ipv4_to_ipv6(self):
        # Regression: a phone disconnects (loses IPv4) but a lingering IPv6 entry
        # remains -> must NOT fire IP_CHANGED, and the record keeps its IPv4.
        state = self._fresh()
        mac = "aa:bb:cc:dd:ee:ff"
        engine.diff_and_update(state, [Device(ip="10.0.0.5", mac=mac)], "t1")
        ev = engine.diff_and_update(state, [Device(ip="fe80::abcd", mac=mac)], "t2")
        self.assertFalse(any(e["type"] == "IP_CHANGED" for e in ev))
        self.assertEqual(state["devices"][mac]["ip"], "10.0.0.5")   # IPv4 preserved

    def test_fingerprint_history_accumulates(self):
        # Caught once with a port + strong ID, then goes silent: the record must
        # remember the richer fingerprint (so the UI can still show what it is).
        state = self._fresh()
        mac = "22:54:bb:0c:34:51"
        d1 = Device(ip="10.0.0.4", mac=mac, vendor="Randomized / private MAC",
                    open_ports=[62078], device_type="Apple iPhone/iPad", confidence=75)
        engine.diff_and_update(state, [d1], "2026-06-20 18:00:00")
        d2 = Device(ip="10.0.0.4", mac=mac, vendor="Randomized / private MAC",
                    device_type="Firewalled device", confidence=40)
        engine.diff_and_update(state, [d2], "2026-06-20 18:30:00")
        rec = state["devices"][mac]
        self.assertEqual(rec["ever_ports"], [62078])            # remembered the port
        self.assertEqual(rec["ever_type"], "Apple iPhone/iPad")  # kept the stronger ID
        self.assertEqual(rec["ever_confidence"], 75)
        self.assertEqual(rec["enriched_at"], "2026-06-20 18:00:00")

    def test_rejoined_after_absence(self):
        state = self._fresh()
        d = Device(ip="10.0.0.50", mac="aa:bb:cc:dd:ee:ff", device_type="Windows PC")
        key = "aa:bb:cc:dd:ee:ff"
        engine.diff_and_update(state, [d], "t1")            # NEW; now known + present
        known = set(state["devices"])
        # Round where it's absent (prev_keys had it, cur is empty) -> GONE.
        gone = engine.presence_events(state, [], {key}, known, first=False)
        self.assertTrue(any(e["type"] == "GONE" for e in gone))
        # Round where it returns (prev_keys empty, it reappears) -> REJOINED.
        engine.diff_and_update(state, [d], "t2")
        back = engine.presence_events(state, [d], set(), known, first=False)
        self.assertTrue(any(e["type"] == "REJOINED" for e in back))


class TestEngineThreads(unittest.TestCase):
    def _engine(self):
        import ipaddress

        def fake_scan():
            return (ipaddress.ip_network("10.0.0.0/24"),
                    [Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff", is_gateway=True)])
        return Engine(fake_scan, interval=99, state_path="_t_unused.json")

    def test_merge_fuses_passive_only_device(self):
        eng = self._engine()
        passive_seen = {"10.0.0.9": {"names": {"iPhone.local"}, "services": set(),
                                     "protocols": {"mdns"}, "info": set()}}
        merged = eng._merged([Device(ip="10.0.0.1")], passive_seen)
        ips = {d.ip for d in merged}
        self.assertIn("10.0.0.9", ips)   # a device only heard passively still shows up

    def test_stop_event_ends_passive_loop(self):
        import threading
        eng = self._engine()
        t = threading.Thread(target=eng.passive_loop)
        t.start()
        eng.stop.set()
        t.join(timeout=3)
        self.assertFalse(t.is_alive())   # one stop signal cleanly ends the thread


class TestDnsMsg(unittest.TestCase):
    def test_reverse_name(self):
        self.assertEqual(probes.reverse_name("10.0.0.8"), "8.0.0.10.in-addr.arpa")

    def test_parses_ptr_answer_with_compression(self):
        # Build a response: question for 8.0.0.10.in-addr.arpa PTR, answer points
        # (via a compression pointer) to a name "iPhone.local".
        header = struct.pack(">HHHHHH", 0x1234, 0x8000, 1, 1, 0, 0)
        qname = probes.encode_name("8.0.0.10.in-addr.arpa")
        question = qname + struct.pack(">HH", probes.PTR, probes.IN)
        target = probes.encode_name("iPhone.local")
        rdata = target
        answer = (b"\xc0\x0c"                                  # name -> ptr to qname at offset 12
                  + struct.pack(">HHIH", probes.PTR, probes.IN, 120, len(rdata))
                  + rdata)
        resp = header + question + answer
        parsed = probes.parse_answers(resp)
        self.assertIn((probes.PTR, "iPhone.local"), parsed)


class TestPassive(unittest.TestCase):
    def _a_record(self):
        header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        rr = (probes.encode_name("iPhone.local")
              + struct.pack(">HHIH", probes.A, probes.IN, 120, 4) + bytes([10, 0, 0, 9]))
        return header + rr

    def test_parse_records_extracts_a_record_name(self):
        recs = probes.parse_records(self._a_record())
        self.assertIn(("iPhone.local", probes.A, "10.0.0.9"), recs)

    def test_harvest_mdns_name(self):
        rec = {"names": set(), "services": set(), "protocols": set(), "info": set()}
        probes._harvest_dns(self._a_record(), rec)
        self.assertIn("iPhone.local", rec["names"])

    def test_harvest_ssdp_server(self):
        rec = {"names": set(), "services": set(), "protocols": set(), "info": set()}
        ssdp = b"NOTIFY * HTTP/1.1\r\nSERVER: Linux UPnP/1.0 MyPlug/2.0\r\nNT: upnp:rootdevice\r\n\r\n"
        probes._harvest_ssdp(ssdp, rec)
        self.assertTrue(any("MyPlug" in i for i in rec["info"]))


class TestRouting(unittest.TestCase):
    SAMPLE = """
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.0.0.1        10.0.0.8     25
        10.0.0.0    255.255.255.0         On-link         10.0.0.8    281
        10.0.0.8  255.255.255.255         On-link         10.0.0.8    281
      10.0.0.255  255.255.255.255         On-link         10.0.0.8    281
       127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
       224.0.0.0        240.0.0.0         On-link         10.0.0.8    281
===========================================================================
"""

    def test_real_gateway_not_assumed_dot1(self):
        rows = net._parse_route_table(self.SAMPLE)
        self.assertEqual(net._gateway_from_routes(rows, "10.0.0.8"), "10.0.0.1")

    def test_real_subnet_prefix(self):
        rows = net._parse_route_table(self.SAMPLE)
        self.assertEqual(net._prefix_from_routes(rows, "10.0.0.8"), 24)   # not assumed

    def test_detects_non_24_subnet(self):
        rows = [("10.0.0.0", "255.255.254.0", "On-link", "10.0.0.8")]     # a /23
        self.assertEqual(net._prefix_from_routes(rows, "10.0.0.8"), 23)

    def test_gateway_on_254(self):
        rows = [("0.0.0.0", "0.0.0.0", "192.168.1.254", "192.168.1.50")]  # router on .254
        self.assertEqual(net._gateway_from_routes(rows, "192.168.1.50"), "192.168.1.254")


class TestSelfDeclared(unittest.TestCase):
    def test_ssdp_location_extraction(self):
        resp = (b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n"
                b"LOCATION: http://10.0.0.20:8060/dial/dd.xml\r\nUSN: uuid:x\r\n\r\n")
        locs = probes.ssdp_locations({"10.0.0.20": resp})
        self.assertEqual(locs["10.0.0.20"], "http://10.0.0.20:8060/dial/dd.xml")

    def test_parse_upnp_xml(self):
        xml = (b'<?xml version="1.0"?>'
               b'<root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
               b'<friendlyName>Living Room TV</friendlyName>'
               b'<manufacturer>Samsung</manufacturer>'
               b'<modelName>UE55MU7000</modelName></device></root>')
        info = probes.parse_upnp(xml)
        self.assertEqual(info["name"], "Living Room TV")
        self.assertEqual(info["model"], "Samsung UE55MU7000")

    def test_mdns_txt_model(self):
        # md=Chromecast is the device's own declared model
        self.assertEqual(probes._model_from_txt({"id": "abc", "md": "Chromecast", "ve": "05"}),
                         "Chromecast")
        self.assertEqual(probes._model_from_txt({"ty": "HP OfficeJet Pro 8600"}),
                         "HP OfficeJet Pro 8600")
        self.assertEqual(probes._model_from_txt({"foo": "bar"}), "")

    def test_self_declared_model_wins(self):
        d = Device(ip="10.0.0.20", vendor="Randomized / private MAC", model="Sonos One")
        dtype, conf, ev = identify.classify(d)
        self.assertEqual(dtype, "Sonos One")
        self.assertGreaterEqual(conf, 80)


class TestSnapshot(unittest.TestCase):
    def test_snapshot_shape(self):
        eng = Engine(lambda: None, interval=99, state_path="_t_unused.json", do_passive=False)
        eng.devices = [Device(ip="10.0.0.1", vendor="NETGEAR", is_gateway=True,
                              device_type="Router / Gateway", confidence=99, open_ports=[80])]
        eng.net = "10.0.0.0/24"
        snap = eng.snapshot()
        self.assertEqual(snap["stats"]["devices"], 1)
        self.assertEqual(snap["devices"][0]["type"], "Router / Gateway")
        self.assertIn("backend", snap)
        self.assertEqual(snap["devices"][0]["open_ports"], [80])   # raw ports surfaced


class TestPortInfo(unittest.TestCase):
    def test_service_names(self):
        self.assertEqual(identify.service(445), "SMB")
        self.assertEqual(identify.service(22), "SSH")
        self.assertEqual(identify.label(3389), "3389/RDP")
        self.assertTrue(identify.service(65000).startswith("port"))  # unknown falls back

    def test_notable_flagging(self):
        self.assertTrue(identify.is_notable(23))      # Telnet
        self.assertTrue(identify.is_notable(445))     # SMB
        self.assertTrue(identify.is_notable(3389))    # RDP
        self.assertTrue(identify.is_notable(6379))    # Redis
        self.assertFalse(identify.is_notable(443))    # HTTPS is normal
        self.assertFalse(identify.is_notable(53))     # DNS is normal

    def test_summarize(self):
        s = identify.summarize([80, 445, 443, 445])   # dupes collapse
        self.assertEqual(s["count"], 3)
        self.assertEqual(s["ports"], [80, 443, 445])
        notable_ports = [p for p, _, _ in s["notable"]]
        self.assertEqual(notable_ports, [445])
        self.assertIn("web", s["categories"])
        self.assertIn("file", s["categories"])

    def test_summarize_empty(self):
        s = identify.summarize([])
        self.assertEqual(s["count"], 0)
        self.assertEqual(s["notable"], [])

    def test_clean_banner(self):
        self.assertEqual(identify.clean_banner("Server: nginx/1.18.0"), "nginx/1.18.0")
        self.assertEqual(identify.clean_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu"),
                         "SSH-2.0-OpenSSH_8.2p1 Ubuntu")
        self.assertEqual(identify.clean_banner(""), "")
        self.assertEqual(identify.clean_banner(None), "")
        self.assertTrue(identify.clean_banner("x" * 80).endswith("…"))


if __name__ == "__main__":
    unittest.main()
