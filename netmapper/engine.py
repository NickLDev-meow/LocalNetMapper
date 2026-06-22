"""The live engine + change tracking.

Two cooperating halves:

  * monitoring - a persisted state file of every device ever seen (first/last
    seen, times seen), diffed each scan into change events:
        NEW / GONE / REJOINED / IP_CHANGED / MAC_CONFLICT / VENDOR_CHANGED
  * the Engine - runs active scanning AND passive listening together in
    background threads, fuses the results, and exposes the whole live state as a
    single `snapshot()` for the terminal UI to render. UI-agnostic: it produces
    data, the front-end draws it.
"""
from __future__ import annotations

import json
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path

from . import net, probes

DEFAULT_STATE = "netmapper_state.json"


# ==========================================================================
# Monitoring: persistent state + change diffing
# ==========================================================================
def _key(d) -> str:
    return d.mac or d.ip


def _is_ipv4(ip: str) -> bool:
    parts = (ip or "").split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_state(path: str | None) -> dict:
    if path:                                   # path=None -> in-memory only
        p = Path(path)
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    return {"devices": {}, "ip_mac": {}}


def save_state(path: str | None, state: dict) -> None:
    if not path:                               # in-memory only; nothing on disk
        return
    try:
        Path(path).write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError:
        pass


def _label(d) -> str:
    name = d.hostname or d.device_type or d.vendor or "device"
    return f"{d.ip} ({name})"


def _accumulate_history(rec: dict, d, now: str) -> None:
    """Remember the richest things we ever learned about a device, so a device
    that is silent now still shows what it revealed when it was chatty (e.g. an
    iPhone caught unlocked, or a laptop that was briefly on a Private profile)."""
    if d.open_ports:
        rec["ever_ports"] = sorted(set(rec.get("ever_ports", [])) | set(d.open_ports))
    if d.services:
        rec["ever_services"] = sorted(set(rec.get("ever_services", [])) | set(d.services))
    if d.hostname:
        rec["ever_hostname"] = d.hostname
    if d.os_family:
        rec["ever_os"] = d.os_family
    # keep the highest-confidence device type ever seen
    if d.device_type and d.confidence >= rec.get("ever_confidence", 0):
        rec["ever_type"] = d.device_type
        rec["ever_confidence"] = d.confidence
    # timestamp of the last time the device gave us a strong signal
    if d.open_ports or d.hostname:
        rec["enriched_at"] = now


def diff_and_update(state: dict, devices: list, now: str) -> list[dict]:
    """Fold this scan into the state, returning the change events it produced."""
    devs = state.setdefault("devices", {})
    ip_mac = state.setdefault("ip_mac", {})
    events: list[dict] = []

    for d in devices:
        k = _key(d)
        rec = devs.get(k)

        # Same IP, different MAC => possible spoofing.
        prior_mac = ip_mac.get(d.ip)
        if d.mac and prior_mac and prior_mac != d.mac:
            events.append({"type": "MAC_CONFLICT", "ip": d.ip,
                           "label": _label(d), "detail": f"{prior_mac} -> {d.mac}"})
        if d.mac:
            ip_mac[d.ip] = d.mac

        if rec is None:
            devs[k] = {"ip": d.ip, "mac": d.mac, "vendor": d.vendor,
                       "hostname": d.hostname, "device_type": d.device_type,
                       "first_seen": now, "last_seen": now, "times_seen": 1}
            events.append({"type": "NEW", "ip": d.ip, "label": _label(d),
                           "detail": d.device_type or "first seen"})
        else:
            # Only a same-family IP change is a real "IP changed" - an IPv4->IPv6
            # flip just means the device dropped IPv4 but a lingering IPv6 entry
            # remains (e.g. a phone that disconnected); never alarm on that.
            same_family = _is_ipv4(rec.get("ip", "")) == _is_ipv4(d.ip)
            if rec.get("ip") != d.ip and same_family:
                events.append({"type": "IP_CHANGED", "ip": d.ip, "label": _label(d),
                               "detail": f"{rec.get('ip')} -> {d.ip}"})
            if d.vendor and rec.get("vendor") and rec["vendor"] != d.vendor:
                events.append({"type": "VENDOR_CHANGED", "ip": d.ip, "label": _label(d),
                               "detail": f"{rec['vendor']} -> {d.vendor}"})
            # Keep an IPv4 primary; don't let it flip to an IPv6 address.
            if _is_ipv4(d.ip) or same_family:
                rec["ip"] = d.ip
            rec["last_seen"] = now
            rec["hostname"] = d.hostname or rec.get("hostname")
            rec["device_type"] = d.device_type or rec.get("device_type")
            rec["times_seen"] = rec.get("times_seen", 1) + 1

        _accumulate_history(devs[k], d, now)

    return events


def presence_events(state: dict, devices: list, prev_keys: set,
                    known_before: set, first: bool) -> list[dict]:
    """Detect GONE (present->absent) and REJOINED (absent->present-again) events
    by comparing this round's present set with the previous round's.

    `known_before` is the set of device keys known *before* this round's
    diff_and_update, so a reappearing device is told apart from a brand-new one.
    """
    if first:
        return []
    cur = {_key(d) for d in devices}
    by_key = {_key(d): d for d in devices}
    events: list[dict] = []
    for gone in prev_keys - cur:
        rec = state.get("devices", {}).get(gone, {})
        events.append({"type": "GONE", "ip": rec.get("ip", "?"),
                       "label": f"{rec.get('ip','?')} ({rec.get('hostname') or rec.get('device_type') or 'device'})",
                       "detail": f"last seen {rec.get('last_seen','?')}"})
    for k in cur - prev_keys:
        if k in known_before:          # known device that had been absent -> it's back
            d = by_key[k]
            events.append({"type": "REJOINED", "ip": d.ip, "label": _label(d),
                           "detail": "back online"})
    return events


# ==========================================================================
# The live engine
# ==========================================================================
def _ports_str(d) -> str:
    return ", ".join(f"{p}/{net.COMMON_PORTS.get(p, '?')}" for p in d.open_ports) or "-"


class Engine:
    """Runs active scanning AND passive listening together, fused into one live
    view, with a single stop event that cleanly ends every background thread."""

    def __init__(self, scan_fn, interval: int, state_path: str, do_passive: bool = True,
                 intensive: bool = False):
        self.scan_fn = scan_fn
        self.interval = interval
        self.state_path = state_path
        self.do_passive = do_passive
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.wake = threading.Event()      # set to trigger an immediate rescan
        self.base_intensive = intensive    # every scan intensive (from --intensive)
        self.intensive_once = False         # one-off intensive scan (from the 'i' key)
        self.scanning_intensive = False
        self.last_intensive = False
        self.devices: list = []
        self.events: list = []
        self.passive_seen: dict = {}
        self.net = ""
        self.last_scan = "never"
        self.scanning = False
        self.scan_count = 0
        self.state = load_state(state_path)
        self._prev_keys = set(self.state.get("devices", {}))
        self._mine = net.local_ips()
        self.active_thread = None
        self.passive_thread = None

    def start(self):
        """Start the background scan + passive-listen threads."""
        self.active_thread = threading.Thread(target=self.active_loop, daemon=True)
        self.active_thread.start()
        if self.do_passive:
            self.passive_thread = threading.Thread(target=self.passive_loop, daemon=True)
            self.passive_thread.start()

    def shutdown(self):
        """Signal the background threads to finish."""
        self.stop.set()
        self.wake.set()

    def request_rescan(self):
        """Wake the scanner to run a fresh scan immediately."""
        self.wake.set()

    def request_intensive(self):
        """Run a deep/intensive scan on the next cycle, now."""
        self.intensive_once = True
        self.wake.set()

    def _call_scan(self, intensive: bool):
        try:
            return self.scan_fn(intensive=intensive)
        except TypeError:                  # scan_fn without an intensive kwarg
            return self.scan_fn()

    def active_loop(self):
        first = True
        while not self.stop.is_set():
            intensive = self.base_intensive or self.intensive_once
            with self.lock:
                self.scanning = True
                self.scanning_intensive = intensive
            try:
                net_, devices = self._call_scan(intensive)
            except Exception as exc:
                # Keep the thread alive on a scan failure: record it as an event
                # and retry next cycle, rather than dying and wiping the screen.
                with self.lock:
                    self.scanning = False
                    self.scanning_intensive = False
                    self.events.insert(0, {"time": _now(), "type": "SCAN_ERROR",
                                           "label": "scan failed", "detail": str(exc)[:80]})
                    self.events = self.events[:80]
                self.intensive_once = False
                self.wake.wait(self.interval)
                self.wake.clear()
                continue
            now = _now()
            known_before = set(self.state.get("devices", {}))
            evs = diff_and_update(self.state, devices, now)
            evs += presence_events(self.state, devices, self._prev_keys, known_before, first)
            cur_keys = {_key(d) for d in devices}
            save_state(self.state_path, self.state)
            with self.lock:
                self.devices = devices
                self.net = str(net_)
                self.last_scan = now
                self.scanning = False
                for e in evs:
                    self.events.insert(0, {"time": now, **e})
                self.events = self.events[:80]
                self.last_intensive = intensive
                self.scanning_intensive = False
                self.scan_count += 1
            self.intensive_once = False
            self._prev_keys = cur_keys
            first = False
            self.wake.wait(self.interval)   # wakes early on stop or a rescan request
            self.wake.clear()

    def passive_loop(self):
        import select
        socks = probes.open_sockets()
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select(list(socks), [], [], 1.0)
                for s in ready:
                    try:
                        data, addr = s.recvfrom(8192)
                    except OSError:
                        continue
                    with self.lock:
                        probes._ingest(socks[s], data, addr[0], self.passive_seen)
        finally:
            for s in socks:
                s.close()

    def _merged(self, devices: list, passive_seen: dict) -> list:
        """Fuse active devices with passive captures (enrich + add passive-only)."""
        by_ip = {d.ip: d for d in devices}
        arp = net.arp_table() if passive_seen else {}
        for ip, rec in passive_seen.items():
            if ip in self._mine:
                continue
            if ip in by_ip:
                d = by_ip[ip]
                if not d.hostname and rec["names"]:
                    d.hostname = sorted(rec["names"])[0]
                    d.name_source = "passive"
                if rec["services"]:
                    d.services = sorted(set(d.services) | rec["services"])
            else:
                by_ip[ip] = probes.device_from_passive(ip, rec, arp)
        return sorted(by_ip.values(),
                      key=lambda d: tuple(int(o) for o in d.ip.split(".")) if d.ip.count(".") == 3 else (0,))

    def snapshot(self) -> dict:
        with self.lock:
            base = list(self.devices)
            passive_seen = {ip: {k: set(v) for k, v in rec.items()}
                            for ip, rec in self.passive_seen.items()}
            events = list(self.events)
            net_, last_scan, scanning = self.net, self.last_scan, self.scanning
            scan_count = self.scan_count
            scanning_intensive = self.scanning_intensive
            last_intensive = self.last_intensive
            history = {k: dict(v) for k, v in self.state.get("devices", {}).items()}
        devices = self._merged(base, passive_seen)
        os_counts = Counter(d.os_family for d in devices if d.os_family)
        via_counts = Counter(d.discovery for d in devices if d.discovery)
        dev_dicts = [self._with_history(self._dev(d), history) for d in devices]
        return {
            "scanning": scanning,
            "scanning_intensive": scanning_intensive,
            "last_intensive": last_intensive,
            "last_scan": last_scan,
            "scan_count": scan_count,
            "net": net_,
            "interval": self.interval,
            "passive": self.do_passive,
            "backend": {
                "active": bool(self.active_thread and self.active_thread.is_alive()),
                "passive": bool(self.passive_thread and self.passive_thread.is_alive()),
                "scanning": scanning,
            },
            "stats": {
                "devices": len(devices),
                "named": sum(1 for d in devices if d.hostname),
                "windows": sum(1 for d in devices if d.os_family == "Windows"),
                "anon": sum(1 for d in devices if (d.vendor or "").startswith("Randomized")),
                "stale": sum(1 for d in devices if d.stale),
                "os": dict(os_counts), "via": dict(via_counts),
            },
            "devices": dev_dicts,
            "events": events,
        }

    @staticmethod
    def _with_history(dd: dict, history: dict) -> dict:
        """Attach the persisted fingerprint history for this device (by MAC/IP)."""
        rec = history.get(dd["mac"] or dd["ip"], {})
        dd["hist"] = {
            "first_seen": rec.get("first_seen", ""),
            "last_seen": rec.get("last_seen", ""),
            "times_seen": rec.get("times_seen", 0),
            "ever_type": rec.get("ever_type", ""),
            "ever_confidence": rec.get("ever_confidence", 0),
            "ever_ports": rec.get("ever_ports", []),
            "ever_hostname": rec.get("ever_hostname", ""),
            "ever_os": rec.get("ever_os", ""),
            "enriched_at": rec.get("enriched_at", ""),
        }
        return dd

    @staticmethod
    def _dev(d) -> dict:
        return {
            "ip": d.ip, "mac": d.mac or "", "ipv6": d.ipv6, "vendor": d.vendor or "",
            "hostname": d.hostname or "", "name_source": d.name_source,
            "os": d.os_family, "type": d.device_type or d.role,
            "confidence": d.confidence, "via": d.discovery,
            "ports": _ports_str(d),
            "open_ports": list(d.open_ports),
            "banners": dict(d.banners),
            "anon": (d.vendor or "").startswith("Randomized"),
            "stale": d.stale,
            "self": d.is_self, "gateway": d.is_gateway,
            "evidence": "; ".join(d.evidence), "services": ", ".join(d.services),
        }
