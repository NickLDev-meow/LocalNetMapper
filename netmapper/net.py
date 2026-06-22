"""Network helpers and the Device data model.

Subnet math, ping (with TTL), ARP and IPv6 neighbor tables, reverse DNS, a
TCP-connect port scan, banner grabbing and role inference. Standard library
only; shells out to the OS ping/arp, so it runs without elevation.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from typing import Any

_IS_WINDOWS = platform.system().lower().startswith("win")

# MACs that are never real, individual devices - filter these out of results.
_NON_DEVICE_MAC = re.compile(r"^(ff-ff-ff-ff-ff-ff|00-00-00-00-00-00|01-00-5e|33-33|ff:ff)", re.I)


# --------------------------------------------------------------------------
# The data model produced by the scanner and consumed by the engine/UI.
# --------------------------------------------------------------------------
@dataclass
class Device:
    ip: str
    ipv6: list[str] = field(default_factory=list)   # link-local/global IPv6 neighbor addrs
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    name_source: str = ""        # how the name was found: dns / netbios / mdns / llmnr / local
    open_ports: list[int] = field(default_factory=list)
    role: str = "Unknown"
    os_family: str = ""          # inferred from ping TTL: Windows / Linux/Apple/Android / ...
    discovery: str = ""          # how the host was found: ping / arp / tcp / self
    device_type: str = ""        # multi-signal fingerprint, e.g. "Apple device"
    confidence: int = 0          # 0-99 confidence in device_type
    services: list[str] = field(default_factory=list)  # advertised mDNS services
    model: str = ""              # self-declared model (UPnP description / mDNS TXT)
    banners: dict[int, str] = field(default_factory=dict)  # port -> service banner/version
    evidence: list[str] = field(default_factory=list)  # why we classified it so
    is_gateway: bool = False
    is_self: bool = False
    responded_ping: bool = False
    stale: bool = False          # a lingering ARP-cache ghost, not actively present

    def sort_key(self):
        """Sort IPv4 numerically and first; IPv6-only devices sort after, by text."""
        parts = self.ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return (0,) + tuple(int(o) for o in parts)
        return (1, self.ip)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Host / subnet helpers.
# --------------------------------------------------------------------------
def local_ipv4() -> str:
    """Best-effort local IPv4. Uses a UDP socket to a public IP - no packets are
    actually sent; it just makes the OS pick the outbound interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def local_ips() -> set[str]:
    """All IPv4 addresses belonging to this machine (across adapters), so we can
    filter our own interfaces (e.g. a VirtualBox host-only adapter) out of
    passive captures and scans."""
    ips = {local_ipv4()}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    # `arp -a` prints an "Interface: <ip> --- 0x.." header per local adapter -
    # a reliable way to catch every interface, including VM/host-only ones.
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
        for m in re.finditer(r"Interface:\s*(\d{1,3}(?:\.\d{1,3}){3})", out):
            ips.add(m.group(1))
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ips


def default_network(prefix: int | None = None) -> ipaddress.IPv4Network:
    """The network containing this host. Reads the real subnet mask from the
    routing table (so a /23 or /25 is scanned correctly), not a hardcoded /24."""
    ip = local_ipv4()
    if prefix is None:
        prefix = local_prefix()
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def hosts_in(network: str | ipaddress.IPv4Network) -> list[str]:
    """Return the list of host addresses to scan for a CIDR like '10.0.0.0/24'."""
    net = ipaddress.ip_network(str(network), strict=False)
    return [str(h) for h in net.hosts()]


def gateway_guess(network: ipaddress.IPv4Network) -> str:
    """Conventional gateway: the first usable address (e.g. x.x.x.1). Fallback
    only - default_gateway() reads the real one from the routing table."""
    return str(next(network.hosts()))


# --- Real subnet mask + default gateway, read from the OS routing table ----
def _looks_ipv4(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _route_print() -> str:
    if not _IS_WINDOWS:
        return ""
    try:
        return subprocess.run(["route", "print", "-4"], capture_output=True,
                              text=True, timeout=10).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _parse_route_table(text: str) -> list[tuple[str, str, str, str]]:
    """Pull (destination, netmask, gateway, interface) rows out of `route print`.
    Language-independent: it keys off the numeric IPv4 columns, not labels."""
    rows = []
    for line in text.splitlines():
        toks = line.split()
        if len(toks) == 5 and _looks_ipv4(toks[0]) and _looks_ipv4(toks[1]) and _looks_ipv4(toks[3]):
            rows.append((toks[0], toks[1], toks[2], toks[3]))
    return rows


def _gateway_from_routes(rows, my_ip: str) -> str | None:
    """The default route's gateway (preferring the one on our own interface)."""
    for dest, mask, gw, iface in rows:
        if dest == "0.0.0.0" and mask == "0.0.0.0" and iface == my_ip and _looks_ipv4(gw):
            return gw
    for dest, mask, gw, iface in rows:
        if dest == "0.0.0.0" and mask == "0.0.0.0" and _looks_ipv4(gw):
            return gw
    return None


def _prefix_from_routes(rows, my_ip: str) -> int | None:
    """The prefix length of the on-link subnet route that contains our IP."""
    try:
        me = ipaddress.ip_address(my_ip)
    except ValueError:
        return None
    best = None
    for dest, mask, _gw, iface in rows:
        if dest == "0.0.0.0" or iface != my_ip:
            continue
        try:
            netw = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
        except ValueError:
            continue
        if netw.prefixlen >= 31 or netw.is_multicast or netw.is_loopback:
            continue
        if me in netw and (best is None or netw.prefixlen > best.prefixlen):
            best = netw
    return best.prefixlen if best else None


def default_gateway() -> str | None:
    """The real default gateway IP from the routing table, or None."""
    return _gateway_from_routes(_parse_route_table(_route_print()), local_ipv4())


def local_prefix(floor: int = 22) -> int:
    """The real subnet prefix length, falling back to /24. Clamped so an unusually
    large subnet (e.g. a /16) can't trigger a 65k-host sweep; pass an explicit
    network on the CLI to scan a bigger range deliberately."""
    p = _prefix_from_routes(_parse_route_table(_route_print()), local_ipv4())
    if p is None:
        return 24
    return max(p, floor)


# --------------------------------------------------------------------------
# Ping / OS guess.
# --------------------------------------------------------------------------
def ping_ttl(ip: str, timeout_ms: int = 600) -> tuple[bool, int | None]:
    """Ping once; return (alive, ttl). The TTL of the reply hints at the OS
    family (see os_guess). Uses the OS ping so it needs no elevation."""
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        secs = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(secs), ip]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=(timeout_ms / 1000) + 2)
    except (subprocess.TimeoutExpired, OSError):
        return False, None
    if res.returncode != 0:
        return False, None
    ttl_m = re.search(r"ttl[=:](\d+)", res.stdout, re.I)
    # Windows `ping` can return 0 on "Destination host unreachable"; a real reply
    # always carries a TTL, so its absence means no genuine answer.
    if _IS_WINDOWS and not ttl_m:
        return False, None
    return True, (int(ttl_m.group(1)) if ttl_m else None)


def ping(ip: str, timeout_ms: int = 600) -> bool:
    """Return True if the host answers a single ping."""
    return ping_ttl(ip, timeout_ms)[0]


def os_guess(ttl: int | None) -> str:
    """Infer the OS family from a reply TTL. Default initial TTLs: Windows 128,
    Linux/Unix/Android 64, many network devices 255. We allow for a few router
    hops by bucketing rather than matching exactly."""
    if ttl is None:
        return ""
    if ttl <= 64:
        # 64 is the default for Linux, Android, and Apple (macOS/iOS are
        # Darwin/BSD-based) - i.e. everything that isn't Windows or net gear.
        return "Linux/Apple/Android"
    if ttl <= 128:
        return "Windows"
    return "Network device"


# --------------------------------------------------------------------------
# ARP / neighbor tables, local MAC, reverse DNS.
# --------------------------------------------------------------------------
def parse_arp(text: str) -> dict[str, str]:
    """Parse `arp -a` output into {ip: mac}, normalized to lower-case colon MACs
    and excluding broadcast/multicast pseudo-entries."""
    table: dict[str, str] = {}
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    mac_re = re.compile(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")
    for line in text.splitlines():
        ip_m = ip_re.search(line)
        mac_m = mac_re.search(line)
        if not (ip_m and mac_m):
            continue
        mac_raw = mac_m.group(1)
        if _NON_DEVICE_MAC.match(mac_raw):
            continue
        table[ip_m.group(1)] = mac_raw.replace("-", ":").lower()
    return table


def arp_table() -> dict[str, str]:
    """Run `arp -a` and parse it into {ip: mac}."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except (subprocess.TimeoutExpired, OSError):
        return {}
    return parse_arp(out)


def local_mac() -> str | None:
    """Best-effort MAC of this machine (your own IP isn't in your ARP table).
    `uuid.getnode()` returns a random value with the multicast bit set if it
    can't read a real one - we detect and reject that case."""
    node = uuid.getnode()
    if (node >> 40) & 0x01:   # multicast bit set => getnode() couldn't find a real MAC
        return None
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def neighbor_states() -> dict[str, str]:
    """Return {ip: reachability_state} from the OS neighbor table.

    States: reachable / stale / delay / probe / incomplete. A 'stale' entry that
    won't re-confirm is a ghost - e.g. a phone that rotated its MAC and left,
    leaving a lingering ARP cache entry. Distinguishing these from genuinely
    present devices stops phantom devices from inflating the count.
    """
    if not _IS_WINDOWS:
        return {}
    try:
        out = subprocess.run(["netsh", "interface", "ipv4", "show", "neighbors"],
                             capture_output=True, text=True, timeout=10).stdout
    except (subprocess.TimeoutExpired, OSError):
        return {}
    states: dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+[0-9a-fA-F-]{17}\s+(\w+)", line)
        if m:
            states[m.group(1)] = m.group(2).lower()
    return states


def reverse_dns(ip: str) -> str | None:
    """Reverse-DNS lookup; returns None if there's no PTR record (common on LANs)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# --------------------------------------------------------------------------
# TCP port scan + banner grab + role inference.
# --------------------------------------------------------------------------
# Service ports that help identify a device's role.
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 515: "Printer-LPD", 554: "RTSP", 631: "IPP",
    1900: "UPnP", 3389: "RDP", 5000: "UPnP/HTTP", 5353: "mDNS", 7000: "AirPlay",
    8008: "Cast", 8009: "Cast", 8060: "Roku", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9100: "JetDirect", 32400: "Plex", 62078: "iOS-lockdownd",
}

# Ports checked to decide a host is "alive" when it blocks ping (Windows PCs
# typically expose some of these even with the firewall on).
LIVENESS_PORTS = [445, 139, 135, 3389, 22, 80, 443]

# A wider, well-known top-ports list used by the intensive scan - catches
# services the quick COMMON_PORTS pass misses.
INTENSIVE_PORTS = sorted(set(COMMON_PORTS) | {
    1, 3, 7, 9, 13, 17, 19, 25, 26, 37, 79, 81, 88, 106, 110, 111, 113, 119, 135,
    143, 144, 179, 199, 389, 427, 444, 465, 513, 514, 543, 544, 548, 587, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
    1755, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3986, 4899, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8001, 8081, 8200, 8888, 9999, 10000, 32768, 32400, 49152, 49153, 49154,
    49155, 49156, 49157, 62078,
})


def tcp_alive(ip: str, ports: list[int] | None = None, timeout: float = 0.4) -> int | None:
    """Return the first open liveness port (host is up), or None. Stops at the
    first success so a responsive host is detected quickly."""
    for port in (ports if ports is not None else LIVENESS_PORTS):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                if s.connect_ex((ip, port)) == 0:
                    return port
            except OSError:
                pass
    return None


def scan_ports(ip: str, ports: list[int] | None = None, timeout: float = 0.4) -> list[int]:
    """Return the sorted list of open TCP ports on `ip` from the probe set."""
    probe = ports if ports is not None else list(COMMON_PORTS)

    def check(port: int) -> int | None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                if s.connect_ex((ip, port)) == 0:
                    return port
            except OSError:
                return None
        return None

    with ThreadPoolExecutor(max_workers=min(32, len(probe))) as ex:
        found = [p for p in ex.map(check, probe) if p is not None]
    return sorted(found)


def grab_banner(ip: str, port: int, timeout: float = 0.8) -> str | None:
    """Connect to an open port and read a short banner for fingerprinting.
    For HTTP ports we send a HEAD request to elicit the Server header; SSH/FTP/
    Telnet announce themselves on connect. Returns a cleaned one-line string."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            if port in (80, 8080, 8000, 5000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n")
            try:
                raw = s.recv(512)
            except socket.timeout:
                return None
    except OSError:
        return None
    if not raw:
        return None
    text = raw.decode("latin-1", "replace")
    # For HTTP, pull just the Server header if present.
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            return line.strip()
    return text.splitlines()[0].strip() if text.strip() else None


def guess_role(open_ports: list[int], is_gateway: bool) -> str:
    """Infer a human-friendly device role from its open ports."""
    s = set(open_ports)
    if is_gateway:
        return "Router / Gateway"
    if {9100, 515, 631} & s:
        return "Printer"
    if 32400 in s:
        return "Media server (Plex)"
    if {445, 139} & s and 3389 in s:
        return "Windows PC"
    if {445, 139} & s:
        return "Windows / file share"
    if 22 in s:
        return "Linux / SSH device"
    if {80, 443, 8080, 8443, 5000} & s:
        return "Web device / IoT"
    if {1900, 5353} & s:
        return "IoT / media device"
    if not s:
        return "Host (no common ports open)"
    return "Unknown"
