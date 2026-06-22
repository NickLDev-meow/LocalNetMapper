"""Wire-protocol discovery & naming - everything that speaks a protocol on the
network to find or name a device, active and passive.

  * dnsmsg            - a tiny DNS message encoder/decoder (shared by mDNS/LLMNR)
  * netbios_query     - NetBIOS node-status name lookup (names Windows PCs)
  * mdns/llmnr        - reverse-name resolution + an mDNS service sweep
  * ssdp/wsd probes   - active solicitation that makes hidden gear announce itself
  * ipv6_neighbors    - IPv6 neighbor discovery (find IPv4-invisible devices)
  * passive listening - join the multicast groups and harvest the chatter silently

All on the standard library, no admin required.
"""
from __future__ import annotations

import platform
import re
import socket
import struct
import subprocess
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from . import identify, net

# ==========================================================================
# DNS message codec (RFC 1035 / mDNS RFC 6762 / LLMNR RFC 4795)
# ==========================================================================
PTR = 12
A = 1
AAAA = 28
TXT = 16
SRV = 33
IN = 1


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii", "replace")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def build_query(qname: str, qtype: int = PTR, qclass: int = IN, txid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack(">HH", qtype, qclass)
    return header + question


def reverse_name(ip: str) -> str:
    """10.0.0.8 -> 8.0.0.10.in-addr.arpa (the reverse-DNS name)."""
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset),
    where next_offset is the position right after the name in the original
    stream (not where a compression pointer jumped to)."""
    labels: list[str] = []
    jumped = False
    next_offset = offset
    hops = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break
        if (length & 0xC0) == 0xC0:                 # compression pointer
            if not jumped:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumped = True
            hops += 1
            if hops > 50:                            # guard against pointer loops
                break
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), next_offset


def parse_answers(data: bytes) -> list[tuple[int, str]]:
    """Return [(rtype, value)] for each answer; PTR/A values decoded to text."""
    try:
        _txid, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            _, offset = parse_name(data, offset)
            offset += 4                              # qtype + qclass
        answers: list[tuple[int, str]] = []
        for _ in range(an):
            _name, offset = parse_name(data, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == PTR:
                target, _ = parse_name(data, offset)
                answers.append((PTR, target.rstrip(".")))
            elif rtype == A and rdlen == 4:
                answers.append((A, ".".join(str(b) for b in data[offset:offset + 4])))
            offset += rdlen
        return answers
    except (struct.error, IndexError):
        return []


def parse_records(data: bytes) -> list[tuple[str, int, object]]:
    """Parse ALL resource records (answer+authority+additional), returning
    (record_name, rtype, value). A/PTR values are strings; TXT values are a dict
    of the record's key=value pairs (where the device's model often lives)."""
    try:
        _id, _flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            _, offset = parse_name(data, offset)
            offset += 4
        out: list[tuple[str, int, object]] = []
        for _ in range(an + ns + ar):
            name, offset = parse_name(data, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            value: object = None
            if rtype == A and rdlen == 4:
                value = ".".join(str(b) for b in data[offset:offset + 4])
            elif rtype == PTR:
                value, _ = parse_name(data, offset)
                value = value.rstrip(".")
            elif rtype == TXT:
                value = _parse_txt(data[offset:offset + rdlen])
            out.append((name.rstrip("."), rtype, value))
            offset += rdlen
        return out
    except (struct.error, IndexError):
        return []


def _parse_txt(blob: bytes) -> dict[str, str]:
    """Decode a DNS TXT record (a run of length-prefixed strings) into a dict of
    its key=value pairs, lower-cased keys."""
    out: dict[str, str] = {}
    i = 0
    while i < len(blob):
        ln = blob[i]
        i += 1
        s = blob[i:i + ln].decode("utf-8", "replace")
        i += ln
        if "=" in s:
            k, v = s.split("=", 1)
            out[k.strip().lower()] = v
        elif s:
            out[s.strip().lower()] = ""
    return out


def _model_from_txt(txt: dict[str, str]) -> str:
    """Pull a device model/name out of mDNS TXT keys. 'ty'=printer type,
    'md'=Cast model, 'model'=generic, 'fn'/'name'=friendly name, 'am'=Apple model."""
    for key in ("ty", "md", "model", "fn", "name", "am"):
        v = (txt.get(key) or "").strip()
        if v:
            return v
    return ""


# ==========================================================================
# NetBIOS node-status name query (RFC 1002)
# ==========================================================================
NBSTAT = 0x0021
IN_CLASS = 0x0001


def _encode_nb_name(name: str = "*") -> bytes:
    """First-level encode a 16-byte NetBIOS name (RFC 1001 4.1). The node-status
    query uses the wildcard name '*' padded with NULs to 16 bytes."""
    raw = name.encode("ascii")[:16]
    raw = raw + b"\x00" * (16 - len(raw))
    encoded = bytearray()
    for b in raw:
        encoded.append((b >> 4) + ord("A"))
        encoded.append((b & 0x0F) + ord("A"))
    return bytes([len(encoded)]) + bytes(encoded) + b"\x00"


def netbios_query(ip: str, timeout: float = 1.0) -> str | None:
    """Return the host's NetBIOS computer name, or None if it doesn't answer."""
    header = struct.pack(">HHHHHH", 0x4A4B, 0x0000, 1, 0, 0, 0)
    question = _encode_nb_name("*") + struct.pack(">HH", NBSTAT, IN_CLASS)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    return parse_nbstat(data)


def parse_nbstat(data: bytes) -> str | None:
    """Extract the workstation name from an NBSTAT response."""
    try:
        _tid, _flags, qd, _an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        idx = 12
        # Skip any echoed questions.
        for _ in range(qd):
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1 + 4  # null + qtype + qclass
        # Answer RR: name, then type/class/ttl/rdlength.
        while data[idx] != 0:
            idx += data[idx] + 1
        idx += 1 + 2 + 2 + 4 + 2
        count = data[idx]
        idx += 1

        names: list[tuple[str, int, bool]] = []
        for _ in range(count):
            label = data[idx:idx + 15].decode("ascii", "replace").rstrip()
            suffix = data[idx + 15]
            flags = struct.unpack(">H", data[idx + 16:idx + 18])[0]
            idx += 18
            names.append((label, suffix, bool(flags & 0x8000)))   # group bit

        # The unique (non-group) name with suffix 0x00 is the workstation name.
        for label, suffix, is_group in names:
            if suffix == 0x00 and not is_group and label:
                return label
        return names[0][0] if names else None
    except (IndexError, struct.error):
        return None


# ==========================================================================
# mDNS (Bonjour) + LLMNR name resolution
# ==========================================================================
MDNS_GROUP = "224.0.0.251"      # standard mDNS multicast group
MDNS_PORT = 5353
LLMNR_PORT = 5355
# mDNS "QU" bit: ask the responder to reply unicast to us, not via multicast.
_MDNS_QUNICAST = 0x8000


def _first_ptr(data: bytes) -> str | None:
    for rtype, value in parse_answers(data):
        if rtype == PTR and value:
            return value
    return None


def mdns_name(ip: str, timeout: float = 1.0) -> str | None:
    """Resolve a device name via mDNS/Bonjour (typically 'Name.local').

    Sends the reverse-name query to the mDNS *multicast* group (which is how
    iPhones/Apple devices actually answer) with the QU bit set so the owner
    replies unicast to us. Reads replies until one for this IP arrives.
    """
    packet = build_query(reverse_name(ip), PTR, IN | _MDNS_QUNICAST)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        # Send multicast out the LAN interface, not e.g. a VM/host-only adapter.
        local = net.local_ipv4()
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
        except OSError:
            pass
        sock.settimeout(timeout)
        sock.sendto(packet, (MDNS_GROUP, MDNS_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            # Only the owner of `ip` answers a reverse query for it; still, prefer
            # a reply whose source matches, and accept any PTR otherwise.
            name = _first_ptr(data)
            if name and (addr[0] == ip or True):
                return name
        return None
    except OSError:
        return None
    finally:
        sock.close()


def discover_services(timeout: float = 2.0) -> dict[str, dict]:
    """One multicast mDNS sweep mapping each IP -> {services: set, model: str}.
    The service types (PTR) say what a device offers; any TXT records devices
    bundle in their replies carry the device's own model (md/ty/model keys)."""
    packet = build_query("_services._dns-sd._udp.local", PTR, IN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: dict[str, dict] = {}
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(net.local_ipv4()))
        except OSError:
            pass
        sock.settimeout(timeout)
        sock.sendto(packet, (MDNS_GROUP, MDNS_PORT))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            rec = found.setdefault(addr[0], {"services": set(), "model": ""})
            for rname, rtype, value in parse_records(data):
                if rtype == PTR and value and value.endswith(("._tcp.local", "._udp.local")):
                    rec["services"].add(value)
                elif rtype == TXT and isinstance(value, dict) and not rec["model"]:
                    rec["model"] = _model_from_txt(value)
    except OSError:
        pass
    finally:
        sock.close()
    return found


def llmnr_name(ip: str, timeout: float = 1.0) -> str | None:
    """Resolve a device name via LLMNR (good for Windows hosts). LLMNR responders
    answer unicast queries, so this is sent directly to the host on UDP 5355."""
    packet = build_query(reverse_name(ip), PTR, IN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, LLMNR_PORT))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    return _first_ptr(data)


# ==========================================================================
# Active multicast solicitation (SSDP M-SEARCH + WS-Discovery Probe)
# ==========================================================================
_SSDP = ("239.255.255.250", 1900)
_WSD = ("239.255.255.250", 3702)

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()

_WSD_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    "<e:Header><w:MessageID>urn:uuid:{uuid}</w:MessageID>"
    "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
    "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
    "</e:Header><e:Body><d:Probe/></e:Body></e:Envelope>"
)


def _probe(group: str, port: int, payload: bytes, timeout: float) -> dict[str, bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: dict[str, bytes] = {}
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(net.local_ipv4()))
        except OSError:
            pass
        sock.settimeout(timeout)
        sock.sendto(payload, (group, port))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            found.setdefault(addr[0], data)
    except OSError:
        pass
    finally:
        sock.close()
    return found


def ssdp_probe(timeout: float = 2.5) -> dict[str, bytes]:
    return _probe(*_SSDP, _SSDP_MSEARCH, timeout)


def wsd_probe(timeout: float = 2.5) -> dict[str, bytes]:
    payload = _WSD_PROBE.format(uuid=uuid.uuid4()).encode()
    return _probe(*_WSD, payload, timeout)


def ssdp_locations(responses: dict[str, bytes]) -> dict[str, str]:
    """Map {ip: SSDP response} -> {ip: device-description URL} from LOCATION headers."""
    out: dict[str, str] = {}
    for ip, data in responses.items():
        m = re.search(rb"(?im)^LOCATION:\s*(\S+)", data)
        if m:
            out[ip] = m.group(1).decode("latin-1", "replace").strip()
    return out


def fetch_upnp(url: str, expect_ip: str | None = None, timeout: float = 2.0) -> dict[str, str]:
    """Fetch and parse a UPnP device-description XML, returning the device's OWN
    declared {name, manufacturer, model}. Only fetches http:// on the LAN, and (if
    expect_ip is given) only from that host, so a device can't redirect us off-box."""
    try:
        u = urlparse(url)
        if u.scheme != "http" or not u.hostname:
            return {}
        if expect_ip and u.hostname != expect_ip:
            return {}
        req = urllib.request.Request(url, headers={"User-Agent": "netmapper"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(65536)
    except (OSError, ValueError):          # URLError is an OSError subclass
        return {}
    return parse_upnp(raw)


def parse_upnp(raw: bytes) -> dict[str, str]:
    """Pull {name, manufacturer, model} from UPnP device-description XML."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}

    def _text(tag):                        # match the tag regardless of XML namespace
        el = root.find(f".//{{*}}{tag}")
        return (el.text or "").strip() if el is not None and el.text else ""

    name, maker, model = _text("friendlyName"), _text("manufacturer"), _text("modelName")
    full = (f"{maker} {model}".strip() if model and maker and maker.lower() not in model.lower()
            else model or maker)
    return {"name": name, "manufacturer": maker, "model": full}


# ==========================================================================
# IPv6 neighbor discovery
# ==========================================================================
_IS_WINDOWS = platform.system().lower().startswith("win")
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")
# MAC prefixes that are multicast/broadcast, never a real unicast device.
_NON_DEVICE = ("33:33", "01:00:5e", "ff:ff", "00:00:00")
# Neighbor reachability states. "Stale"-ish entries linger after a device leaves
# (e.g. a phone that disconnected from Wi-Fi), so we don't count them as present.
_STATE_RE = re.compile(r"\b(reachable|stale|delay|probe|incomplete|permanent|unreachable)\b", re.I)
_STALE_STATES = ("stale", "probe", "incomplete", "unreachable")


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=12).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def interface_indexes() -> list[str]:
    """Connected, non-loopback IPv6 interface zone IDs (for ff02::1%<id>)."""
    out = _run(["netsh", "interface", "ipv6", "show", "interfaces"])
    idxs = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+\d+\s+\d+\s+connected\s+(.+)", line)
        if m and "loopback" not in m.group(2).lower():
            idxs.append(m.group(1))
    return idxs


def _solicit6(idxs: list[str]) -> None:
    for idx in idxs:
        try:
            subprocess.run(["ping", "-6", "-n", "1", "-w", "1000", f"ff02::1%{idx}"],
                           capture_output=True, timeout=4)
        except (OSError, subprocess.TimeoutExpired):
            pass


def ipv6_neighbors(solicit: bool = True) -> dict[str, str]:
    """Return {ipv6_address: mac} of unicast IPv6 neighbors."""
    if not _IS_WINDOWS:
        return _parse(_run(["ip", "-6", "neigh"]))   # best-effort on Linux/macOS
    if solicit:
        _solicit6(interface_indexes())
    return _parse(_run(["netsh", "interface", "ipv6", "show", "neighbors"]))


def _parse(out: str, present_only: bool = True) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in out.splitlines():
        toks = line.split()
        if not toks:
            continue
        ip6 = toks[0].lower()
        if ":" not in ip6 or ip6.startswith("ff"):     # need an IPv6, skip multicast
            continue
        mac_m = _MAC_RE.search(line)
        if not mac_m:
            continue
        mac = mac_m.group(1).replace("-", ":").lower()
        if any(mac.startswith(p) for p in _NON_DEVICE):
            continue
        if present_only:
            state_m = _STATE_RE.search(line)
            if state_m and state_m.group(1).lower() in _STALE_STATES:
                continue                              # lingering ghost - skip
        result[ip6.split("%")[0]] = mac               # drop any %zone suffix
    return result


# ==========================================================================
# Passive (listen-only) discovery
# ==========================================================================
# (group, port) for each multicast protocol we passively listen to.
_GROUPS = {
    "mdns": ("224.0.0.251", 5353),
    "ssdp": ("239.255.255.250", 1900),
    "llmnr": ("224.0.0.252", 5355),
}


def _join(group: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton("0.0.0.0"))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def open_sockets() -> dict:
    """Open and join the multicast listen sockets; returns {socket: proto_name}."""
    socks: dict = {}
    for name, (grp, port) in _GROUPS.items():
        try:
            socks[_join(grp, port)] = name
        except OSError:
            pass  # port already held by the OS resolver, etc.
    return socks


def _ingest(proto: str, data: bytes, ip: str, found: dict) -> None:
    """Fold one received packet into the capture dict."""
    rec = found.setdefault(ip, {"names": set(), "services": set(),
                                "protocols": set(), "info": set(), "model": ""})
    rec["protocols"].add(proto)
    if proto in ("mdns", "llmnr"):
        _harvest_dns(data, rec)
    else:
        _harvest_ssdp(data, rec)


def poll_once(socks: dict, found: dict, timeout: float = 1.0) -> dict:
    """Read whatever is ready on the listen sockets into `found`, then return."""
    import select
    ready, _, _ = select.select(list(socks), [], [], timeout)
    for s in ready:
        try:
            data, addr = s.recvfrom(8192)
        except OSError:
            continue
        _ingest(socks[s], data, addr[0], found)
    return found


def device_from_passive(ip: str, rec: dict, arp: dict) -> net.Device:
    """Build a Device from a single passive capture record."""
    d = net.Device(ip=ip)
    d.discovery = "passive"
    d.mac = arp.get(ip)
    d.vendor = identify.lookup(d.mac) if d.mac else None
    d.hostname = sorted(rec["names"])[0] if rec["names"] else None
    d.name_source = "passive" if d.hostname else ""
    d.services = sorted(rec["services"])
    d.model = rec.get("model", "")
    d.device_type, d.confidence, ev = identify.classify(d, set(d.services), {})
    d.evidence = [f"heard via {', '.join(sorted(rec['protocols']))}"] + sorted(rec["info"])[:3] + ev
    return d


def _harvest_dns(data: bytes, rec: dict) -> None:
    for name, rtype, value in parse_records(data):
        if rtype == A and name and name.endswith(".local"):
            rec["names"].add(name)
        elif rtype == PTR and value and value.endswith(("._tcp.local", "._udp.local")):
            rec["services"].add(value)
        elif rtype == TXT and isinstance(value, dict) and not rec.get("model"):
            rec["model"] = _model_from_txt(value)


def _harvest_ssdp(data: bytes, rec: dict) -> None:
    for line in data.decode("latin-1", "replace").splitlines():
        low = line.lower()
        if low.startswith("server:"):
            rec["info"].add("Server: " + line.split(":", 1)[1].strip())
        elif low.startswith(("nt:", "usn:")) and "::" not in line:
            rec["info"].add(line.strip())
