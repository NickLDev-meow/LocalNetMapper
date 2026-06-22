"""Identity & meaning - turn raw signals into something a human understands.

Three layers, from a bare MAC/port to an interpreted device:

  * vendor   - MAC OUI -> hardware vendor (+ algorithmic multicast/randomized-MAC
               detection that needs no database),
  * type     - a multi-signal fingerprint (vendor + ports + mDNS services + OS +
               banners) -> a confidence-scored device type with evidence,
  * exposure - port intelligence: service names + which open ports are notable
               attack surface on a LAN (the things a pentester flags first).
"""
from __future__ import annotations

import csv
import os
from collections import defaultdict

from .net import COMMON_PORTS, Device

# ==========================================================================
# Vendor lookup (MAC OUI)
# ==========================================================================
_DIR = os.path.join(os.path.dirname(__file__), "data")
_CSV = os.path.join(_DIR, "oui.csv")          # compact form: PREFIX,Vendor

# A tiny set of well-known prefixes so there's *something* if the full IEEE
# database (data/oui.csv) hasn't been placed alongside.
_STARTER: dict[str, str] = {
    "001C42": "Parallels",
    "080027": "VirtualBox (Oracle)",
    "0050F2": "Microsoft",
    "001A11": "Google",
}

_cache: dict[str, str] | None = None


def _norm_prefix(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()[:6]


def _load() -> dict[str, str]:
    global _cache
    if _cache is not None:
        return _cache
    db = dict(_STARTER)
    if os.path.exists(_CSV):
        try:
            with open(_CSV, newline="", encoding="utf-8") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 2 and row[0]:
                        db[row[0].strip().upper()] = row[1]
        except OSError:
            pass
    _cache = db
    return db


def lookup(mac: str | None) -> str | None:
    """Resolve a MAC to a vendor / category, or None if no MAC."""
    if not mac:
        return None
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return "Unknown"
    if first & 0x01:
        return "Multicast"
    if first & 0x02:
        return "Randomized / private MAC"   # e.g. a modern phone with MAC privacy
    return _load().get(_norm_prefix(mac), "Unknown")


def db_size() -> int:
    return len(_load())


# ==========================================================================
# Device-type fingerprint (multi-signal)
# ==========================================================================
def classify(d: Device, services: set[str] | None = None,
             banners: dict[int, str] | None = None) -> tuple[str, int, list[str]]:
    services = services or set()
    banners = banners or {}
    svc_blob = " ".join(services).lower()
    vendor = (d.vendor or "").lower()
    ports = set(d.open_ports)
    banner_blob = " ".join(banners.values()).lower()

    scores: dict[str, int] = defaultdict(int)
    evidence: list[str] = []

    def add(dtype: str, points: int, why: str):
        scores[dtype] += points
        evidence.append(why)

    # --- Infrastructure ----------------------------------------------------
    if d.is_gateway:
        add("Router / Gateway", 100, "is the default gateway")

    # --- Self-declared model (UPnP description / mDNS TXT) -----------------
    # The device told us its own model name; trust it over any inference.
    if getattr(d, "model", ""):
        add(d.model[:40], 85, f"self-declared model: {d.model}")

    # --- Vendor-driven signals --------------------------------------------
    if "apple" in vendor:
        add("Apple device", 50, "Apple OUI")
    if "espressif" in vendor:
        add("IoT (ESP32/ESP8266)", 70, "Espressif OUI (microcontroller)")
    if "amazon" in vendor:
        add("Amazon device (Echo/Fire)", 50, "Amazon OUI")
    if "google" in vendor or "nest" in vendor:
        add("Google/Nest device", 45, "Google/Nest OUI")
    if any(v in vendor for v in ("synology", "qnap", "western digital")):
        add("NAS", 65, "storage-vendor OUI")
    if any(v in vendor for v in ("netgear", "tp-link", "ubiquiti", "cisco", "asus")) and d.is_gateway:
        add("Router / Gateway", 30, "network-vendor OUI")

    # --- mDNS service signals ---------------------------------------------
    if any(s in svc_blob for s in ("_airplay", "_raop", "_companion-link", "_apple-mobdev", "_airport")):
        add("Apple device", 60, "advertises Apple/AirPlay services")
    if "_googlecast" in svc_blob:
        add("Google Cast / Chromecast", 70, "advertises Google Cast")
    if any(s in svc_blob for s in ("_spotify-connect", "_sonos", "_amzn")):
        add("Smart speaker / media", 45, "advertises audio-streaming service")
    if any(s in svc_blob for s in ("_ipp", "_printer", "_pdl-datastream", "_scanner")):
        add("Printer / scanner", 65, "advertises printing services")
    if "_homekit" in svc_blob or "_hap" in svc_blob:
        add("Smart home (HomeKit)", 50, "advertises HomeKit")
    if "_androidtvremote" in svc_blob:
        add("Android TV", 55, "advertises the Android TV remote service")
    if "_roku" in svc_blob:
        add("Roku streaming player", 65, "advertises Roku service")
    if "_sonos" in svc_blob:
        add("Sonos speaker", 65, "advertises Sonos service")
    if "_hue" in svc_blob or "_philipshue" in svc_blob:
        add("Philips Hue lighting", 60, "advertises Hue service")
    if "_nanoleaf" in svc_blob:
        add("Nanoleaf lighting", 60, "advertises Nanoleaf service")
    if "_miio" in svc_blob:
        add("Xiaomi smart device", 55, "advertises Xiaomi miio service")
    if "_matter" in svc_blob or "_matterc" in svc_blob:
        add("Matter smart-home device", 45, "advertises Matter")

    # --- Apple iOS & streaming devices (strong port tells) ----------------
    if 62078 in ports:
        # lockdownd - the iOS pairing/sync service; present on iPhones & iPads.
        add("Apple iPhone/iPad", 75, "iOS lockdownd port 62078 open")
    if 7000 in ports:
        add("Apple device", 40, "AirPlay port open")
    if ports & {8008, 8009}:
        add("Google Cast / Chromecast", 55, "Cast port open")
    if 8060 in ports:
        add("Roku", 60, "Roku ECP port open")

    # --- Port + banner signals --------------------------------------------
    if ports & {9100, 515, 631}:
        add("Printer / scanner", 60, "printer ports open (9100/515/631)")
    if ports & {139, 445} and 3389 in ports:
        add("Windows PC", 50, "SMB + RDP open")
    elif ports & {139, 445}:
        add("Windows / file share", 35, "SMB/NetBIOS open")
    if d.os_family == "Windows":
        add("Windows PC", 45, "TTL fingerprint = Windows")
    if 22 in ports:
        add("Linux / SSH host", 40, "SSH open")
        if "ubuntu" in banner_blob:
            add("Linux / SSH host", 15, "SSH banner mentions Ubuntu")
        if "raspbian" in banner_blob or "raspberry" in banner_blob:
            add("Raspberry Pi", 40, "banner mentions Raspberry Pi")
    if 23 in ports:
        add("Legacy/IoT (Telnet)", 30, "Telnet open (legacy)")
    if 32400 in ports:
        add("Media server (Plex)", 60, "Plex port open")
    for port, banner in banners.items():
        if banner and banner.lower().startswith("server:"):
            evidence.append(f"HTTP {port}: {banner[:40]}")

    # --- Privacy / anonymized ---------------------------------------------
    # A randomized MAC that answers nothing - no ping/TTL, no open ports, no name
    # - could be a locked phone OR a firewalled (Public-profile) PC that also has
    # MAC randomization on. Active probing can't separate the two, so say both.
    if vendor.startswith("randomized") and not ports and not d.hostname:
        if d.os_family == "Windows":
            add("Windows PC (firewalled)", 45, "randomized MAC, TTL says Windows, firewalled")
        else:
            add("Firewalled device", 40,
                "randomized MAC, fully silent - could be a locked phone or a firewalled PC")

    if not scores:
        base = 20 if (ports or services) else 10
        return ("Unknown device", base, evidence)

    best = max(scores, key=lambda k: scores[k])
    confidence = min(99, scores[best])
    return (best, confidence, evidence)


# ==========================================================================
# Port intelligence (attack-surface read)
# ==========================================================================
# port -> (service name, category)
_SERVICE: dict[int, tuple[str, str]] = {
    21: ("FTP", "file"), 22: ("SSH", "remote"), 23: ("Telnet", "remote"),
    25: ("SMTP", "mail"), 53: ("DNS", "infra"), 80: ("HTTP", "web"),
    110: ("POP3", "mail"), 111: ("RPC", "file"), 135: ("MSRPC", "windows"),
    139: ("NetBIOS", "file"), 143: ("IMAP", "mail"), 389: ("LDAP", "infra"),
    443: ("HTTPS", "web"), 445: ("SMB", "file"), 515: ("LPD", "print"),
    548: ("AFP", "file"), 554: ("RTSP", "media"), 631: ("IPP", "print"),
    993: ("IMAPS", "mail"), 995: ("POP3S", "mail"), 1433: ("MS-SQL", "db"),
    1723: ("PPTP", "remote"), 1883: ("MQTT", "iot"), 1900: ("UPnP", "iot"),
    2049: ("NFS", "file"), 3306: ("MySQL", "db"), 3389: ("RDP", "remote"),
    5000: ("UPnP/HTTP", "iot"), 5353: ("mDNS", "iot"), 5432: ("PostgreSQL", "db"),
    5900: ("VNC", "remote"), 5984: ("CouchDB", "db"), 6379: ("Redis", "db"),
    7000: ("AirPlay", "media"), 8008: ("Cast", "media"), 8009: ("Cast", "media"),
    8060: ("Roku", "media"), 8080: ("HTTP-alt", "web"), 8443: ("HTTPS-alt", "web"),
    8883: ("MQTT-TLS", "iot"), 9100: ("JetDirect", "print"), 9200: ("Elastic", "db"),
    11211: ("Memcached", "db"), 27017: ("MongoDB", "db"), 32400: ("Plex", "media"),
    49152: ("UPnP", "iot"), 62078: ("iOS-lockdownd", "apple"),
}

# Ports worth flagging as notable attack surface, with the reason a defender
# (or attacker) cares. These are the "look here first" services on a LAN.
_NOTABLE: dict[int, str] = {
    21: "cleartext file transfer (FTP)",
    23: "cleartext remote shell (Telnet)",
    135: "Windows RPC endpoint",
    139: "legacy NetBIOS file sharing",
    445: "SMB file sharing",
    512: "rexec", 513: "rlogin", 514: "rsh",
    1433: "MS-SQL database exposed",
    1723: "legacy PPTP VPN",
    2049: "NFS exports",
    3306: "MySQL database exposed",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL database exposed",
    5900: "remote screen control (VNC)",
    5984: "CouchDB exposed",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch exposed",
    11211: "Memcached (often unauthenticated)",
    27017: "MongoDB exposed",
}


def service(port: int) -> str:
    """Human service name for a port (falls back to the common-ports table, then the number)."""
    if port in _SERVICE:
        return _SERVICE[port][0]
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    return f"port {port}"


def category(port: int) -> str:
    return _SERVICE.get(port, (None, "other"))[1]


def is_notable(port: int) -> bool:
    return port in _NOTABLE


def note(port: int) -> str:
    return _NOTABLE.get(port, "")


def label(port: int) -> str:
    """e.g. '445/SMB' - the compact port/service token used in the UI."""
    return f"{port}/{service(port)}"


def clean_banner(banner: str | None, maxlen: int = 46) -> str:
    """Tidy a raw service banner into a short version string for display.
    Strips an HTTP 'Server:' prefix, collapses whitespace, and clips length."""
    if not banner:
        return ""
    b = banner.strip()
    if b.lower().startswith("server:"):
        b = b.split(":", 1)[1].strip()
    b = " ".join(b.split())
    return (b[:maxlen - 1] + "…") if len(b) > maxlen else b


def summarize(open_ports) -> dict:
    """Roll a list of open ports into an attack-surface summary."""
    ports = sorted(set(open_ports or []))
    notable = [(p, service(p), _NOTABLE[p]) for p in ports if p in _NOTABLE]
    cats = sorted({category(p) for p in ports if category(p) != "other"})
    return {"count": len(ports), "ports": ports, "notable": notable, "categories": cats}
