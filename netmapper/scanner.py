"""Orchestrates a full scan: discover hosts, then enrich each into a Device.

Pipeline:
  1. Ping-sweep the subnet concurrently to find responsive hosts.
  2. Read the ARP table - this catches devices that ignore ping but answered the
     ARP broadcast the sweep triggered (phones, some IoT).
  3. For every live host, gather MAC, vendor, hostname, open ports, and role.
"""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from . import identify, net, probes
from .net import Device

# Open ports worth grabbing a banner from - services that announce a version
# string on connect (SSH/FTP/Telnet/SMTP) or via an HTTP Server header.
_BANNER_PORTS = (22, 21, 23, 25, 80, 110, 143, 554, 8080, 8000, 8443, 5000, 9100)


def scan(network: str | None = None, do_ports: bool = True, ping_timeout: int = 600,
         port_timeout: float = 0.4, workers: int = 64, tcp_discovery: bool = True,
         do_netbios: bool = True, do_mdns: bool = True, do_llmnr: bool = True,
         ping_retries: int = 1, active_solicit: bool = True, do_ipv6: bool = True,
         intensive: bool = False
         ) -> tuple[ipaddress.IPv4Network, list[Device]]:
    # Intensive mode: scan a much wider port set, more retries, longer timeouts.
    port_list = net.INTENSIVE_PORTS if intensive else None
    if intensive:
        ping_retries += 2
        port_timeout *= 1.5
    subnet = (ipaddress.ip_network(str(network), strict=False)
              if network else net.default_network())
    my_ip = net.local_ipv4()
    gateway = net.default_gateway() or net.gateway_guess(subnet)
    hosts = net.hosts_in(subnet)

    # Track how each host was discovered (first method wins for labeling).
    methods: dict[str, str] = {}

    # 1. Ping sweep (concurrent), capturing reply TTL for OS fingerprinting.
    #    Retry only the non-responders, so a dropped packet can't hide a host.
    with ThreadPoolExecutor(max_workers=workers) as ex:
        sweep = dict(zip(hosts, ex.map(lambda h: net.ping_ttl(h, ping_timeout), hosts)))
        for _ in range(max(0, ping_retries)):
            retry_hosts = [ip for ip, (alive, _t) in sweep.items() if not alive]
            if not retry_hosts:
                break
            again = dict(zip(retry_hosts, ex.map(lambda h: net.ping_ttl(h, ping_timeout), retry_hosts)))
            for ip, res in again.items():
                if res[0]:
                    sweep[ip] = res
    ping_results = {ip: alive for ip, (alive, _ttl) in sweep.items()}
    ttls = {ip: ttl for ip, (alive, ttl) in sweep.items() if alive}
    for ip, up in ping_results.items():
        if up:
            methods[ip] = "ping"

    # 2. ARP table - catches hosts that ignore ping but answered the ARP broadcast.
    arp = net.arp_table()
    for ip in arp:
        if _in_net(ip, subnet):
            methods.setdefault(ip, "arp")

    # 3. TCP discovery - find hosts that block ping AND aren't in ARP yet (the
    #    classic firewalled Windows PC). Only probe still-unknown addresses.
    if tcp_discovery:
        unknown = [h for h in hosts if h not in methods and h != my_ip]
        with ThreadPoolExecutor(max_workers=max(workers, 128)) as ex:
            for ip, port in zip(unknown, ex.map(lambda h: net.tcp_alive(h, timeout=port_timeout), unknown)):
                if port is not None:
                    methods[ip] = "tcp"

        # Re-read ARP: the TCP probes above resolve MACs at layer 2 even for
        # hosts that drop every connection, so a final pass catches L2-only hosts.
        for ip, mac in net.arp_table().items():
            if _in_net(ip, subnet):
                arp.setdefault(ip, mac)
                methods.setdefault(ip, "arp")

    # Active solicitation - make printers/cameras/TVs/Windows announce themselves.
    ssdp_locs: dict[str, str] = {}
    if active_solicit:
        ssdp_resp = probes.ssdp_probe()
        for ip in ssdp_resp:
            if _in_net(ip, subnet) and ip != my_ip:
                methods.setdefault(ip, "ssdp")
        # Keep the SSDP LOCATION URLs so we can read each device's UPnP description.
        ssdp_locs = probes.ssdp_locations(
            {ip: body for ip, body in ssdp_resp.items() if _in_net(ip, subnet) and ip != my_ip})
        for ip in probes.wsd_probe():
            if _in_net(ip, subnet) and ip != my_ip:
                methods.setdefault(ip, "wsd")
        # Solicitation also primes ARP for any newly-heard hosts.
        for ip, mac in net.arp_table().items():
            if _in_net(ip, subnet) and ip in methods:
                arp.setdefault(ip, mac)

    methods[my_ip] = "self"
    live = set(methods)

    # Neighbor reachability states - used to flag stale ARP-cache ghosts (e.g. a
    # phone that rotated its MAC and left) so they don't inflate the device list.
    nstates = net.neighbor_states()

    # One mDNS service sweep for the whole LAN - feeds device fingerprinting.
    services_map = probes.discover_services() if do_mdns else {}

    # 4. Enrich each live host concurrently.
    def build(ip: str) -> Device:
        d = Device(ip=ip)
        d.discovery = methods.get(ip, "")
        d.is_self = (ip == my_ip)
        d.is_gateway = (ip == gateway)
        d.responded_ping = ping_results.get(ip, False)
        d.mac = arp.get(ip) or (net.local_mac() if d.is_self else None)
        d.vendor = identify.lookup(d.mac) or ("This machine" if d.is_self else None)

        # Name resolution chain - try each method until one names the host. This
        # is what unmasks anonymized (randomized-MAC) devices: mDNS names Apple/
        # IoT gear, LLMNR/NetBIOS name Windows PCs.
        if d.is_self:
            d.hostname = socket.gethostname()
            d.name_source = "local"
        else:
            for source, fn, enabled in (
                ("dns", net.reverse_dns, True),
                ("netbios", probes.netbios_query, do_netbios),
                ("mdns", probes.mdns_name, do_mdns),
                ("llmnr", probes.llmnr_name, do_llmnr),
            ):
                if not enabled:
                    continue
                d.hostname = fn(ip)
                if d.hostname:
                    d.name_source = source
                    break

        if do_ports:
            d.open_ports = net.scan_ports(ip, ports=port_list, timeout=port_timeout)
        d.role = net.guess_role(d.open_ports, d.is_gateway)
        d.os_family = net.os_guess(ttls.get(ip)) or ("Windows" if d.is_self else "")

        # mDNS services + any self-declared model from TXT records.
        svc = services_map.get(ip, {})
        d.services = sorted(svc.get("services", []))
        if svc.get("model"):
            d.model = svc["model"]

        # UPnP: follow the SSDP LOCATION header and read the device's own
        # description for its real friendly name + model (the device names itself).
        loc = ssdp_locs.get(ip)
        if loc:
            info = probes.fetch_upnp(loc, ip)
            if info.get("model"):
                d.model = info["model"]
            if info.get("name") and not d.hostname:
                d.hostname, d.name_source = info["name"], "upnp"

        # Multi-signal fingerprint: combine vendor + ports + mDNS services +
        # OS + banners + self-declared model into a confidence-scored device type.
        banners = {}
        for p in _BANNER_PORTS:
            if p in d.open_ports:
                b = net.grab_banner(ip, p, timeout=port_timeout * 2)
                if b:
                    banners[p] = b
        d.banners = banners
        d.device_type, d.confidence, d.evidence = identify.classify(
            d, set(d.services), banners)

        d.stale = is_stale_ghost(d, nstates.get(ip, ""))
        return d

    ordered = sorted(live, key=lambda x: tuple(int(o) for o in x.split(".")))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        devices = list(ex.map(build, ordered))

    # IPv6: stir the neighbor cache, then correlate by MAC. Dual-stack devices
    # gain their IPv6 address; a MAC we never saw on IPv4 becomes a new device.
    if do_ipv6:
        nbrs = probes.ipv6_neighbors()
        by_mac = {d.mac: d for d in devices if d.mac}
        extra: dict[str, list[str]] = {}
        for ip6, mac in nbrs.items():
            if mac in by_mac:
                if ip6 not in by_mac[mac].ipv6:
                    by_mac[mac].ipv6.append(ip6)
            else:
                extra.setdefault(mac, []).append(ip6)
        for mac, ip6s in extra.items():
            d = Device(ip=ip6s[0])
            d.ipv6 = sorted(ip6s)
            d.mac = mac
            d.vendor = identify.lookup(mac)
            d.discovery = "ipv6"
            d.device_type, d.confidence, d.evidence = identify.classify(d, set(), {})
            devices.append(d)
        devices.sort(key=lambda d: d.sort_key())

    return subnet, devices


def is_stale_ghost(d: Device, neighbor_state: str) -> bool:
    """A device is a stale ghost if the OS neighbor entry is 'stale'/'incomplete'
    AND it showed no active liveness this scan (no ping, no ports, no name).

    A genuinely-present device - even a firewalled one - is 'reachable' or answers
    *something*, so a real host (including a Windows PC) is never flagged stale.
    """
    return (not d.is_self and not d.responded_ping and not d.open_ports
            and not d.hostname and neighbor_state in ("stale", "incomplete"))


def _in_net(ip: str, subnet: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in subnet
    except ValueError:
        return False
