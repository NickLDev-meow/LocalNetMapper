"""netmapper - live local-network discovery in a terminal dashboard.

    python -m netmapper                 # launch the live dashboard (drive it with the number menu)
    python -m netmapper 192.168.1.0/24  # monitor a specific network
    python -m netmapper --intensive     # deep scan: wider port set + more retries
"""
from __future__ import annotations

import argparse
import sys

from . import console
from .scanner import scan

BANNER = r"""
 _   _ _____ _____ __  __    _    ____  ____  _____ ____
| \ | | ____|_   _|  \/  |  / \  |  _ \|  _ \| ____|  _ \
|  \| |  _|   | | | |\/| | / _ \ | |_) | |_) |  _| | |_) |
| |\  | |___  | | | |  | |/ ___ \|  __/|  __/| |___|  _ <
|_| \_|_____| |_| |_|  |_/_/   \_\_|   |_|   |_____|_| \_\

     ( =^..^= )     live network dashboard
                    drive it with the number menu at the bottom
"""


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(
        prog="netmapper",
        description="Live local-network discovery dashboard (active + passive).",
    )
    parser.add_argument("network", nargs="?",
                        help="CIDR to scan (e.g. 192.168.1.0/24). Default: your local /24.")
    parser.add_argument("--interval", type=int, default=30,
                        help="Seconds between background rescans (default 30).")
    parser.add_argument("--intensive", action="store_true",
                        help="Deep scan: a much wider port set + more retries (slower, more thorough).")
    # Discovery tuning (all on by default).
    parser.add_argument("--no-ports", action="store_true", help="Skip the port scan (faster).")
    parser.add_argument("--no-tcp-discovery", action="store_true", help="Skip TCP-probe discovery.")
    parser.add_argument("--no-netbios", action="store_true", help="Skip NetBIOS name lookups.")
    parser.add_argument("--no-mdns", action="store_true", help="Skip mDNS name lookups.")
    parser.add_argument("--no-llmnr", action="store_true", help="Skip LLMNR name lookups.")
    parser.add_argument("--no-solicit", action="store_true", help="Skip SSDP/WS-Discovery solicitation.")
    parser.add_argument("--no-ipv6", action="store_true", help="Skip IPv6 neighbor discovery.")
    parser.add_argument("--retries", type=int, default=1, metavar="N",
                        help="Extra ping passes for non-responders (default 1).")
    parser.add_argument("--timeout", type=int, default=600, help="Ping timeout in ms (default 600).")
    parser.add_argument("--port-timeout", type=float, default=0.4,
                        help="Per-port connect timeout in seconds (default 0.4).")
    parser.add_argument("--workers", type=int, default=64, help="Concurrent workers (default 64).")
    args = parser.parse_args(argv)
    print(BANNER)

    def do_scan(intensive=False):
        return scan(
            network=args.network, do_ports=not args.no_ports, ping_timeout=args.timeout,
            port_timeout=args.port_timeout, workers=args.workers,
            tcp_discovery=not args.no_tcp_discovery, do_netbios=not args.no_netbios,
            do_mdns=not args.no_mdns, do_llmnr=not args.no_llmnr,
            ping_retries=args.retries, active_solicit=not args.no_solicit,
            do_ipv6=not args.no_ipv6, intensive=intensive,
        )

    console.run(do_scan, interval=args.interval, intensive=args.intensive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
