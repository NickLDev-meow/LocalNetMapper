"""Live console dashboard: a plain ASCII UI wrapped in a slash border.

Clears and reprints a frame each second from the engine snapshot: a NETMAPPER
banner, the device table, an attack-surface summary, a details inspector and an
event feed, with a number menu to drive it.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import time

from . import identify
from .engine import Engine

_ANSI = re.compile(r"\033\[[0-9;]*m")
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"

# --- palette -------------------------------------------------------------
# the frame stays red; device rows get an accent color by type so they're
# easy to tell apart at a glance.
RED = "\033[38;2;190;75;70m"     # primary / frame (muted brick red, easy on the eyes)
BRED = "\033[38;2;215;110;100m"  # soft highlight (banner / emphasis)
DRED = "\033[38;2;120;48;46m"    # dim (borders / secondary)
AMBER = "\033[38;2;255;180;40m"  # router / gateway
CYAN = "\033[38;2;60;210;235m"   # Apple
GREEN = "\033[38;2;90;220;120m"  # Windows
ORANGE = "\033[38;2;255;140;50m" # IoT / media / smart-home
BLUE = "\033[38;2;110;160;255m"  # printer / scanner
VIOLET = "\033[38;2;150;140;240m"   # anonymized: phone or firewalled PC


def _type_color(d: dict) -> str:
    if d["self"]:
        return GREEN
    t = (d["type"] or "").lower()
    if d["gateway"] or "router" in t or "gateway" in t:
        return AMBER
    if any(x in t for x in ("apple", "iphone", "ipad", "mac")):
        return CYAN
    if "windows" in t:
        return GREEN
    if any(x in t for x in ("amazon", "echo", "cast", "chromecast", "roku", "media", "plex",
                            "iot", "esp", "smart", "sonos", "speaker", "hue", "nanoleaf",
                            "android", "tv")):
        return ORANGE
    if "printer" in t or "scanner" in t:
        return BLUE
    if d.get("anon") or "firewalled" in t or "anonymized" in t or "mobile" in t:
        return VIOLET
    return RED

# ASCII banner for the title bar
_BANNER = [
    " _   _  _____  _____  __  __     _     ____   ____   _____  ____  ",
    "| \\ | || ____||_   _||  \\/  |   / \\   |  _ \\ |  _ \\ | ____||  _ \\ ",
    "|  \\| ||  _|    | |  | |\\/| |  / _ \\  | |_) || |_) ||  _|  | |_) |",
    "| |\\  || |___   | |  | |  | | / ___ \\ |  __/ |  __/ | |___ |  _ < ",
    "|_| \\_||_____|  |_|  |_|  |_|/_/   \\_\\|_|    |_|    |_____||_| \\_\\",
]

_EVENT_TAG = {"NEW": "+", "REJOINED": "+", "GONE": "-",
              "MAC_CONFLICT": "!", "VENDOR_CHANGED": "!", "IP_CHANGED": "*",
              "SCAN_ERROR": "!"}


def _c(text, color) -> str:
    return f"{color}{text}{RESET}"


def _vlen(s: str) -> int:
    return len(_ANSI.sub("", s))


def _clip_ansi(s: str, width: int) -> str:
    """Truncate to `width` visible columns, keeping any color codes intact."""
    if _vlen(s) <= width:
        return s
    out, vis, i = [], 0, 0
    while i < len(s) and vis < width:
        m = _ANSI.match(s, i)
        if m:
            out.append(m.group())
            i = m.end()
        else:
            out.append(s[i])
            vis += 1
            i += 1
    return "".join(out) + RESET


def _clip(text: str, width: int) -> str:
    return (text[:width - 1] + "…") if len(text) > width else text


def _center(s: str, width: int) -> str:
    pad = max(0, width - _vlen(s))
    return " " * (pad // 2) + s


def _enable_ansi() -> None:
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


def _short_vendor(v: str) -> str:
    if not v:
        return "—"
    if v.startswith("Randomized"):
        return "private MAC"
    if v == "This machine":
        return "this machine"
    v = v.split(",")[0]
    for junk in (" Technologies", " COMPUTER INC.", " Inc.", " Inc", " LLC", " Corporation"):
        v = v.replace(junk, "")
    return (v[:13] + "…") if len(v) > 14 else v


def _border(lines: list[str], width: int) -> list[str]:
    """Wrap content lines in a slash border: //// top/bottom, // on each side."""
    inner = width - 6
    edge = _c("/" * width, DRED)
    out = [edge]
    for ln in lines:
        clipped = _clip_ansi(ln, inner)
        pad = " " * max(0, inner - _vlen(clipped))
        out.append(_c("//", DRED) + " " + clipped + pad + " " + _c("//", DRED))
    out.append(edge)
    return out


def _dev_row(d: dict, selected: bool = False) -> str:
    color = _type_color(d)
    glyph = "~" if d["stale"] else ("?" if d["anon"] else "+")
    cursor = _c(">", BRED) if selected else " "
    mac = d["mac"] or "—"
    osv = _clip(d["os"] or "—", 6)
    vend = _short_vendor(d["vendor"])
    via = _clip(d["via"] or "—", 7)
    dtype = _clip(d["type"], 17)
    if d["hostname"]:
        host = _clip(d["hostname"], 20)
    elif d["ports"] and d["ports"] != "-":
        host = _clip(d["ports"], 20)
    else:
        host = "—"
    tags = []
    if d["gateway"]:
        tags.append("gw")
    if d["self"]:
        tags.append("you")
    if d["stale"]:
        tags.append("stale")
    if tags:
        host = f"{host} ({','.join(tags)})"
    summ = identify.summarize(d.get("open_ports", []))
    if summ["count"]:
        badge = _c(f"  {summ['count']}p!", ORANGE) if summ["notable"] else _c(f"  {summ['count']}p", DRED)
    else:
        badge = ""
    return (cursor + _c(glyph, color) + "  " + _c(f"{d['ip']:15}", color) + " " + _c(f"{mac:17}", DRED)
            + " " + _c(f"{vend:13}", RED) + " " + _c(f"{osv:6}", DRED) + " "
            + _c(f"{via:7}", BRED) + " " + _c(f"{dtype:17}", color) + " " + _c(host, RED) + badge)


def _detail_block(d: dict) -> list[str]:
    """The expanded per-device inspector, shown in its own DETAILS section."""
    color = _type_color(d)
    summ = identify.summarize(d.get("open_ports", []))
    out = []

    def kv(label, value):
        out.append(_c(f"  {label:9} ", DRED) + value)

    out.append(_c(" DETAILS ", BRED) + _c("· " + d["ip"], color)
               + _c("    (↑/↓ select · [3] hide)", DRED))
    extra = (f"   ·   {d['confidence']}% confidence" if d["confidence"] else "")
    kv("type", _c(d["type"] or "unknown", color) + _c(f"   {d['os'] or 'OS unknown'}", DRED) + _c(extra, DRED))
    kv("mac", _c(d["mac"] or "—", RED) + _c(f"   {_short_vendor(d['vendor'])}", DRED))
    if d["hostname"]:
        kv("name", _c(d["hostname"], RED)
           + (_c(f"   (via {d['name_source']})", DRED) if d["name_source"] else ""))
    kv("found via", _c(d["via"] or "—", BRED) + _c(f"   ·   {summ['count']} open port(s)", DRED))
    if summ["count"]:
        toks = [(_c(identify.label(p) + "!", ORANGE) if identify.is_notable(p)
                 else _c(identify.label(p), RED)) for p in summ["ports"]]
        kv("ports", "  ".join(toks))
    if summ["notable"]:
        notes = "; ".join(f"{svc}: {why}" for _, svc, why in summ["notable"])
        kv("notable", _c(notes, ORANGE))
    bn = d.get("banners") or {}
    vtoks = [_c(f"{identify.label(p)} ", BRED) + _c(identify.clean_banner(bn[p]), RED)
             for p in sorted(bn) if identify.clean_banner(bn[p])]
    if vtoks:
        kv("versions", _c("  ·  ", DRED).join(vtoks))
    if d["services"]:
        kv("services", _c(d["services"], DRED))
    if d["ipv6"]:
        kv("ipv6", _c("  ".join(d["ipv6"][:2]), DRED))
    if d["evidence"]:
        kv("evidence", _c(d["evidence"], DRED))

    # fingerprint history: what we ever learned, even if it's silent now
    h = d.get("hist") or {}
    if h.get("times_seen"):
        span = f"{h.get('first_seen','?')[5:16]} → {h.get('last_seen','?')[5:16]}"
        kv("seen", _c(f"{h['times_seen']}x   {span}", DRED))
    hints = []
    if h.get("ever_type") and (h["ever_type"] != d["type"] or h.get("ever_confidence", 0) > d["confidence"]):
        hints.append(f"was {h['ever_type']} ({h.get('ever_confidence', 0)}%)")
    extra_ports = [p for p in h.get("ever_ports", []) if p not in summ["ports"]]
    if extra_ports:
        hints.append("ports seen " + " ".join(identify.label(p) for p in extra_ports))
    if h.get("ever_hostname") and not d["hostname"]:
        hints.append(f"named {h['ever_hostname']}")
    if h.get("ever_os") and not d["os"]:
        hints.append(f"OS {h['ever_os']}")
    if hints:
        tail = _c(f"   (last {h['enriched_at'][5:16]})", DRED) if h.get("enriched_at") else ""
        kv("history", _c("  ·  ".join(hints), BRED) + tail)
    return out


def _frame(snap: dict, verbose: bool = False, notice: str = "", width: int = 100, sel: int = 0,
           events_expanded: bool = False, height: int = 0) -> str:
    width = max(72, min(width, 108))
    inner = width - 6
    s = snap["stats"]

    if snap["scanning"]:
        status = "intensive sweep…" if snap.get("scanning_intensive") else "scanning…"
    else:
        status = f"updated {snap['last_scan']}"
    active = s["devices"] - s.get("stale", 0)
    info = (f"=^..^=    net {snap['net'] or '…'}    {s['devices']} hosts "
            f"({active} up" + (f", {s['stale']} ghost" if s.get("stale") else "") + f")    {status}")

    content: list[str] = []
    for b in _BANNER:
        content.append(_center(_c(b, BRED), inner))
    content.append("")
    content.append(_center(_c(info, RED), inner))
    content.append("")

    # device table
    content.append(_c(f" {'':1}  {'IP':15} {'MAC':17} {'VENDOR':13} {'OS':6} {'VIA':7} {'TYPE':17} HOST", DRED))
    content.append(_c(" " + "-" * (inner - 2), DRED))
    devices = snap["devices"]
    ordered = [d for d in devices if d["gateway"]] + [d for d in devices if not d["gateway"]]
    if not ordered:
        content.append(_c("    scanning the subnet…", DRED))
    sel = max(0, min(sel, len(ordered) - 1)) if ordered else 0
    for i, d in enumerate(ordered):
        content.append(_dev_row(d, selected=(verbose and i == sel)))
    content.append("")

    # attack-surface summary
    content.append(_c(" ATTACK SURFACE", BRED))
    exp = [(d, identify.summarize(d.get("open_ports", []))) for d in devices]
    exp = [(d, s) for d, s in exp if s["count"]]
    notable_hosts = [(d, s) for d, s in exp if s["notable"]]
    if exp:
        line = "  " + _c(f"{len(exp)} host(s) with open ports", RED)
        line += (_c(f"   ·   {len(notable_hosts)} with notable exposure", ORANGE)
                 if notable_hosts else _c("   ·   nothing notable", DRED))
        content.append(line)
        for d, s in notable_hosts[:4]:
            svcs = ", ".join(svc for _, svc, _ in s["notable"])
            content.append("  " + _c("! ", ORANGE) + _c(f"{d['ip']:15} ", ORANGE)
                           + _c(svcs, RED) + _c("   (press [3] for detail)", DRED))
    else:
        content.append(_c("  no open ports seen yet; try [2] for an intensive scan", DRED))
    content.append("")

    # expanded per-device inspector (toggled with [3])
    if verbose and ordered:
        content += _detail_block(ordered[sel])
        content.append("")

    # legend + menu always render (the user must be able to see the controls)
    tail: list[str] = []
    tail.append(" " + _c("router", AMBER) + _c("  apple", CYAN) + _c("  windows", GREEN)
                + _c("  iot/media", ORANGE) + _c("  printer", BLUE) + _c("  firewalled", VIOLET)
                + _c("   (~ stale  ? anonymized)", DRED))
    det = "on" if verbose else "off"
    evm = "expanded" if events_expanded else "compact"
    tail.append(_c(" [1]", BOLD + BRED) + _c(" rescan   ", RED) + _c("[2]", BOLD + BRED)
                + _c(" intensive   ", RED) + _c("[3]", BOLD + BRED) + _c(f" details ({det})   ", RED)
                + _c("[4]", BOLD + BRED) + _c(f" events ({evm})   ", RED) + _c("[0]", BOLD + BRED)
                + _c(" quit", RED))
    if notice:
        tail.append(_c(" > " + notice, BRED))

    # events feed: the flexible section. Show as many as fit the terminal height
    # (most expendable), so the frame never overflows and tears the redraw.
    evs = snap["events"]
    limit = 18 if events_expanded else 6
    avail = (height - 2 - len(content) - len(tail)) if height else 10_000   # rows for the events block
    if avail >= 3:                          # room for header + >=1 line + blank
        n = max(0, min(limit, len(evs), avail - 2))
        more = len(evs) - n
        header = " EVENTS" + (f"  (showing {n} of {len(evs)})" if (events_expanded or more) else "")
        content.append(_c(header, BRED))
        if n:
            for e in evs[:n]:
                tag = _EVENT_TAG.get(e["type"], "*")
                when = _c(f"{e['time']} ", DRED) if events_expanded and e.get("time") else ""
                detail = _c(f"  ({e['detail']})", DRED) if e.get("detail") else ""
                content.append("  " + _c(tag, BRED) + " " + when + _c(f"{e['type']:14}", RED)
                               + " " + _c(e["label"], RED) + detail)
        else:
            content.append(_c("  (no activity yet)", DRED))
        content.append("")
    content += tail

    return "\n".join(_border(content, width))


def run(scan_fn, interval: int = 30, state_path: str | None = None,
        do_passive: bool = True, intensive: bool = False) -> None:
    _enable_ansi()
    try:
        import msvcrt
    except ImportError:
        msvcrt = None

    # Ephemeral by design: keep device state in memory only (state_path=None), and
    # remove any state file an earlier version may have left in the run directory.
    try:
        os.remove("netmapper_state.json")
    except OSError:
        pass

    dash = Engine(scan_fn, interval, state_path, do_passive, intensive=intensive)
    dash.start()
    ui = {"verbose": False, "notice": "", "until": 0.0, "sel": 0, "ndev": 0,
          "events_expanded": False}

    def notify(msg):
        ui["notice"] = msg
        ui["until"] = time.time() + 5

    def on_key(ch):
        if ch in ("q", "0"):
            return False
        if ch == "1":
            dash.request_rescan(); notify("rescanning now…")
        elif ch == "2":
            dash.request_intensive(); notify("intensive scan started (wider port sweep)…")
        elif ch == "3":
            ui["verbose"] = not ui["verbose"]
            notify(f"details panel {'on (use up/down to inspect a device)' if ui['verbose'] else 'off'}")
        elif ch == "4":
            ui["events_expanded"] = not ui["events_expanded"]
            notify(f"events view {'expanded' if ui['events_expanded'] else 'compact'}")
        elif ch in ("up", "k"):
            ui["verbose"] = True
            ui["sel"] = max(0, ui["sel"] - 1)
        elif ch in ("down", "j"):
            ui["verbose"] = True
            ui["sel"] = min(max(0, ui["ndev"] - 1), ui["sel"] + 1)
        return True

    def read_key():
        raw = msvcrt.getwch()
        if raw in ("\x00", "\xe0"):                 # arrow / function key prefix
            return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
        return raw.lower()

    sys.stdout.write("\033[2J")
    try:
        running = True
        while running and not dash.stop.is_set():
            snap = dash.snapshot()
            ui["ndev"] = len(snap["devices"])
            ui["sel"] = max(0, min(ui["sel"], ui["ndev"] - 1)) if ui["ndev"] else 0
            notice = ui["notice"] if time.time() < ui["until"] else ""
            size = shutil.get_terminal_size((112, 48))   # adapt to the live terminal
            cols = max(72, size.columns)
            rows = max(20, size.lines)
            width = min(cols - 1, 108)
            frame = _frame(snap, ui["verbose"], notice, width, ui["sel"],
                           ui["events_expanded"], height=rows)
            body = "\n".join(_clip_ansi(line, cols - 1) + "\033[K" for line in frame.split("\n"))
            sys.stdout.write("\033[H" + body + "\033[J")
            sys.stdout.flush()
            deadline = time.time() + 1.0
            while running and time.time() < deadline:
                if msvcrt and msvcrt.kbhit():
                    key = read_key()
                    if key:
                        running = on_key(key)
                time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    finally:
        dash.shutdown()
        for th in (dash.active_thread, dash.passive_thread):
            if th:
                th.join(timeout=2)
        # Ephemeral by design: don't leave a state file behind after closing.
        if state_path:
            try:
                os.remove(state_path)
            except OSError:
                pass
        sys.stdout.write(RESET + "\033[2J\033[H netmapper stopped.\n")
        sys.stdout.flush()
