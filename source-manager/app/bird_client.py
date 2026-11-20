"""Pure-Python BIRD 2 Unix control socket client (replaces docker.sock / FRR vtysh)."""

import os
import re
import socket
import threading

_BIRD_LOCK = threading.Lock()
_TERM_RE = re.compile(r"^(0(?!00[12])\d{3}|[89]\d{3}) ")
_CODE_PREFIX_RE = re.compile(r"^\d{4}[- ]")


def get_bird_socket() -> str:
    return os.environ.get("BIRD_SOCKET", "/run/bird/bird.ctl")


def _strip_bird_prefix(raw_line: str) -> str:
    line = raw_line.rstrip("\r\n")
    if _CODE_PREFIX_RE.match(line):
        return line[5:]
    if line.startswith(" "):
        return line[1:]
    return line


def bird_cmd(cmd: str, timeout: float = 10.0) -> tuple[bool, str, list[str]]:
    """Send a single command over BIRD's control socket and return (ok, code, lines)."""
    sock_path = get_bird_socket()
    with _BIRD_LOCK:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            reader = s.makefile("r", encoding="utf-8", errors="replace")
            greeting = reader.readline()
            if not greeting.startswith("0001"):
                raise RuntimeError(f"Unexpected BIRD greeting: {greeting.strip()}")

            s.sendall((cmd.strip() + "\n").encode("utf-8"))
            lines: list[str] = []
            terminal_code = "9999"
            while True:
                raw = reader.readline()
                if not raw:
                    break
                lines.append(_strip_bird_prefix(raw))
                match = _TERM_RE.match(raw)
                if match:
                    terminal_code = match.group(1)
                    break

            ok = not terminal_code.startswith(("8", "9"))
            return ok, terminal_code, lines


def bird_configure() -> str:
    """Reload BIRD configuration and verify it accepted the routes."""
    ok, code, lines = bird_cmd("configure", timeout=30.0)
    output = "\n".join(lines).strip()
    if not ok or (code != "0003" and "Reconfigured" not in output):
        raise RuntimeError(f"BIRD rejected configuration ({code}): {output[-1000:]}")
    return output


def bird_status() -> dict:
    """Return BIRD daemon status information."""
    try:
        ok, _code, lines = bird_cmd("show status", timeout=5.0)
        text = "\n".join(lines)
        version_match = re.search(r"BIRD\s+([0-9.]+)", text)
        rid_match = re.search(r"Router ID is\s+([0-9.]+)", text)
        reboot_match = re.search(r"Last reboot on\s+(.+)", text)
        reconfig_match = re.search(r"Last reconfiguration on\s+(.+)", text)
        up = ok and "Daemon is up and running" in text
        return {
            "up": up,
            "version": version_match.group(1) if version_match else "2.x",
            "router_id": rid_match.group(1) if rid_match else "—",
            "last_reboot": reboot_match.group(1).strip() if reboot_match else "—",
            "last_reconfig": reconfig_match.group(1).strip() if reconfig_match else "—",
        }
    except Exception as exc:
        return {"up": False, "error": str(exc), "version": "—", "router_id": "—"}


def bird_route_count() -> int:
    """Return total active IPv4 routes in BIRD master4 table."""
    try:
        ok, _code, lines = bird_cmd("show route count", timeout=5.0)
        if not ok:
            return 0
        text = "\n".join(lines)
        m = re.search(r"(\d+)\s+of\s+\d+\s+routes\s+for\s+\d+\s+networks\s+in\s+table\s+master4", text)
        if m:
            return int(m.group(1))
        m_total = re.search(r"Total:\s+(\d+)\s+of", text)
        return int(m_total.group(1)) if m_total else 0
    except Exception:
        return 0


def parse_protocols_all(lines: list[str]) -> list[dict]:
    """Parse `show protocols all` text lines for dynamic/static BGP client sessions."""
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.startswith("Name ") and "Proto" in line:
            continue
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        if not line.startswith(" "):
            if current:
                blocks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append(current)

    peers: list[dict] = []
    for blk in blocks:
        header = blk[0].split()
        if len(header) < 5 or header[1] != "BGP":
            continue
        body = "\n".join(blk)
        # Skip the passive listener template protocol (has no Neighbor address)
        nbr_match = re.search(r"Neighbor address:\s+([0-9a-fA-F:.]+)", body)
        if not nbr_match:
            continue

        bgp_state_m = re.search(r"BGP state:\s+(.+)", body)
        nas_m = re.search(r"Neighbor AS:\s+(\d+)", body)
        las_m = re.search(r"Local AS:\s+(\d+)", body)
        nid_m = re.search(r"Neighbor ID:\s+([0-9.]+)", body)
        hold_m = re.search(r"Hold timer:\s+([0-9./]+)", body)
        ka_m = re.search(r"Keepalive timer:\s+([0-9./]+)", body)
        routes_m = re.search(r"Routes:\s+(\d+)\s+imported,\s+(\d+)\s+exported,\s+(\d+)\s+preferred", body)
        upd_m = re.search(r"Export updates:\s+\d+\s+\d+\s+\d+\s+---\s+(\d+)", body)
        wd_m = re.search(r"Export withdraws:\s+\d+\s+---\s+---\s+---\s+(\d+)", body)

        state = bgp_state_m.group(1).strip() if bgp_state_m else (header[5] if len(header) > 5 else header[3])
        peers.append(
            {
                "name": header[0],
                "ip": nbr_match.group(1),
                "remote_as": int(nas_m.group(1)) if nas_m else "—",
                "local_as": int(las_m.group(1)) if las_m else "—",
                "router_id": nid_m.group(1) if nid_m else "—",
                "state": state,
                "since": header[4],
                "exported_routes": int(routes_m.group(2)) if routes_m else 0,
                "imported_routes": int(routes_m.group(1)) if routes_m else 0,
                "hold_timer": hold_m.group(1) if hold_m else "—",
                "keepalive_timer": ka_m.group(1) if ka_m else "—",
                "updates_sent": int(upd_m.group(1)) if upd_m else 0,
                "withdraws_sent": int(wd_m.group(1)) if wd_m else 0,
            }
        )
    return peers


def bird_peers() -> list[dict]:
    """Return active BGP peers connected to BIRD."""
    try:
        ok, _code, lines = bird_cmd("show protocols all", timeout=5.0)
        if not ok:
            return []
        return parse_protocols_all(lines)
    except Exception:
        return []
