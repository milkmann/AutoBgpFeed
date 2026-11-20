"""Core route collection, CIDR math, Smart-DNS, transactional BIRD apply, previews, provenance, and backups."""

import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import uuid

import dns.resolver
import httpx

from .bird_client import bird_configure, bird_route_count
from .db import DEFAULT_SETTINGS, get_db, get_settings, set_settings

_REBUILD_LOCK = threading.Lock()
_CLOUDFLARE_LOCK = threading.Lock()

CLOUDFLARE_NETWORKS = [
    ipaddress.IPv4Network("173.245.48.0/20"),
    ipaddress.IPv4Network("103.21.244.0/22"),
    ipaddress.IPv4Network("103.22.200.0/22"),
    ipaddress.IPv4Network("103.31.4.0/22"),
    ipaddress.IPv4Network("141.101.64.0/18"),
    ipaddress.IPv4Network("108.162.192.0/18"),
    ipaddress.IPv4Network("190.93.240.0/20"),
    ipaddress.IPv4Network("188.114.96.0/20"),
    ipaddress.IPv4Network("197.234.240.0/22"),
    ipaddress.IPv4Network("198.41.128.0/17"),
    ipaddress.IPv4Network("162.158.0.0/15"),
    ipaddress.IPv4Network("104.16.0.0/12"),
    ipaddress.IPv4Network("172.64.0.0/13"),
    ipaddress.IPv4Network("131.0.72.0/22"),
]

FASTLY_NETWORKS = [
    ipaddress.IPv4Network("151.101.0.0/16"),
    ipaddress.IPv4Network("199.232.0.0/16"),
    ipaddress.IPv4Network("23.235.32.0/20"),
    ipaddress.IPv4Network("43.249.72.0/22"),
]

CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")

COUNTRY_MAP = {
    "ua": ("UA", "Ukraine (Украина)", 804),
    "ukraine": ("UA", "Ukraine (Украина)", 804),
    "украина": ("UA", "Ukraine (Украина)", 804),
    "україна": ("UA", "Ukraine (Украина)", 804),
    "ru": ("RU", "Russia (Россия)", 643),
    "russia": ("RU", "Russia (Россия)", 643),
    "россия": ("RU", "Russia (Россия)", 643),
    "рф": ("RU", "Russia (Россия)", 643),
    "pl": ("PL", "Poland (Польша)", 616),
    "poland": ("PL", "Poland (Польша)", 616),
    "польша": ("PL", "Poland (Польша)", 616),
    "kz": ("KZ", "Kazakhstan (Казахстан)", 398),
    "kazakhstan": ("KZ", "Kazakhstan (Казахстан)", 398),
    "казахстан": ("KZ", "Kazakhstan (Казахстан)", 398),
    "by": ("BY", "Belarus (Беларусь)", 112),
    "belarus": ("BY", "Belarus (Беларусь)", 112),
    "беларусь": ("BY", "Belarus (Беларусь)", 112),
    "ge": ("GE", "Georgia (Грузия)", 268),
    "georgia": ("GE", "Georgia (Грузия)", 268),
    "грузия": ("GE", "Georgia (Грузия)", 268),
    "am": ("AM", "Armenia (Армения)", 51),
    "armenia": ("AM", "Armenia (Армения)", 51),
    "армения": ("AM", "Armenia (Армения)", 51),
    "az": ("AZ", "Azerbaijan (Азербайджан)", 31),
    "azerbaijan": ("AZ", "Azerbaijan (Азербайджан)", 31),
    "азербайджан": ("AZ", "Azerbaijan (Азербайджан)", 31),
    "uz": ("UZ", "Uzbekistan (Узбекистан)", 860),
    "uzbekistan": ("UZ", "Uzbekistan (Узбекистан)", 860),
    "узбекистан": ("UZ", "Uzbekistan (Узбекистан)", 860),
    "md": ("MD", "Moldova (Молдова)", 498),
    "moldova": ("MD", "Moldova (Молдова)", 498),
    "молдова": ("MD", "Moldova (Молдова)", 498),
    "tr": ("TR", "Turkey (Турция)", 792),
    "turkey": ("TR", "Turkey (Турция)", 792),
    "турция": ("TR", "Turkey (Турция)", 792),
    "de": ("DE", "Germany (Германия)", 276),
    "germany": ("DE", "Germany (Германия)", 276),
    "германия": ("DE", "Germany (Германия)", 276),
    "us": ("US", "United States (США)", 840),
    "usa": ("US", "United States (США)", 840),
    "сша": ("US", "United States (США)", 840),
    "nl": ("NL", "Netherlands (Нидерланды)", 528),
    "netherlands": ("NL", "Netherlands (Нидерланды)", 528),
    "нидерланды": ("NL", "Netherlands (Нидерланды)", 528),
    "gb": ("GB", "United Kingdom (Великобритания)", 826),
    "uk": ("GB", "United Kingdom (Великобритания)", 826),
    "великобритания": ("GB", "United Kingdom (Великобритания)", 826),
    "fr": ("FR", "France (Франция)", 250),
    "france": ("FR", "France (Франция)", 250),
    "франция": ("FR", "France (Франция)", 250),
}

DELEGATED_REGISTRIES = ("ripencc", "arin", "apnic", "lacnic", "afrinic")
DELEGATED_BASE_URL = "https://ftp.apnic.net/pub/stats"
LIST_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def get_data_dir() -> str:
    return os.environ.get("DATA_DIR", "/data")


def get_generated_dir() -> str:
    return os.environ.get("GENERATED_DIR", "/generated")


def get_server_ip() -> str:
    return os.environ.get("SERVER_IP", "").strip()


def get_server_asn() -> int:
    try:
        return int(os.environ.get("SERVER_ASN", "65000"))
    except ValueError:
        return 65000


def get_min_prefix_length() -> int:
    try:
        return max(1, min(32, int(os.environ.get("MIN_PREFIX_LENGTH", "8"))))
    except ValueError:
        return 8


def get_cache_max_age() -> int:
    try:
        return max(60, int(os.environ.get("CACHE_MAX_AGE", "604800")))
    except ValueError:
        return 604800


def _atomic_write_text(path: str, content: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def _atomic_write_json(path: str, obj: dict | list) -> None:
    _atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2))


def _read_json(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def log_msg(message: str, level: str = "INFO") -> None:
    conn = None
    try:
        conn = get_db()
        with conn:
            conn.execute("INSERT INTO logs (level, message) VALUES (?, ?)", (level, message))
            conn.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 300)")
    except Exception:
        pass
    finally:
        if conn:
            conn.close()
    print(f"[{level}] {message}", flush=True)


def format_ip_human(num: int) -> str:
    if not num:
        return "0 IP"
    if num >= 1_000_000:
        val = round(num / 1_000_000, 1)
        return f"~{val:g} млн IP"
    if num >= 1_000:
        val = round(num / 1_000, 1)
        return f"{val:g} тыс. IP"
    return f"{num} IP"


def _is_unsafe_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True
    if ip_obj.version == 4 and ip_obj in CGNAT_NETWORK:
        return True
    return False


def is_valid_ipv4_net(
    cidr_str: str,
    min_prefix_length: int | None = None,
    allow_broad: bool = False,
) -> ipaddress.IPv4Network | None:
    """Parse an IPv4 CIDR string and reject private, loopback, CGNAT, server IP, or overly broad prefixes."""
    try:
        net = ipaddress.IPv4Network(str(cidr_str).strip(), strict=False)
    except Exception:
        return None

    if net.prefixlen == 0:
        return None
    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved or net.is_unspecified:
        return None
    if net.overlaps(CGNAT_NETWORK) and net.subnet_of(CGNAT_NETWORK):
        return None

    server_ip = get_server_ip()
    if server_ip:
        try:
            srv_addr = ipaddress.IPv4Address(server_ip)
            if net.prefixlen == 32 and srv_addr in net:
                return None
        except ValueError:
            pass

    min_len = get_min_prefix_length() if min_prefix_length is None else min_prefix_length
    if not allow_broad and net.prefixlen < min_len:
        return None

    return net


def _resolve_host_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    ips = []
    for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
        addr = info[4][0].split("%")[0]
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return ips


def validate_external_url(url: str) -> str:
    """Allow only public http/https URLs and block SSRF to loopback, private, link-local, or metadata hosts."""
    clean = (url or "").strip()
    parsed = urllib.parse.urlparse(clean)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme or 'none'}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a hostname")

    if hostname.lower() in ("localhost", "localhost.localdomain"):
        raise ValueError("Localhost URLs are forbidden")

    # Literal IP check first
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if _is_unsafe_ip(ip_obj):
            raise ValueError(f"Target IP {ip_obj} is private/reserved")
        return clean
    except ValueError as exc:
        if "private/reserved" in str(exc):
            raise

    resolved = _resolve_host_ips(hostname)
    if not resolved:
        raise ValueError(f"Cannot resolve host: {hostname}")
    for ip_obj in resolved:
        if _is_unsafe_ip(ip_obj):
            raise ValueError(f"Target host resolves to forbidden IP {ip_obj}")
    return clean


def _safe_http_get_text(url: str, timeout: float = 12.0, validate_ssrf: bool = True) -> str:
    current_url = validate_external_url(url) if validate_ssrf else url
    headers = {"User-Agent": "AutoBgpFeed/2.0"}
    with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers) as client:
        for _ in range(4):
            resp = client.get(current_url)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location")
                if not loc:
                    break
                next_url = urllib.parse.urljoin(current_url, loc)
                current_url = validate_external_url(next_url) if validate_ssrf else next_url
                continue
            resp.raise_for_status()
            return resp.text
    raise RuntimeError(f"Too many redirects fetching {url}")


def subtract_networks(
    networks: list[ipaddress.IPv4Network],
    excluded: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Subtract excluded CIDRs from networks using exact IPv4 address exclusion and collapse."""
    if not networks:
        return []
    if not excluded:
        return list(ipaddress.collapse_addresses(networks))

    collapsed_exc = list(ipaddress.collapse_addresses(excluded))
    result: list[ipaddress.IPv4Network] = []
    for network in networks:
        remaining = [network]
        for exc in collapsed_exc:
            next_remaining: list[ipaddress.IPv4Network] = []
            for cand in remaining:
                if not cand.overlaps(exc):
                    next_remaining.append(cand)
                elif cand.subnet_of(exc):
                    continue
                elif exc.subnet_of(cand):
                    next_remaining.extend(cand.address_exclude(exc))
                else:
                    next_remaining.append(cand)
            remaining = next_remaining
            if not remaining:
                break
        result.extend(remaining)
    return list(ipaddress.collapse_addresses(result))


def resolve_country_input(q: str) -> tuple[str, str, int]:
    if not q:
        return ("UN", "Unknown Country", 1000)
    q_clean = q.strip().lower()
    if q_clean in COUNTRY_MAP:
        return COUNTRY_MAP[q_clean]
    if len(q_clean) == 2 and q_clean.isalpha():
        cc = q_clean.upper()
        return (cc, f"Country {cc}", 1000)
    return (q[:2].upper(), q, 1000)


def update_cloudflare_ranges() -> None:
    try:
        text = _safe_http_get_text("https://www.cloudflare.com/ips-v4", timeout=6.0, validate_ssrf=False)
        fetched = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                net = is_valid_ipv4_net(line)
                if net:
                    fetched.append(net)
        if fetched:
            with _CLOUDFLARE_LOCK:
                CLOUDFLARE_NETWORKS[:] = fetched
            log_msg(f"Обновлены официальные диапазоны Cloudflare: {len(fetched)} блоков", "INFO")
    except Exception as e:
        log_msg(f"Используются встроенные диапазоны Cloudflare: {e}", "INFO")


def is_cdn_anycast(ip_obj: ipaddress.IPv4Address) -> bool:
    with _CLOUDFLARE_LOCK:
        cf_nets = list(CLOUDFLARE_NETWORKS)
    return any(ip_obj in net for net in cf_nets) or any(ip_obj in net for net in FASTLY_NETWORKS)


def parse_delegated_stats(
    text: str,
    country_code: str,
    min_prefix_length: int = 8,
    allow_broad: bool = False,
) -> list[ipaddress.IPv4Network]:
    """Parse RIR delegated-*-latest stats accurately using summarize_address_range."""
    cc = country_code.strip().upper()
    nets: list[ipaddress.IPv4Network] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        registry, rec_cc, rtype, start, value, _date, status = parts[:7]
        if registry == "version" or value == "summary":
            continue
        if rec_cc.upper() != cc or rtype != "ipv4" or status not in ("allocated", "assigned"):
            continue
        try:
            start_ip = ipaddress.IPv4Address(start)
            count = int(value)
        except Exception:
            continue
        if count <= 0:
            continue
        end_ip = ipaddress.IPv4Address(int(start_ip) + count - 1)
        for net in ipaddress.summarize_address_range(start_ip, end_ip):
            valid = is_valid_ipv4_net(str(net), min_prefix_length=min_prefix_length, allow_broad=allow_broad)
            if valid:
                nets.append(valid)
    return list(ipaddress.collapse_addresses(nets))


def fetch_country_prefixes(
    country_code: str,
    force_download: bool = False,
    min_prefix_length: int | None = None,
    allow_broad: bool = False,
) -> list[str]:
    cc = country_code.strip().upper()
    cache_file = os.path.join(get_data_dir(), "last-good", f"{cc.lower()}_prefixes.txt")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    min_len = get_min_prefix_length() if min_prefix_length is None else min_prefix_length

    if not force_download and os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            cached = [l.strip() for l in f if l.strip()]
        if cached:
            return cached

    nets: list[ipaddress.IPv4Network] = []

    # 1) Primary: RIPE Stat country resource list
    try:
        ripe_url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={cc.lower()}&v4_format=prefix"
        data = json.loads(_safe_http_get_text(ripe_url, timeout=15.0, validate_ssrf=False))
        for item in data.get("data", {}).get("resources", {}).get("ipv4", []):
            net = is_valid_ipv4_net(str(item), min_prefix_length=min_len, allow_broad=allow_broad)
            if net:
                nets.append(net)
    except Exception as e:
        log_msg(f"RIPEstat для страны {cc} недоступен ({e}), пробуем IPverse...", "WARN")

    # 2) Secondary: IPverse
    if not nets:
        try:
            ipverse_url = f"https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{cc.lower()}/ipv4-aggregated.txt"
            text = _safe_http_get_text(ipverse_url, timeout=15.0, validate_ssrf=False)
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    net = is_valid_ipv4_net(line, min_prefix_length=min_len, allow_broad=allow_broad)
                    if net:
                        nets.append(net)
        except Exception as e:
            log_msg(f"IPverse для страны {cc} недоступен ({e}), пробуем 5 RIR delegated...", "WARN")

    # 3) Fallback: all 5 delegated RIR stats via summarize_address_range
    if not nets:
        delegated_nets: list[ipaddress.IPv4Network] = []
        for registry in DELEGATED_REGISTRIES:
            try:
                url = f"{DELEGATED_BASE_URL}/{registry}/delegated-{registry}-latest"
                text = _safe_http_get_text(url, timeout=20.0, validate_ssrf=False)
                delegated_nets.extend(parse_delegated_stats(text, cc, min_prefix_length=min_len, allow_broad=allow_broad))
            except Exception as e:
                log_msg(f"Ошибка загрузки delegated-{registry} для {cc}: {e}", "WARN")
        nets = delegated_nets

    if nets:
        collapsed = list(ipaddress.collapse_addresses(nets))
        _atomic_write_text(cache_file, "\n".join(str(n) for n in collapsed) + "\n")
        return [str(n) for n in collapsed]

    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    return []


def fetch_ru_prefixes(force_download: bool = False) -> list[str]:
    return fetch_country_prefixes("RU", force_download=force_download)


def fetch_google_non_cloud(min_prefix_length: int | None = None, allow_broad: bool = False) -> list[str]:
    """Fetch official Google IP ranges excluding Google Cloud customer ranges."""
    min_len = get_min_prefix_length() if min_prefix_length is None else min_prefix_length
    goog_data = json.loads(_safe_http_get_text("https://www.gstatic.com/ipranges/goog.json", timeout=12.0, validate_ssrf=False))
    cloud_data = json.loads(_safe_http_get_text("https://www.gstatic.com/ipranges/cloud.json", timeout=12.0, validate_ssrf=False))

    goog_nets = []
    for item in goog_data.get("prefixes", []):
        p = item.get("ipv4Prefix")
        if p:
            n = is_valid_ipv4_net(p, min_prefix_length=min_len, allow_broad=allow_broad)
            if n:
                goog_nets.append(n)

    cloud_nets = []
    for item in cloud_data.get("prefixes", []):
        p = item.get("ipv4Prefix")
        if p:
            n = is_valid_ipv4_net(p, min_prefix_length=min_len, allow_broad=allow_broad)
            if n:
                cloud_nets.append(n)

    diff = subtract_networks(goog_nets, cloud_nets)
    return [str(n) for n in diff]


def _get_configured_resolvers(settings: dict[str, str] | None = None) -> list[str]:
    s = settings if settings is not None else get_settings()
    raw = s.get("dns_resolvers", DEFAULT_SETTINGS["dns_resolvers"])
    resolvers = []
    for part in re.split(r"[\s,;]+", raw):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.IPv4Address(part)
            resolvers.append(part)
        except ValueError:
            continue
    return resolvers or ["1.1.1.1", "8.8.8.8"]


def resolve_domain_ips(domain: str, resolvers: list[str] | None = None, include_www: bool = True) -> set[str]:
    """Resolve raw A records for a domain across configured DNS servers."""
    d_clean = domain.strip().lower()
    if d_clean.startswith("http://") or d_clean.startswith("https://"):
        d_clean = urllib.parse.urlparse(d_clean).hostname or d_clean
    d_clean = d_clean.rstrip(".")

    # Literal IPv4 shortcut
    try:
        ip_obj = ipaddress.IPv4Address(d_clean)
        return {str(ip_obj)} if not _is_unsafe_ip(ip_obj) else set()
    except ValueError:
        pass

    servers = resolvers or _get_configured_resolvers()
    subdomains = [d_clean]
    if include_www and not d_clean.startswith("www."):
        subdomains.append(f"www.{d_clean}")

    resolved_ips: set[str] = set()
    for srv in servers:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [srv]
        res.timeout = 0.9
        res.lifetime = 1.4
        for sub in subdomains:
            try:
                ans = res.resolve(sub, "A")
                for rdata in ans:
                    resolved_ips.add(rdata.to_text())
            except Exception:
                continue
    return resolved_ips


def resolve_domain(
    domain: str,
    cdn_mode: str = "auto",
    resolvers: list[str] | None = None,
    cache_ttl: int | None = None,
    use_dns_cache: bool = True,
) -> list[str]:
    """Smart-DNS classifier with TTL caching for rotating CDNs and configurable /24 expansion."""
    d_clean = domain.strip().lower()
    if d_clean.startswith("http://") or d_clean.startswith("https://"):
        d_clean = urllib.parse.urlparse(d_clean).hostname or d_clean
    d_clean = d_clean.rstrip(".")

    settings = get_settings()
    ttl = cache_ttl if cache_ttl is not None else int(settings.get("dns_cache_ttl_sec", "86400"))
    fresh_ips = resolve_domain_ips(d_clean, resolvers=resolvers or _get_configured_resolvers(settings))
    now_ts = int(time.time())

    all_ips = set(fresh_ips)
    if use_dns_cache:
        conn = None
        try:
            conn = get_db()
            with conn:
                for ip_str in fresh_ips:
                    conn.execute(
                        "INSERT OR REPLACE INTO dns_cache (domain, ip, last_seen) VALUES (?, ?, ?)",
                        (d_clean, ip_str, now_ts),
                    )
                cutoff = now_ts - max(60, ttl)
                conn.execute("DELETE FROM dns_cache WHERE last_seen < ?", (cutoff,))
                rows = conn.execute("SELECT ip FROM dns_cache WHERE domain = ?", (d_clean,)).fetchall()
                for r in rows:
                    all_ips.add(r["ip"])
        except Exception:
            pass
        finally:
            if conn:
                conn.close()

    if not all_ips:
        return []

    final_nets: list[ipaddress.IPv4Network] = []
    for ip_str in sorted(all_ips):
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            if _is_unsafe_ip(ip_obj):
                continue
            if cdn_mode == "subnet24" or (cdn_mode == "auto" and is_cdn_anycast(ip_obj)):
                net = is_valid_ipv4_net(f"{ip_str}/24")
            else:
                net = is_valid_ipv4_net(f"{ip_str}/32")
            if net:
                final_nets.append(net)
        except Exception:
            continue

    return [str(n) for n in ipaddress.collapse_addresses(final_nets)]


def fetch_asn(asn_str: str, min_prefix_length: int | None = None, allow_broad: bool = False) -> list[str]:
    asn_num = re.sub(r"[^0-9]", "", str(asn_str))
    if not asn_num:
        return []
    min_len = get_min_prefix_length() if min_prefix_length is None else min_prefix_length
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
    data = json.loads(_safe_http_get_text(url, timeout=8.0, validate_ssrf=False))
    prefixes = []
    for item in data.get("data", {}).get("prefixes", []):
        p = item.get("prefix")
        if p and ":" not in p:
            net = is_valid_ipv4_net(p, min_prefix_length=min_len, allow_broad=allow_broad)
            if net:
                prefixes.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(prefixes)]


def fetch_external_url(url: str, min_prefix_length: int | None = None, allow_broad: bool = False) -> list[str]:
    min_len = get_min_prefix_length() if min_prefix_length is None else min_prefix_length
    content = _safe_http_get_text(url, timeout=10.0, validate_ssrf=True)
    prefixes: list[ipaddress.IPv4Network] = []
    broad_rejected: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split()[0]
        if "/" not in token:
            token = f"{token}/32"
        try:
            raw_net = ipaddress.IPv4Network(token, strict=False)
        except ValueError:
            continue
        if not allow_broad and 0 < raw_net.prefixlen < min_len:
            broad_rejected.append(str(raw_net))
            continue
        net = is_valid_ipv4_net(token, min_prefix_length=min_len, allow_broad=allow_broad)
        if net:
            prefixes.append(net)

    if broad_rejected and not prefixes:
        raise ValueError(f"Rejected overly broad prefix (< /{min_len}): {', '.join(broad_rejected[:3])}")
    return [str(n) for n in ipaddress.collapse_addresses(prefixes)]


def _source_cache_path(source_id: int) -> str:
    return os.path.join(get_data_dir(), "cache", f"source_{source_id}.json")


def save_source_cache(source_id: int, prefixes: list[str]) -> str:
    now_str = datetime.datetime.now().strftime("%d.%m.%Y, %H:%M:%S")
    _atomic_write_json(
        _source_cache_path(source_id),
        {"updated_at": int(time.time()), "updated_str": now_str, "prefixes": prefixes},
    )
    return now_str


def load_source_cache(source_id: int, max_age: int | None = None) -> tuple[list[str], str | None]:
    data = _read_json(_source_cache_path(source_id))
    if not data or not isinstance(data.get("prefixes"), list):
        return [], None
    age_limit = get_cache_max_age() if max_age is None else max_age
    ts = int(data.get("updated_at", 0))
    if time.time() - ts > age_limit:
        return [], None
    return [str(p) for p in data["prefixes"]], data.get("updated_str")


def _parse_community(comm_str: str, fallback_asn: int) -> tuple[int, int]:
    if comm_str and ":" in comm_str:
        parts = comm_str.strip().split(":", 1)
        try:
            return int(parts[0]), int(parts[1])
        except ValueError:
            pass
    return fallback_asn, 1000


def _collect_single_source(
    src: dict,
    force_download: bool,
    min_prefix_length: int,
    allow_broad: bool,
    resolvers: list[str],
    cache_ttl: int,
) -> dict:
    s_id = int(src["id"])
    s_type = str(src["type"]).upper()
    s_val = str(src["value"]).strip()
    cdn_mode = str(src.get("cdn_mode") or "auto")
    now_str = datetime.datetime.now().strftime("%d.%m.%Y, %H:%M:%S")

    prefixes: list[str] = []
    err: str | None = None
    degraded = False
    cached_at = src.get("cached_at")

    try:
        if s_type == "COUNTRY":
            prefixes = fetch_country_prefixes(
                s_val, force_download=force_download, min_prefix_length=min_prefix_length, allow_broad=allow_broad
            )
            if not prefixes:
                raise RuntimeError(f"Empty country list for {s_val}")
        elif s_type == "DOMAIN":
            prefixes = resolve_domain(s_val, cdn_mode=cdn_mode, resolvers=resolvers, cache_ttl=cache_ttl)
            if not prefixes:
                raise RuntimeError(f"DNS resolved 0 IPv4 addresses for {s_val}")
        elif s_type == "ASN":
            prefixes = fetch_asn(s_val, min_prefix_length=min_prefix_length, allow_broad=allow_broad)
            if not prefixes:
                raise RuntimeError(f"RIPEstat returned 0 prefixes for {s_val}")
        elif s_type == "PREFIX":
            token = s_val if "/" in s_val else f"{s_val}/32"
            net = is_valid_ipv4_net(token, min_prefix_length=min_prefix_length, allow_broad=allow_broad)
            if not net:
                raise ValueError(f"Invalid or forbidden IPv4 prefix: {s_val}")
            prefixes = [str(net)]
        elif s_type == "EXTERNAL_URL":
            prefixes = fetch_external_url(s_val, min_prefix_length=min_prefix_length, allow_broad=allow_broad)
            if not prefixes:
                raise RuntimeError(f"URL returned 0 valid prefixes: {s_val}")
        elif s_type == "GOOGLE":
            prefixes = fetch_google_non_cloud(min_prefix_length=min_prefix_length, allow_broad=allow_broad)
            if not prefixes:
                raise RuntimeError("Google IP ranges fetch returned 0 prefixes")
        else:
            raise ValueError(f"Unknown source type: {s_type}")

        cached_at = save_source_cache(s_id, prefixes)
    except Exception as exc:
        err = str(exc)
        cached_prefixes, cached_ts = load_source_cache(s_id)
        if cached_prefixes:
            prefixes = cached_prefixes
            cached_at = cached_ts or cached_at
            degraded = True
            log_msg(f"Источник «{src['name']}» недоступен ({err}) — используется кеш ({len(prefixes)} преф.)", "WARN")
        else:
            log_msg(f"Ошибка источника «{src['name']}»: {err}", "ERROR")

    return {
        "id": s_id,
        "name": src["name"],
        "type": s_type,
        "value": s_val,
        "community": src.get("community") or f"{get_server_asn()}:1000",
        "gateway": src.get("gateway") or "wireguard1",
        "cdn_mode": cdn_mode,
        "prefixes": prefixes,
        "error": err,
        "degraded": degraded,
        "status": "degraded" if degraded else ("error" if err and not prefixes else "active"),
        "last_update": now_str,
        "cached_at": cached_at,
    }


def _resolve_exclusion_nets(exclusions: list[dict], resolvers: list[str]) -> list[dict]:
    resolved: list[dict] = []
    for exc in exclusions:
        e_type = str(exc.get("type") or "PREFIX").upper()
        e_val = str(exc.get("value") or "").strip()
        if not e_val:
            continue
        nets: list[ipaddress.IPv4Network] = []
        if e_type == "DOMAIN":
            ips = resolve_domain_ips(e_val, resolvers=resolvers)
            for ip_str in ips:
                n = is_valid_ipv4_net(f"{ip_str}/32", min_prefix_length=1, allow_broad=True)
                if n:
                    nets.append(n)
        else:
            token = e_val if "/" in e_val else f"{e_val}/32"
            n = is_valid_ipv4_net(token, min_prefix_length=1, allow_broad=True)
            if n:
                nets.append(n)
        if nets:
            resolved.append(
                {
                    "id": exc["id"],
                    "name": exc["name"],
                    "type": e_type,
                    "value": e_val,
                    "nets": nets,
                }
            )
    return resolved


def build_candidate_snapshot(force_download: bool = False) -> dict:
    """Compile all enabled sources, apply exclusions across ALL sources (including RU), and generate BIRD routes."""
    t_start = time.time()
    server_asn = get_server_asn()
    now_str = datetime.datetime.now().strftime("%d.%m.%Y, %H:%M:%S")

    if force_download:
        update_cloudflare_ranges()

    conn = get_db()
    try:
        settings = get_settings(conn)
        sources_rows = [dict(r) for r in conn.execute("SELECT * FROM sources WHERE enabled = 1 ORDER BY id ASC").fetchall()]
        excl_rows = [dict(r) for r in conn.execute("SELECT * FROM exclusions WHERE enabled = 1 ORDER BY id ASC").fetchall()]
    finally:
        conn.close()

    min_len = max(1, min(32, int(settings.get("min_prefix_length", str(get_min_prefix_length())))))
    allow_broad = settings.get("allow_broad_routes", "0") == "1"
    resolvers = _get_configured_resolvers(settings)
    cache_ttl = int(settings.get("dns_cache_ttl_sec", "86400"))

    exclusion_rules = _resolve_exclusion_nets(excl_rows, resolvers)
    all_excl_nets = [n for rule in exclusion_rules for n in rule["nets"]]

    source_results = [
        _collect_single_source(src, force_download, min_len, allow_broad, resolvers, cache_ttl)
        for src in sources_rows
    ]

    raw_count = 0
    custom_count = 0
    pre_filter_count = 0
    post_filter_count = 0
    applied_exclusion_ids: set[int] = set()

    merged: dict[ipaddress.IPv4Network, dict] = {}
    provenance_sources: list[dict] = []

    for sr in source_results:
        is_ru = sr["type"] == "COUNTRY" and sr["value"].upper() == "RU"
        raw_nets: list[ipaddress.IPv4Network] = []
        for p in sr["prefixes"]:
            n = is_valid_ipv4_net(p, min_prefix_length=min_len, allow_broad=allow_broad)
            if n:
                raw_nets.append(n)

        raw_nets = list(ipaddress.collapse_addresses(raw_nets))
        if is_ru:
            raw_count += len(raw_nets)
        else:
            custom_count += len(raw_nets)
        pre_filter_count += len(raw_nets)

        for rule in exclusion_rules:
            if any(net.overlaps(en) for net in raw_nets for en in rule["nets"]):
                applied_exclusion_ids.add(int(rule["id"]))

        filtered_nets = subtract_networks(raw_nets, all_excl_nets)
        post_filter_count += len(filtered_nets)

        provenance_sources.append(
            {
                "id": sr["id"],
                "name": sr["name"],
                "type": sr["type"],
                "value": sr["value"],
                "community": sr["community"],
                "gateway": sr["gateway"],
                "status": sr["status"],
                "error": sr["error"],
                "raw_prefixes": [str(n) for n in raw_nets],
                "final_prefixes": [str(n) for n in filtered_nets],
            }
        )

        comm_tuple = _parse_community(sr["community"], server_asn)
        if is_ru:
            category = "RU Pool"
        elif sr["type"] == "DOMAIN":
            category = f"Domain ({sr['name']})"
        elif sr["type"] == "ASN":
            category = f"ASN ({sr['name']})"
        elif sr["type"] == "COUNTRY":
            category = f"{sr['value']} Pool"
        elif sr["type"] == "PREFIX":
            category = "Custom CIDR"
        elif sr["type"] == "EXTERNAL_URL":
            category = "URL List"
        elif sr["type"] == "GOOGLE":
            category = "Google (non-GCP)"
        else:
            category = f"Custom ({sr['type']})"

        for net in filtered_nets:
            entry = merged.get(net)
            comms = {(server_asn, 1000), comm_tuple}
            if is_ru:
                comms.add((server_asn, 900))
            if entry is None:
                merged[net] = {
                    "network": net,
                    "communities": comms,
                    "source_names": [sr["name"]],
                    "category": category,
                    "gateway": sr["gateway"],
                    "is_custom": 0 if is_ru else 1,
                }
            else:
                entry["communities"].update(comms)
                if sr["name"] not in entry["source_names"]:
                    entry["source_names"].append(sr["name"])
                if not is_ru:
                    entry["is_custom"] = 1
                    entry["gateway"] = sr["gateway"]
                    entry["category"] = category

    sorted_nets = sorted(merged.keys(), key=lambda n: (int(n.network_address), n.prefixlen))
    collapsed_duplicates = max(0, post_filter_count - len(sorted_nets))

    lines = ["# Generated by AutoBgpFeed v2"]
    entries: list[dict] = []
    for net in sorted_nets:
        meta = merged[net]
        comm_list = sorted(meta["communities"])
        comm_adds = " ".join(f"bgp_community.add(({a}, {t}));" for a, t in comm_list)
        lines.append(f"route {net} blackhole {{ {comm_adds} }};")
        comm_display = ", ".join(f"{a}:{t}" for a, t in comm_list if t != 1000) or f"{server_asn}:1000"
        entries.append(
            {
                "prefix": str(net),
                "addresses_count": net.num_addresses,
                "addresses_formatted": f"{net.num_addresses:,} IP",
                "category": meta["category"],
                "community": comm_display,
                "source_name": ", ".join(meta["source_names"]),
                "gateway": meta["gateway"],
                "is_custom": meta["is_custom"],
            }
        )

    routes_conf_text = "\n".join(lines) + "\n"
    routes_sha256 = hashlib.sha256(routes_conf_text.encode("utf-8")).hexdigest()
    t_elapsed = round(time.time() - t_start, 3)

    degraded_reasons = [f"{sr['name']}: {sr['error']}" for sr in source_results if sr["degraded"] or (sr["error"] and not sr["prefixes"])]
    is_degraded = any(sr["degraded"] for sr in source_results) or any(sr["error"] and not sr["prefixes"] for sr in source_results)

    return {
        "generated_at": now_str,
        "generated_at_unix": int(time.time()),
        "gen_duration": f"{t_elapsed}с",
        "gen_duration_sec": t_elapsed,
        "routes_conf_text": routes_conf_text,
        "routes_sha256": routes_sha256,
        "prefixes": [e["prefix"] for e in entries],
        "entries": entries,
        "source_results": source_results,
        "provenance_sources": provenance_sources,
        "exclusions": [
            {
                "id": r["id"],
                "name": r["name"],
                "type": r["type"],
                "value": r["value"],
                "prefixes": [str(n) for n in r["nets"]],
            }
            for r in exclusion_rules
        ],
        "degraded": is_degraded,
        "degraded_reasons": degraded_reasons,
        "stats": {
            "raw_count": raw_count,
            "custom_count": custom_count,
            "pre_filter_count": pre_filter_count,
            "post_filter_count": post_filter_count,
            "final_count": len(entries),
            "exclusions_applied": len(applied_exclusion_ids),
            "collapsed_duplicates": collapsed_duplicates,
        },
    }


def _persist_snapshot_to_db(snapshot: dict, now_str: str) -> None:
    conn = get_db()
    try:
        with conn:
            cur = conn.cursor()
            for sr in snapshot["source_results"]:
                cur.execute(
                    """
                    UPDATE sources
                    SET prefix_count = ?, last_update = ?, status = ?, error = ?, degraded = ?, cached_at = COALESCE(?, cached_at)
                    WHERE id = ?
                    """,
                    (
                        len(sr["prefixes"]),
                        sr["last_update"],
                        sr["status"],
                        sr["error"],
                        1 if sr["degraded"] else 0,
                        sr["cached_at"],
                        sr["id"],
                    ),
                )

            existing_dates = {r[0]: r[1] for r in cur.execute("SELECT prefix, date_added FROM routes_index").fetchall()}
            new_prefixes = {e["prefix"] for e in snapshot["entries"]}
            withdrawn = set(existing_dates.keys()) - new_prefixes
            if withdrawn:
                cur.executemany("DELETE FROM routes_index WHERE prefix = ?", [(p,) for p in withdrawn])

            rows_to_upsert = [
                (
                    e["prefix"],
                    e["addresses_count"],
                    e["addresses_formatted"],
                    e["category"],
                    e["community"],
                    e["source_name"],
                    existing_dates.get(e["prefix"], now_str),
                    e["gateway"],
                    e["is_custom"],
                )
                for e in snapshot["entries"]
            ]
            if rows_to_upsert:
                cur.executemany(
                    """
                    INSERT OR REPLACE INTO routes_index
                    (prefix, addresses_count, addresses_formatted, category, community, source_name, date_added, gateway, is_custom)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows_to_upsert,
                )

            st = snapshot["stats"]
            degraded_reason = "; ".join(snapshot["degraded_reasons"])
            cur.execute(
                """
                UPDATE stats SET
                    last_gen_time = ?,
                    gen_duration = ?,
                    raw_count = ?,
                    custom_count = ?,
                    pre_filter_count = ?,
                    post_filter_count = ?,
                    final_count = ?,
                    exclusions_applied = ?,
                    collapsed_duplicates = ?,
                    degraded = ?,
                    degraded_reason = ?,
                    routes_sha256 = ?,
                    last_apply_time = ?
                WHERE id = 1
                """,
                (
                    now_str,
                    snapshot["gen_duration"],
                    st["raw_count"],
                    st["custom_count"],
                    st["pre_filter_count"],
                    st["post_filter_count"],
                    st["final_count"],
                    st["exclusions_applied"],
                    st["collapsed_duplicates"],
                    1 if snapshot["degraded"] else 0,
                    degraded_reason,
                    snapshot["routes_sha256"],
                    now_str,
                ),
            )
    finally:
        conn.close()


def apply_snapshot(snapshot: dict, force_reload: bool = False) -> dict:
    """Atomically write BIRD routes.conf, reload BIRD, and rollback to last-good on failure."""
    gen_dir = get_generated_dir()
    data_dir = get_data_dir()
    routes_conf_path = os.path.join(gen_dir, "routes.conf")
    last_good_conf_path = os.path.join(data_dir, "last-good", "routes.last-good.conf")
    confirmed_path = os.path.join(data_dir, "confirmed_snapshot.json")

    confirmed = _read_json(confirmed_path)
    prev_sha = confirmed.get("routes_sha256") if confirmed else None
    current_disk_sha = None
    if os.path.exists(routes_conf_path):
        with open(routes_conf_path, "r", encoding="utf-8", errors="replace") as f:
            current_disk_sha = hashlib.sha256(f.read().encode("utf-8")).hexdigest()

    live_count = bird_route_count()
    expected_count = len(snapshot["prefixes"])

    # No-op short-circuit: eliminate pointless SQLite writes & BIRD reloads when routes are unchanged
    if (
        not force_reload
        and prev_sha == snapshot["routes_sha256"]
        and current_disk_sha == snapshot["routes_sha256"]
        and live_count == expected_count
        and not snapshot["degraded"]
    ):
        return {"changed": False, "final_count": expected_count, "degraded": False}

    if expected_count == 0 and prev_sha and os.path.exists(last_good_conf_path):
        # Refuse silently wiping all routes when active sources exist unless explicitly empty
        enabled_cnt = len(snapshot["source_results"])
        if enabled_cnt > 0:
            err_msg = "All enabled sources returned 0 prefixes; keeping last-good snapshot"
            conn = get_db()
            try:
                with conn:
                    conn.execute(
                        "UPDATE stats SET degraded = 1, degraded_reason = ? WHERE id = 1",
                        (err_msg,),
                    )
            finally:
                conn.close()
            log_msg(err_msg, "ERROR")
            return {"changed": False, "final_count": live_count, "degraded": True, "error": err_msg}

    prev_conf_bytes = None
    if os.path.exists(last_good_conf_path):
        with open(last_good_conf_path, "r", encoding="utf-8") as f:
            prev_conf_bytes = f.read()
    elif os.path.exists(routes_conf_path):
        with open(routes_conf_path, "r", encoding="utf-8") as f:
            prev_conf_bytes = f.read()

    try:
        _atomic_write_text(routes_conf_path, snapshot["routes_conf_text"])
        bird_configure()
    except Exception as exc:
        # Rollback BIRD routes.conf immediately
        if prev_conf_bytes is not None:
            try:
                _atomic_write_text(routes_conf_path, prev_conf_bytes)
                bird_configure()
            except Exception as rb_exc:
                log_msg(f"Критическая ошибка отката BIRD: {rb_exc}", "ERROR")
        conn = get_db()
        try:
            with conn:
                conn.execute(
                    "UPDATE stats SET degraded = 1, degraded_reason = ? WHERE id = 1",
                    (f"BIRD rejected routes ({exc}); rolled back to last-good",),
                )
        finally:
            conn.close()
        log_msg(f"BIRD отклонил конфигурацию, выполнен откат на last-good: {exc}", "ERROR")
        raise

    now_str = datetime.datetime.now().strftime("%d.%m.%Y, %H:%M:%S")
    _atomic_write_text(last_good_conf_path, snapshot["routes_conf_text"])
    confirmed_payload = {
        "applied_at": now_str,
        "applied_at_unix": int(time.time()),
        "routes_sha256": snapshot["routes_sha256"],
        "prefixes": snapshot["prefixes"],
        "provenance_sources": snapshot["provenance_sources"],
        "exclusions": snapshot["exclusions"],
        "stats": snapshot["stats"],
        "degraded": snapshot["degraded"],
        "degraded_reasons": snapshot["degraded_reasons"],
    }
    _atomic_write_json(confirmed_path, confirmed_payload)
    _persist_snapshot_to_db(snapshot, now_str)

    log_msg(
        f"BIRD 2 применён за {snapshot['gen_duration']}: {expected_count:,} маршрутов"
        + (" [DEGRADED: использован кеш]" if snapshot["degraded"] else ""),
        "WARN" if snapshot["degraded"] else "SUCCESS",
    )
    return {"changed": True, "final_count": expected_count, "degraded": snapshot["degraded"]}


def rebuild_all(force_download: bool = False, force_reload: bool = False) -> int:
    with _REBUILD_LOCK:
        snapshot = build_candidate_snapshot(force_download=force_download)
        res = apply_snapshot(snapshot, force_reload=force_reload)
        return int(res["final_count"])


def _config_fingerprint() -> str:
    conn = get_db()
    try:
        sources = [dict(r) for r in conn.execute("SELECT id, type, value, enabled, community, gateway, cdn_mode FROM sources ORDER BY id ASC").fetchall()]
        exclusions = [dict(r) for r in conn.execute("SELECT id, type, value, enabled FROM exclusions ORDER BY id ASC").fetchall()]
        settings = get_settings(conn)
    finally:
        conn.close()
    raw = json.dumps({"sources": sources, "exclusions": exclusions, "settings": settings}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _previews_dir() -> str:
    return os.path.join(get_data_dir(), "previews")


def create_preview() -> dict:
    """Build candidate snapshot without applying to BIRD and return diff preview."""
    with _REBUILD_LOCK:
        fp = _config_fingerprint()
        snapshot = build_candidate_snapshot(force_download=True)
        if fp != _config_fingerprint():
            raise RuntimeError("Конфигурация изменилась во время подготовки предпросмотра")

        confirmed = _read_json(os.path.join(get_data_dir(), "confirmed_snapshot.json"))
        old_prefixes = set(confirmed.get("prefixes", [])) if confirmed else set()
        new_prefixes = set(snapshot["prefixes"])

        added = sorted(new_prefixes - old_prefixes)
        removed = sorted(old_prefixes - new_prefixes)

        preview_id = uuid.uuid4().hex
        now_ts = int(time.time())
        record = {
            "id": preview_id,
            "created_at_unix": now_ts,
            "fingerprint": fp,
            "baseline_sha256": confirmed.get("routes_sha256") if confirmed else None,
            "added": added,
            "removed": removed,
            "snapshot": snapshot,
        }
        pdir = _previews_dir()
        os.makedirs(pdir, exist_ok=True)
        for fname in os.listdir(pdir):
            fpath = os.path.join(pdir, fname)
            try:
                if fname.endswith(".json") and os.path.getmtime(fpath) < now_ts - 86400:
                    os.unlink(fpath)
            except OSError:
                pass

        _atomic_write_json(os.path.join(pdir, f"{preview_id}.json"), record)
        return {
            "id": preview_id,
            "total": len(new_prefixes),
            "added_count": len(added),
            "removed_count": len(removed),
            "added": added[:200],
            "removed": removed[:200],
            "degraded": snapshot["degraded"],
            "warnings": snapshot["degraded_reasons"],
            "stats": snapshot["stats"],
        }


def apply_preview(preview_id: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", preview_id or ""):
        raise ValueError("Некорректный ID предпросмотра")
    path = os.path.join(_previews_dir(), f"{preview_id}.json")
    record = _read_json(path)
    if not record:
        raise ValueError("Предпросмотр не найден или удалён")
    if time.time() - int(record.get("created_at_unix", 0)) > 3600:
        raise ValueError("Срок действия предпросмотра истёк (> 1 часа), создайте новый")
    with _REBUILD_LOCK:
        if record.get("fingerprint") != _config_fingerprint():
            raise ValueError("Настройки изменились после создания предпросмотра")
        confirmed = _read_json(os.path.join(get_data_dir(), "confirmed_snapshot.json"))
        curr_base = confirmed.get("routes_sha256") if confirmed else None
        if record.get("baseline_sha256") != curr_base:
            raise ValueError("Активные маршруты изменились после создания предпросмотра")
        res = apply_snapshot(record["snapshot"], force_reload=True)
        try:
            os.unlink(path)
        except OSError:
            pass
        return res


def check_ip_in_feed(ip_str: str) -> dict:
    """Check an IPv4 address against ALL confirmed routes with full source/exclusion provenance."""
    try:
        target_ip = ipaddress.IPv4Address(ip_str.strip())
    except Exception:
        return {"error": "Некорректный IPv4-адрес"}

    confirmed = _read_json(os.path.join(get_data_dir(), "confirmed_snapshot.json"))
    matching_prefixes: list[str] = []
    matching_sources: list[dict] = []
    matching_exclusions: list[dict] = []

    if confirmed:
        for p in confirmed.get("prefixes", []):
            try:
                if target_ip in ipaddress.IPv4Network(p):
                    matching_prefixes.append(p)
            except ValueError:
                continue

        for src in confirmed.get("provenance_sources", []):
            hits = []
            for p in src.get("raw_prefixes", []):
                try:
                    if target_ip in ipaddress.IPv4Network(p):
                        hits.append(p)
                except ValueError:
                    continue
            if hits:
                matching_sources.append(
                    {
                        "name": src["name"],
                        "type": src["type"],
                        "community": src["community"],
                        "gateway": src["gateway"],
                        "matches": hits[:10],
                    }
                )

        for exc in confirmed.get("exclusions", []):
            hits = []
            for p in exc.get("prefixes", []):
                try:
                    if target_ip in ipaddress.IPv4Network(p):
                        hits.append(p)
                except ValueError:
                    continue
            if hits:
                matching_exclusions.append(
                    {
                        "name": exc["name"],
                        "type": exc["type"],
                        "value": exc["value"],
                        "matches": hits,
                    }
                )
    else:
        conn = get_db()
        try:
            rows = conn.execute("SELECT prefix, source_name, community, gateway FROM routes_index").fetchall()
            for r in rows:
                try:
                    if target_ip in ipaddress.IPv4Network(r["prefix"]):
                        matching_prefixes.append(r["prefix"])
                        matching_sources.append(
                            {
                                "name": r["source_name"],
                                "type": "INDEX",
                                "community": r["community"],
                                "gateway": r["gateway"],
                                "matches": [r["prefix"]],
                            }
                        )
                except ValueError:
                    continue
        finally:
            conn.close()

    found = len(matching_prefixes) > 0
    if found:
        decision = "included"
    elif matching_exclusions and matching_sources:
        decision = "excluded"
    else:
        decision = "absent"

    return {
        "ip": str(target_ip),
        "found": found,
        "decision": decision,
        "matching_prefix": matching_prefixes[0] if matching_prefixes else None,
        "matching_prefixes": matching_prefixes,
        "sources": matching_sources,
        "exclusions": matching_exclusions,
        "confirmed": bool(confirmed),
        "feed": "Включён в активные BGP-маршруты" if found else ("Исключён правилом (Exclusion)" if decision == "excluded" else "Вне маршрутов VPN-фида"),
    }


def get_mask_distribution() -> dict[str, int]:
    """Compute CIDR prefix-length distribution across ALL active confirmed routes."""
    dist = {"/8 - /16 (Крупные)": 0, "/17 - /20 (Средние)": 0, "/21 - /24 (Локальные)": 0, "/32 (Хосты/DNS)": 0}
    confirmed = _read_json(os.path.join(get_data_dir(), "confirmed_snapshot.json"))
    prefixes = confirmed.get("prefixes", []) if confirmed else None
    if prefixes is None:
        conn = get_db()
        try:
            prefixes = [r[0] for r in conn.execute("SELECT prefix FROM routes_index").fetchall()]
        finally:
            conn.close()

    for p in prefixes:
        if "/" not in p:
            continue
        try:
            plen = int(p.split("/")[1])
            if plen <= 16:
                dist["/8 - /16 (Крупные)"] += 1
            elif plen <= 20:
                dist["/17 - /20 (Средние)"] += 1
            elif plen <= 24:
                dist["/21 - /24 (Локальные)"] += 1
            else:
                dist["/32 (Хосты/DNS)"] += 1
        except ValueError:
            continue
    return dist


def get_source_prefixes(source_id: int) -> dict:
    conn = get_db()
    try:
        source = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        if not source:
            return {"error": "Источник не найден", "prefixes": []}
        src = dict(source)
    finally:
        conn.close()

    confirmed = _read_json(os.path.join(get_data_dir(), "confirmed_snapshot.json"))
    if confirmed:
        for ps in confirmed.get("provenance_sources", []):
            if int(ps["id"]) == int(source_id):
                return {
                    "source_id": source_id,
                    "name": src["name"],
                    "type": src["type"],
                    "value": src["value"],
                    "count": len(ps["final_prefixes"]),
                    "prefixes": sorted(ps["final_prefixes"]),
                }

    cached, _ = load_source_cache(source_id)
    return {
        "source_id": source_id,
        "name": src["name"],
        "type": src["type"],
        "value": src["value"],
        "count": len(cached),
        "prefixes": sorted(cached),
    }


def search_routes_in_cache(
    query: str = "",
    page: int = 1,
    limit: int = 50,
    sort_by: str = "default",
    sort_order: str = "asc",
) -> dict:
    page = max(1, int(page))
    limit = max(1, min(200, int(limit)))
    conn = get_db()
    try:
        base_where = ""
        params: list = []
        if query:
            q_clean = query.strip()
            base_where = "WHERE (prefix LIKE ? OR category LIKE ? OR source_name LIKE ? OR community LIKE ? OR gateway LIKE ?)"
            q_like = f"%{q_clean}%"
            params = [q_like, q_like, q_like, q_like, q_like]

        total = conn.execute(f"SELECT COUNT(*) FROM routes_index {base_where}", params).fetchone()[0]
        order = "ASC" if sort_order.lower() == "asc" else "DESC"

        if sort_by == "date":
            date_expr = "(SUBSTR(date_added, 7, 4) || '-' || SUBSTR(date_added, 4, 2) || '-' || SUBSTR(date_added, 1, 2) || ' ' || SUBSTR(date_added, 13))"
            order_clause = f"ORDER BY is_custom DESC, {date_expr} {order}, prefix ASC"
        elif sort_by == "prefix":
            order_clause = f"ORDER BY prefix {order}"
        elif sort_by == "addresses":
            order_clause = f"ORDER BY addresses_count {order}, prefix ASC"
        elif sort_by == "category":
            order_clause = f"ORDER BY category {order}, prefix ASC"
        elif sort_by == "community":
            order_clause = f"ORDER BY community {order}, prefix ASC"
        else:
            order_clause = "ORDER BY is_custom DESC, prefix ASC"

        offset = (page - 1) * limit
        rows = conn.execute(
            f"""
            SELECT prefix, addresses_count, addresses_formatted, category, community, source_name, date_added, gateway, is_custom
            FROM routes_index {base_where} {order_clause} LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
    finally:
        conn.close()

    items = [
        {
            "prefix": r["prefix"],
            "addresses": r["addresses_formatted"] or f"{r['addresses_count']:,} IP",
            "type": r["category"],
            "community": r["community"],
            "gateway": r["gateway"] or "wireguard1",
            "date_added": r["date_added"] or "—",
            "source_name": r["source_name"] or "",
            "is_custom": bool(r["is_custom"]),
        }
        for r in rows
    ]
    return {"total": total, "page": page, "limit": limit, "items": items, "sort_by": sort_by, "sort_order": sort_order}


def export_mikrotik_rsc(list_name: str = "autobgpfeed") -> str:
    """Export confirmed active prefixes as an idempotent RouterOS Address List .rsc script."""
    clean_name = (list_name or "").strip()
    if not LIST_NAME_RE.fullmatch(clean_name):
        raise ValueError("Имя списка должно содержать 1–64 символа: латиница, цифры, _ . -")

    confirmed = _read_json(os.path.join(get_data_dir(), "confirmed_snapshot.json"))
    prefixes = confirmed.get("prefixes", []) if confirmed else []
    if not prefixes:
        conn = get_db()
        try:
            prefixes = [r[0] for r in conn.execute("SELECT prefix FROM routes_index ORDER BY prefix ASC").fetchall()]
        finally:
            conn.close()

    if not prefixes:
        raise RuntimeError("Нет подтверждённых маршрутов для экспорта")

    lines = [
        "# AutoBgpFeed v2 MikroTik Address List Export",
        f"# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total: {len(prefixes)}",
        f'/ip firewall address-list remove [find list="{clean_name}" comment~"^autobgpfeed:managed:"]',
        "/ip firewall address-list",
    ]
    for p in prefixes:
        lines.append(f'add list="{clean_name}" address={p} comment="autobgpfeed:managed:{p}"')
    return "\n".join(lines) + "\n"


def export_config_backup() -> dict:
    """Export sources, exclusions, and settings as portable JSON (excludes user password hashes)."""
    conn = get_db()
    try:
        sources = [
            {
                "name": r["name"],
                "type": r["type"],
                "value": r["value"],
                "mode": r["mode"],
                "enabled": int(r["enabled"]),
                "auto_update": int(r["auto_update"]),
                "community": r["community"],
                "gateway": r["gateway"],
                "cdn_mode": r["cdn_mode"],
            }
            for r in conn.execute("SELECT * FROM sources ORDER BY id ASC").fetchall()
        ]
        exclusions = [
            {
                "name": r["name"],
                "type": r["type"],
                "value": r["value"],
                "enabled": int(r["enabled"]),
            }
            for r in conn.execute("SELECT * FROM exclusions ORDER BY id ASC").fetchall()
        ]
        settings = get_settings(conn)
    finally:
        conn.close()

    return {
        "version": 2,
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sources": sources,
        "exclusions": exclusions,
        "settings": settings,
    }


def save_revision(action: str, details: str = "", conn=None) -> int:
    own = conn is None
    if own:
        conn = get_db()
    try:
        backup = export_config_backup() if own else None
        if backup is None:
            sources = [
                {
                    "name": r["name"],
                    "type": r["type"],
                    "value": r["value"],
                    "mode": r["mode"],
                    "enabled": int(r["enabled"]),
                    "auto_update": int(r["auto_update"]),
                    "community": r["community"],
                    "gateway": r["gateway"],
                    "cdn_mode": r["cdn_mode"],
                }
                for r in conn.execute("SELECT * FROM sources ORDER BY id ASC").fetchall()
            ]
            exclusions = [
                {"name": r["name"], "type": r["type"], "value": r["value"], "enabled": int(r["enabled"])}
                for r in conn.execute("SELECT * FROM exclusions ORDER BY id ASC").fetchall()
            ]
            settings = get_settings(conn)
            backup = {"version": 2, "sources": sources, "exclusions": exclusions, "settings": settings}

        routes_cnt = conn.execute("SELECT final_count FROM stats WHERE id = 1").fetchone()
        cnt_val = int(routes_cnt[0]) if routes_cnt and routes_cnt[0] is not None else 0
        cur = conn.execute(
            "INSERT INTO revisions (action, details, routes_count, config_json) VALUES (?, ?, ?, ?)",
            (action, details, cnt_val, json.dumps(backup, ensure_ascii=False)),
        )
        conn.execute("DELETE FROM revisions WHERE id NOT IN (SELECT id FROM revisions ORDER BY id DESC LIMIT 30)")
        if own:
            conn.commit()
        return int(cur.lastrowid)
    finally:
        if own:
            conn.close()


def _apply_config_payload(data: dict, action_label: str) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list) or not isinstance(data.get("exclusions"), list):
        raise ValueError("Некорректный формат конфигурации (ожидаются sources и exclusions)")

    allowed_types = {"COUNTRY", "DOMAIN", "ASN", "PREFIX", "EXTERNAL_URL", "GOOGLE"}
    for s in data["sources"]:
        if not isinstance(s, dict) or not s.get("name") or str(s.get("type", "")).upper() not in allowed_types or not s.get("value"):
            raise ValueError(f"Некорректный источник в бэкапе: {s}")
    for ex in data["exclusions"]:
        if not isinstance(ex, dict) or not ex.get("name") or not ex.get("value"):
            raise ValueError(f"Некорректное исключение в бэкапе: {ex}")

    conn = get_db()
    try:
        with conn:
            save_revision("pre-import", f"Перед операцией: {action_label}", conn=conn)
            conn.execute("DELETE FROM sources")
            for s in data["sources"]:
                conn.execute(
                    """
                    INSERT INTO sources (name, type, value, mode, enabled, auto_update, community, status, gateway, cdn_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        str(s["name"]).strip(),
                        str(s["type"]).upper(),
                        str(s["value"]).strip(),
                        str(s.get("mode") or "default"),
                        1 if s.get("enabled", 1) else 0,
                        1 if s.get("auto_update", 1) else 0,
                        str(s.get("community") or f"{get_server_asn()}:1000"),
                        str(s.get("gateway") or "wireguard1"),
                        str(s.get("cdn_mode") or "auto"),
                    ),
                )
            conn.execute("DELETE FROM exclusions")
            for ex in data["exclusions"]:
                conn.execute(
                    "INSERT INTO exclusions (name, type, value, enabled) VALUES (?, ?, ?, ?)",
                    (
                        str(ex["name"]).strip(),
                        str(ex.get("type") or "PREFIX").upper(),
                        str(ex["value"]).strip(),
                        1 if ex.get("enabled", 1) else 0,
                    ),
                )
            if isinstance(data.get("settings"), dict):
                for k, v in data["settings"].items():
                    if k in DEFAULT_SETTINGS:
                        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
    finally:
        conn.close()


def import_config_backup(data: dict) -> None:
    _apply_config_payload(data, "import_backup")
    log_msg("Конфигурация импортирована из JSON-бэкапа", "SUCCESS")


def list_revisions() -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, action, details, routes_count FROM revisions WHERE config_json IS NOT NULL ORDER BY id DESC LIMIT 30"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def restore_revision(rev_id: int) -> None:
    conn = get_db()
    try:
        row = conn.execute("SELECT action, config_json FROM revisions WHERE id = ?", (rev_id,)).fetchone()
    finally:
        conn.close()
    if not row or not row["config_json"]:
        raise ValueError("Ревизия не найдена")
    data = json.loads(row["config_json"])
    _apply_config_payload(data, f"restore_revision#{rev_id}")
    log_msg(f"Восстановлена ревизия #{rev_id} ({row['action']})", "SUCCESS")


def universal_inspect(query: str) -> dict:
    query = query.strip()
    if query.startswith("http://") or query.startswith("https://"):
        query = urllib.parse.urlparse(query).hostname or query

    q_low = query.lower()
    if q_low in COUNTRY_MAP or (len(q_low) == 2 and q_low.isalpha()):
        iso_code, nice_name, iso_num = resolve_country_input(query)
        prefixes = fetch_country_prefixes(iso_code, force_download=False)
        prefix_details = []
        full_total = 0
        for idx, p in enumerate(prefixes):
            try:
                net = ipaddress.IPv4Network(p)
                full_total += net.num_addresses
                if idx < 100:
                    prefix_details.append({"prefix": p, "addresses": f"{net.num_addresses:,} IP", "mask": f"/{net.prefixlen}"})
            except Exception:
                continue

        return {
            "target": f"Страна: {nice_name}",
            "is_ip": False,
            "is_asn": False,
            "is_country": True,
            "country_code": iso_code,
            "resolved_ips": prefixes[:100],
            "prefix_details": prefix_details,
            "total_ips": full_total,
            "total_ips_formatted": f"{full_total:,}",
            "total_ips_human": format_ip_human(full_total),
            "total_subnets_count": len(prefixes),
            "country": nice_name,
            "provider": f"Национальный пул IP ({iso_code})",
            "asn": f"ISO {iso_num}",
            "asn_digits": str(iso_num),
            "asn_full": f"BGP Community {get_server_asn()}:{iso_num}",
            "asn_prefix_count": len(prefixes),
            "is_cdn": False,
            "is_cloudflare": False,
            "in_ru_feed": iso_code == "RU",
            "external_links": {
                "ripe": f"https://stat.ripe.net/country/{iso_code}",
                "ipinfo": f"https://ipinfo.io/countries/{iso_code.lower()}",
            },
        }

    is_asn = bool(re.match(r"^(?:AS|as)?\d+$", query, re.IGNORECASE))
    if is_asn and "." not in query:
        asn_num = re.sub(r"[^0-9]", "", query)
        try:
            prefixes = fetch_asn(asn_num)
        except Exception:
            prefixes = []
        if not prefixes:
            return {"error": f"Автономная система AS{asn_num} не найдена в реестре RIPEstat или не анонсирует IPv4-префиксы."}

        primary_ip = prefixes[0].split("/")[0]
        geo_data = {}
        try:
            geo_data = json.loads(_safe_http_get_text(f"http://ip-api.com/json/{primary_ip}?fields=status,message,country,countryCode,as,org,isp,query", timeout=3.0, validate_ssrf=False))
        except Exception as e:
            geo_data = {"status": "fail", "message": str(e)}

        asn_raw = geo_data.get("as", f"AS{asn_num}")
        is_cf = asn_num == "13335" or "cloudflare" in geo_data.get("isp", "").lower()

        total_ips = 0
        prefix_details = []
        for p in prefixes:
            try:
                net = ipaddress.IPv4Network(p)
                total_ips += net.num_addresses
                prefix_details.append({"prefix": p, "addresses": f"{net.num_addresses:,} IP", "mask": f"/{net.prefixlen}"})
            except Exception:
                continue

        return {
            "target": f"AS{asn_num}",
            "is_ip": False,
            "is_asn": True,
            "is_country": False,
            "resolved_ips": prefixes,
            "prefix_details": prefix_details,
            "total_ips": total_ips,
            "total_ips_formatted": f"{total_ips:,}",
            "total_ips_human": format_ip_human(total_ips),
            "total_subnets_count": len(prefixes),
            "primary_ip": primary_ip,
            "country": geo_data.get("country", "Международная сеть"),
            "country_code": geo_data.get("countryCode", "GL"),
            "provider": geo_data.get("isp", geo_data.get("org", f"AS{asn_num} Network")),
            "asn": f"AS{asn_num}",
            "asn_digits": asn_num,
            "asn_full": asn_raw,
            "asn_prefix_count": len(prefixes),
            "is_cdn": is_cf,
            "is_cloudflare": is_cf,
            "in_ru_feed": check_ip_in_feed(primary_ip).get("found", False),
            "external_links": {
                "he": f"https://bgp.he.net/AS{asn_num}",
                "ripe": f"https://stat.ripe.net/AS{asn_num}",
                "ipinfo": f"https://ipinfo.io/AS{asn_num}",
                "qrator": f"https://radar.qrator.net/as{asn_num}",
                "peeringdb": f"https://www.peeringdb.com/asn/{asn_num}",
            },
        }

    is_ip = False
    try:
        ipaddress.IPv4Address(query)
        is_ip = True
    except ValueError:
        pass

    resolved_ips = [query] if is_ip else sorted(resolve_domain_ips(query))
    if not resolved_ips:
        return {"error": f"Не удалось отрезолвить адрес или домен «{query}»"}

    primary_ip = resolved_ips[0]
    geo_data = {}
    try:
        geo_data = json.loads(_safe_http_get_text(f"http://ip-api.com/json/{primary_ip}?fields=status,message,country,countryCode,as,org,isp,query", timeout=3.0, validate_ssrf=False))
    except Exception as e:
        geo_data = {"status": "fail", "message": str(e)}

    asn_raw = geo_data.get("as", "")
    asn_num_match = re.search(r"AS(\d+)", asn_raw)
    asn_str = f"AS{asn_num_match.group(1)}" if asn_num_match else ""
    asn_digits = asn_num_match.group(1) if asn_num_match else ""

    isp_l = geo_data.get("isp", "").lower()
    org_l = geo_data.get("org", "").lower()
    is_cf = "cloudflare" in isp_l or "cloudflare" in asn_raw.lower() or "13335" in asn_raw
    is_fastly = "fastly" in isp_l or "54113" in asn_raw
    is_akamai = "akamai" in isp_l or "20940" in asn_raw
    is_cloudfront = "amazon" in isp_l or "cloudfront" in org_l
    is_cdn = is_cf or is_fastly or is_akamai or is_cloudfront

    ip_check = check_ip_in_feed(primary_ip)
    asn_prefix_count = 0
    if asn_digits and not is_cf:
        try:
            asn_prefix_count = len(fetch_asn(asn_digits))
        except Exception:
            pass

    external_links = {}
    if asn_digits:
        external_links = {
            "he": f"https://bgp.he.net/AS{asn_digits}",
            "ripe": f"https://stat.ripe.net/AS{asn_digits}",
            "ipinfo": f"https://ipinfo.io/AS{asn_digits}",
            "qrator": f"https://radar.qrator.net/as{asn_digits}",
            "peeringdb": f"https://www.peeringdb.com/asn/{asn_digits}",
        }

    return {
        "target": query,
        "is_ip": is_ip,
        "is_asn": False,
        "is_country": False,
        "resolved_ips": resolved_ips,
        "primary_ip": primary_ip,
        "country": geo_data.get("country", "Неизвестно"),
        "country_code": geo_data.get("countryCode", "UN"),
        "provider": geo_data.get("isp", geo_data.get("org", "—")),
        "asn": asn_str,
        "asn_digits": asn_digits,
        "asn_full": asn_raw,
        "asn_prefix_count": asn_prefix_count,
        "is_cdn": is_cdn,
        "is_cloudflare": is_cf,
        "in_ru_feed": ip_check.get("found", False),
        "feed_decision": ip_check.get("decision", "absent"),
        "external_links": external_links,
    }
