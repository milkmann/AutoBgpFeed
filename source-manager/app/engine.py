import os
import re
import math
import time
import ipaddress
import urllib.request
import json
import sqlite3
import datetime
import httpx
import dns.resolver
from .db import get_db, DB_PATH

DATA_DIR = os.environ.get("DATA_DIR", "/data")
GENERATED_DIR = os.environ.get("GENERATED_DIR", "/generated")
BGP_CORE_CONTAINER = os.environ.get("BGP_CORE_CONTAINER", "bgp-core")

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

def resolve_country_input(q):
    if not q:
        return ("UN", "Unknown Country", 1000)
    q_clean = q.strip().lower()
    if q_clean in COUNTRY_MAP:
        return COUNTRY_MAP[q_clean]
    if len(q_clean) == 2 and q_clean.isalpha():
        cc = q_clean.upper()
        return (cc, f"Country {cc}", 1000)
    return (q[:2].upper(), q, 1000)

def update_cloudflare_ranges():
    global CLOUDFLARE_NETWORKS
    try:
        url = "https://www.cloudflare.com/ips-v4"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            lines = resp.read().decode().splitlines()
        fetched = []
        for l in lines:
            l = l.strip()
            if l:
                net = is_valid_ipv4_net(l)
                if net:
                    fetched.append(net)
        if fetched:
            CLOUDFLARE_NETWORKS = fetched
            log_msg(f"Обновлены официальные диапазоны Cloudflare: {len(fetched)} блоков", "INFO")
    except Exception as e:
        log_msg(f"Используются базовые диапазоны Cloudflare: {e}", "INFO")

def format_ip_human(num):
    if not num:
        return "0 IP"
    if num >= 1_000_000:
        val = round(num / 1_000_000, 1)
        return f"~{val:g} млн IP"
    elif num >= 1_000:
        val = round(num / 1_000, 1)
        return f"{val:g} тыс. IP"
    return f"{num} IP"

def is_cdn_anycast(ip_obj):
    for net in CLOUDFLARE_NETWORKS:
        if ip_obj in net:
            return True
    return False

def log_msg(message, level="INFO"):
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (level, message) VALUES (?, ?)", (level, message))
        cursor.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 200)")
    except Exception:
        pass
    finally:
        if conn:
            conn.close()
    print(f"[{level}] {message}")

def is_valid_ipv4_net(cidr_str):
    try:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
        if net.is_private or net.is_loopback or net.is_multicast or net.is_reserved or net.prefixlen == 0:
            return None
        return net
    except Exception:
        return None

def fetch_country_prefixes(country_code, force_download=False):
    cc = country_code.strip().upper()
    cache_file = os.path.join(DATA_DIR, "last-good", f"{cc.lower()}_prefixes.txt")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    
    if not force_download and os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            cached = [l.strip() for l in f if l.strip()]
            if cached:
                return cached

    log_msg(f"Загрузка актуального реестра подсетей страны {cc} (IPverse)...", "INFO")
    nets = []
    try:
        url = f"https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{cc.lower()}/ipv4-aggregated.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = resp.read().decode().splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                net = is_valid_ipv4_net(line)
                if net:
                    nets.append(net)
        log_msg(f"Получено {len(nets):,} сетей для {cc} из IPverse", "INFO")
    except Exception as e:
        log_msg(f"Ошибка загрузки IPverse для {cc}: {e}", "WARN")

    if not nets:
        try:
            url = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                lines = resp.read().decode().splitlines()
            for l in lines:
                parts = l.strip().split("|")
                if len(parts) >= 7 and parts[1] == cc and parts[2] == "ipv4" and parts[6] in ("allocated", "assigned"):
                    ip_start = parts[3]
                    count = int(parts[4])
                    if count > 0:
                        prefix_len = 32 - int(math.log2(count))
                        net = is_valid_ipv4_net(f"{ip_start}/{prefix_len}")
                        if net:
                            nets.append(net)
            log_msg(f"Получено {len(nets):,} сетей для {cc} из RIPE NCC", "INFO")
        except Exception as e:
            log_msg(f"Ошибка загрузки RIPE NCC для {cc}: {e}", "ERROR")

    if nets:
        collapsed = list(ipaddress.collapse_addresses(nets))
        with open(cache_file, "w") as f:
            for n in collapsed:
                f.write(f"{n}\n")
        log_msg(f"Успешно сохранено {len(collapsed):,} префиксов для страны {cc}", "SUCCESS")
        return [str(n) for n in collapsed]
    
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            return [l.strip() for l in f if l.strip()]
            
    return []

def fetch_ru_prefixes(force_download=False):
    return fetch_country_prefixes("RU", force_download=force_download)

def resolve_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("/")[2].split(":")[0]
    
    servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "77.88.8.8", "208.67.222.222"]
    subdomains = [domain]
    if not domain.startswith("www."):
        subdomains.append(f"www.{domain}")
        
    resolved_ips = set()
    for s in servers:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [s]
        res.timeout = 0.8
        res.lifetime = 1.2
        for d in subdomains:
            try:
                ans = res.resolve(d, "A")
                for rdata in ans:
                    resolved_ips.add(rdata.to_text())
            except Exception:
                pass
                
    if not resolved_ips:
        return []
        
    final_nets = []
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            if is_cdn_anycast(ip_obj):
                net_24 = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                final_nets.append(net_24)
            else:
                net_32 = ipaddress.IPv4Network(f"{ip_str}/32", strict=False)
                final_nets.append(net_32)
        except Exception:
            pass
            
    collapsed = list(ipaddress.collapse_addresses(final_nets))
    res_list = [str(n) for n in collapsed]
    log_msg(f"Smart-DNS анализ для {domain}: сгенерировано {len(res_list)} сетей: {res_list}", "INFO")
    return res_list

def fetch_asn(asn_str):
    asn_num = re.sub(r"[^0-9]", "", str(asn_str))
    if not asn_num:
        return []
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    prefixes = []
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        for item in data.get("data", {}).get("prefixes", []):
            p = item.get("prefix")
            if p and ":" not in p:
                net = is_valid_ipv4_net(p)
                if net:
                    prefixes.append(net)
        collapsed = list(ipaddress.collapse_addresses(prefixes))
        res_list = [str(n) for n in collapsed]
        log_msg(f"RIPEstat AS{asn_num}: получено {len(res_list)} агрегированных префиксов", "INFO")
        return res_list
    except Exception as e:
        log_msg(f"Ошибка получения ASN {asn_num}: {e}", "WARN")
    return []

def universal_inspect(query):
    query = query.strip()
    if query.startswith("http://") or query.startswith("https://"):
        query = query.split("/")[2].split(":")[0]
        
    # Check if query is a Country input (e.g. Украина, UA, Poland, PL)
    q_low = query.lower()
    if q_low in COUNTRY_MAP or (len(q_low) == 2 and q_low.isalpha()):
        iso_code, nice_name, iso_num = resolve_country_input(query)
        prefixes = fetch_country_prefixes(iso_code, force_download=False)
        total_ips = 0
        prefix_details = []
        for p in prefixes[:100]:
            try:
                net = ipaddress.IPv4Network(p)
                total_ips += net.num_addresses
                prefix_details.append({
                    "prefix": p,
                    "addresses": f"{net.num_addresses:,} IP",
                    "mask": f"/{net.prefixlen}"
                })
            except Exception:
                pass
                
        # Total sum over all prefixes
        full_total = sum(ipaddress.IPv4Network(p).num_addresses for p in prefixes if is_valid_ipv4_net(p))

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
            "asn_full": f"BGP Community 65000:{iso_num}",
            "asn_prefix_count": len(prefixes),
            "is_cdn": False,
            "is_cloudflare": False,
            "in_ru_feed": iso_code == "RU",
            "external_links": {
                "ripe": f"https://stat.ripe.net/country/{iso_code}",
                "ipinfo": f"https://ipinfo.io/countries/{iso_code.lower()}"
            }
        }

    # Check if query is ASN (e.g. AS62041, as15169, 62041)
    is_asn = bool(re.match(r"^(?:AS|as)?\d+$", query, re.IGNORECASE))
    if is_asn and "." not in query:
        asn_num = re.sub(r"[^0-9]", "", query)
        prefixes = fetch_asn(asn_num)
        if not prefixes:
            return {"error": f"Автономная система AS{asn_num} не найдена в реестре RIPEstat или не анонсирует IPv4-префиксы."}
            
        primary_ip = prefixes[0].split("/")[0]
        geo_data = {}
        try:
            url = f"http://ip-api.com/json/{primary_ip}?fields=status,message,country,countryCode,as,org,isp,query"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                geo_data = json.loads(resp.read().decode())
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
                prefix_details.append({
                    "prefix": p,
                    "addresses": f"{net.num_addresses:,} IP",
                    "mask": f"/{net.prefixlen}"
                })
            except Exception:
                pass

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
                "peeringdb": f"https://www.peeringdb.com/asn/{asn_num}"
            }
        }

    # Check if query is IPv4
    is_ip = False
    try:
        ipaddress.IPv4Address(query)
        is_ip = True
    except Exception:
        pass
        
    resolved_ips = [query] if is_ip else []
    if not is_ip:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = ["1.1.1.1", "8.8.8.8"]
        res.timeout = 1.0
        for d in [query, f"www.{query}"]:
            try:
                ans = res.resolve(d, "A")
                for r in ans:
                    resolved_ips.append(r.to_text())
            except Exception:
                pass
        resolved_ips = list(set(resolved_ips))
        
    if not resolved_ips:
        return {"error": f"Не удалось отрезолвить адрес или домен «{query}»"}
        
    primary_ip = resolved_ips[0]
    geo_data = {}
    try:
        url = f"http://ip-api.com/json/{primary_ip}?fields=status,message,country,countryCode,as,org,isp,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            geo_data = json.loads(resp.read().decode())
    except Exception as e:
        geo_data = {"status": "fail", "message": str(e)}
        
    asn_raw = geo_data.get("as", "")
    asn_num_match = re.search(r"AS(\d+)", asn_raw)
    asn_str = f"AS{asn_num_match.group(1)}" if asn_num_match else ""
    asn_digits = asn_num_match.group(1) if asn_num_match else ""
    
    is_cf = "cloudflare" in geo_data.get("isp", "").lower() or "cloudflare" in geo_data.get("as", "").lower() or "13335" in asn_raw
    is_fastly = "fastly" in geo_data.get("isp", "").lower() or "54113" in asn_raw
    is_akamai = "akamai" in geo_data.get("isp", "").lower() or "20940" in asn_raw
    is_cloudfront = "amazon" in geo_data.get("isp", "").lower() or "cloudfront" in geo_data.get("org", "").lower()
    is_cdn = is_cf or is_fastly or is_akamai or is_cloudfront
    
    in_ru_feed = check_ip_in_feed(primary_ip).get("found", False)
    
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
            "peeringdb": f"https://www.peeringdb.com/asn/{asn_digits}"
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
        "in_ru_feed": in_ru_feed,
        "external_links": external_links
    }

def fetch_external_url(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    prefixes = []
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read().decode(errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith(";"):
                if "/" not in line:
                    line = f"{line}/32"
                net = is_valid_ipv4_net(line)
                if net:
                    prefixes.append(net)
        collapsed = list(ipaddress.collapse_addresses(prefixes))
        res_list = [str(n) for n in collapsed]
        log_msg(f"Загрузка списка {url}: получено {len(res_list)} агрегированных префиксов", "INFO")
        return res_list
    except Exception as e:
        log_msg(f"Ошибка загрузки URL {url}: {e}", "WARN")
    return []

def get_mask_distribution():
    cache_file = os.path.join(DATA_DIR, "last-good", "ru_prefixes.txt")
    dist = {"/8 - /16 (Крупные)": 0, "/17 - /20 (Средние)": 0, "/21 - /24 (Локальные)": 0, "/32 (Хосты/DNS)": 0}
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            for l in f:
                l = l.strip()
                if "/" in l:
                    try:
                        plen = int(l.split("/")[1])
                        if plen <= 16:
                            dist["/8 - /16 (Крупные)"] += 1
                        elif plen <= 20:
                            dist["/17 - /20 (Средние)"] += 1
                        elif plen <= 24:
                            dist["/21 - /24 (Локальные)"] += 1
                        else:
                            dist["/32 (Хосты/DNS)"] += 1
                    except Exception:
                        pass
    return dist

def get_source_prefixes(source_id):
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
        source = cursor.fetchone()
        if not source:
            return {"error": "Источник не найден", "prefixes": []}
            
        s_type = source["type"]
        s_val = source["value"]
        
        if s_type == "COUNTRY":
            prefixes = fetch_country_prefixes(s_val, force_download=False)
        elif s_type == "DOMAIN":
            prefixes = resolve_domain(s_val)
        elif s_type == "ASN":
            prefixes = fetch_asn(s_val)
        elif s_type == "PREFIX":
            net = is_valid_ipv4_net(s_val)
            prefixes = [str(net)] if net else []
        elif s_type == "EXTERNAL_URL":
            prefixes = fetch_external_url(s_val)
        else:
            prefixes = []
            
        return {
            "source_id": source_id,
            "name": source["name"],
            "type": s_type,
            "value": s_val,
            "count": len(prefixes),
            "prefixes": sorted(prefixes)
        }
    finally:
        if conn:
            conn.close()

def search_routes_in_cache(query="", page=1, limit=50):
    custom_results = []
    custom_conf = os.path.join(GENERATED_DIR, "custom_routes.conf")
    if os.path.exists(custom_conf):
        with open(custom_conf, "r") as f:
            for line in f:
                m = re.match(r"route\s+([0-9\.\/]+)\s+blackhole.*?bgp_community\.add\(\(65000,\s*(\d+)\)\)", line)
                if m:
                    p = m.group(1)
                    tag = m.group(2)
                    if not query or query.lower() in p.lower() or "custom" in query.lower() or tag in query:
                        net = is_valid_ipv4_net(p)
                        if tag == "200":
                            tname = "Custom Domain"
                        elif tag == "300":
                            tname = "Custom ASN"
                        elif tag == "600":
                            tname = "Custom CIDR"
                        elif tag == "804":
                            tname = "UA Pool (Украина)"
                        elif tag == "616":
                            tname = "PL Pool (Польша)"
                        elif tag == "398":
                            tname = "KZ Pool (Казахстан)"
                        elif tag == "276":
                            tname = "DE Pool (Германия)"
                        elif tag == "840":
                            tname = "US Pool (США)"
                        else:
                            tname = f"Custom Feed ({tag})"
                            
                        custom_results.append({
                            "prefix": p,
                            "addresses": f"{net.num_addresses:,}" if net else "1",
                            "type": tname,
                            "community": f"65000:{tag}",
                            "gateway": "wireguard1"
                        })

    ru_results = []
    cache_file = os.path.join(DATA_DIR, "last-good", "ru_prefixes.txt")
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            for l in f:
                p = l.strip()
                if p:
                    if not query or query.lower() in p.lower() or "ru" in query.lower():
                        net = is_valid_ipv4_net(p)
                        ru_results.append({
                            "prefix": p,
                            "addresses": f"{net.num_addresses:,}" if net else "1",
                            "type": "RU Pool",
                            "community": "65000:643 (RU)",
                            "gateway": "wireguard1"
                        })
                        
    all_results = custom_results + ru_results
    total = len(all_results)
    start = (page - 1) * limit
    end = start + limit
    return {"total": total, "page": page, "limit": limit, "items": all_results[start:end]}

def rebuild_all(force_ru_download=False):
    t_start = time.time()
    conn = None
    try:
        if force_ru_download:
            update_cloudflare_ranges()
            
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sources WHERE enabled = 1")
        sources = cursor.fetchall()
        
        cursor.execute("SELECT * FROM exclusions WHERE enabled = 1")
        exclusions = cursor.fetchall()
        
        custom_routes = []
        now_str = datetime.datetime.now().strftime("%d.%m.%Y, %H:%M:%S")
        
        raw_external_count = 8651
        custom_added_count = 0
        
        for s in sources:
            s_id = s["id"]
            s_type = s["type"]
            s_val = s["value"]
            s_comm = s["community"] or "65000:1000"
            
            prefixes = []
            err = None
            
            if s_type == "COUNTRY" and s_val.upper() == "RU":
                if force_ru_download or not os.path.exists(os.path.join(GENERATED_DIR, "ru_routes.conf")):
                    prefixes = fetch_country_prefixes("RU", force_download=force_ru_download)
                    raw_external_count = len(prefixes)
                    ru_conf_path = os.path.join(GENERATED_DIR, "ru_routes.conf")
                    with open(ru_conf_path, "w") as f:
                        f.write("# Generated Russian IPv4 Feed\n")
                        for p in sorted(prefixes):
                            f.write(f"route {p} blackhole {{ bgp_community.add((65000, 1000)); bgp_community.add((65000, 900)); bgp_community.add((65000, 643)); }};\n")
                else:
                    raw_external_count = s["prefix_count"] or 8651
                cursor.execute("""
                    UPDATE sources
                    SET prefix_count = ?, last_update = ?, status = ?, error = ?
                    WHERE id = ?
                """, (raw_external_count, now_str, "active", None, s_id))
            elif s_type == "COUNTRY":
                try:
                    prefixes = fetch_country_prefixes(s_val, force_download=force_ru_download)
                except Exception as e:
                    err = str(e)
                cursor.execute("""
                    UPDATE sources 
                    SET prefix_count = ?, last_update = ?, status = ?, error = ?
                    WHERE id = ?
                """, (len(prefixes), now_str, "error" if err else "active", err, s_id))
                custom_added_count += len(prefixes)
                for p in prefixes:
                    custom_routes.append((p, s_comm, s_type))
            else:
                try:
                    if s_type == "DOMAIN":
                        prefixes = resolve_domain(s_val)
                    elif s_type == "ASN":
                        prefixes = fetch_asn(s_val)
                    elif s_type == "PREFIX":
                        net = is_valid_ipv4_net(s_val)
                        if net:
                            prefixes = [str(net)]
                    elif s_type == "EXTERNAL_URL":
                        prefixes = fetch_external_url(s_val)
                except Exception as e:
                    err = str(e)
                    
                cursor.execute("""
                    UPDATE sources 
                    SET prefix_count = ?, last_update = ?, status = ?, error = ?
                    WHERE id = ?
                """, (len(prefixes), now_str, "error" if err else "active", err, s_id))
                
                custom_added_count += len(prefixes)
                for p in prefixes:
                    custom_routes.append((p, s_comm, s_type))

        exclusion_nets = []
        for exc in exclusions:
            net = is_valid_ipv4_net(exc["value"] if "/" in exc["value"] else f"{exc[value]}/32")
            if net:
                exclusion_nets.append(net)
                
        filtered_custom = []
        for p, comm, stype in custom_routes:
            net = is_valid_ipv4_net(p)
            if net and net not in exclusion_nets:
                filtered_custom.append((net, comm, stype))

        custom_conf_path = os.path.join(GENERATED_DIR, "custom_routes.conf")
        with open(custom_conf_path, "w") as f:
            f.write("# Generated Custom Routes Feed\n")
            for net, comm, stype in sorted(filtered_custom, key=lambda x: str(x[0])):
                # Extract community tag number (e.g. 65000:804 -> 804)
                comm_tag = 1000
                if ":" in comm:
                    try:
                        comm_tag = int(comm.split(":")[1])
                    except Exception:
                        pass
                f.write(f"route {net} blackhole {{ bgp_community.add((65000, 1000)); bgp_community.add((65000, {comm_tag})); }};\n")
                
        reload_bird()
        
        t_elapsed = round(time.time() - t_start, 3)
        duration_str = f"{t_elapsed}с"
        final_count = raw_external_count + len(filtered_custom)
        
        cursor.execute("""
            UPDATE stats SET
                last_gen_time = ?,
                gen_duration = ?,
                raw_count = ?,
                custom_count = ?,
                pre_filter_count = ?,
                post_filter_count = ?,
                final_count = ?,
                exclusions_applied = ?,
                collapsed_duplicates = ?
            WHERE id = 1
        """, (now_str, duration_str, raw_external_count, custom_added_count, raw_external_count + custom_added_count, final_count, final_count, len(exclusion_nets), 0))
        
        log_msg(f"Сборка завершена за {duration_str}: всего {final_count:,} маршрутов", "SUCCESS")
        return final_count
    finally:
        if conn:
            conn.close()

def reload_bird():
    try:
        transport = httpx.HTTPTransport(uds="/var/run/docker.sock")
        with httpx.Client(transport=transport, timeout=3) as client:
            r = client.post(f"http://docker/containers/{BGP_CORE_CONTAINER}/exec", json={
                "Cmd": ["birdc", "configure"],
                "AttachStdout": True,
                "AttachStderr": True
            })
            exec_id = r.json().get("Id")
            if exec_id:
                client.post(f"http://docker/exec/{exec_id}/start", json={"Detach": False, "Tty": False})
        log_msg("BIRD 2 успешно перезагружен", "SUCCESS")
    except Exception as e:
        log_msg(f"Ошибка перезагрузки BIRD: {e}", "ERROR")

def check_ip_in_feed(ip_str):
    try:
        target_ip = ipaddress.IPv4Address(ip_str.strip())
    except Exception:
        return {"error": "Некорректный IPv4-адрес"}
        
    cache_file = os.path.join(DATA_DIR, "last-good", "ru_prefixes.txt")
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            for l in f:
                p = l.strip()
                if p:
                    net = is_valid_ipv4_net(p)
                    if net and target_ip in net:
                        return {"ip": ip_str, "found": True, "matching_prefix": p}
                        
    return {"ip": ip_str, "found": False}
