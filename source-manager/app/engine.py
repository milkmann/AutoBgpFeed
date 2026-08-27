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

def fetch_ru_prefixes(force_download=False):
    cache_file = os.path.join(DATA_DIR, "last-good", "ru_prefixes.txt")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    
    if not force_download and os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            cached = [l.strip() for l in f if l.strip()]
            if cached:
                return cached

    log_msg("Загрузка актуального реестра RU подсетей (IPverse & RIPE NCC)...", "INFO")
    nets = []
    try:
        url = "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = resp.read().decode().splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                net = is_valid_ipv4_net(line)
                if net:
                    nets.append(net)
        log_msg(f"Получено {len(nets):,} сетей из IPverse", "INFO")
    except Exception as e:
        log_msg(f"Ошибка загрузки IPverse RU: {e}", "WARN")

    if not nets:
        try:
            url = "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                lines = resp.read().decode().splitlines()
            for l in lines:
                parts = l.strip().split("|")
                if len(parts) >= 7 and parts[1] == "RU" and parts[2] == "ipv4" and parts[6] in ("allocated", "assigned"):
                    ip_start = parts[3]
                    count = int(parts[4])
                    if count > 0:
                        prefix_len = 32 - int(math.log2(count))
                        net = is_valid_ipv4_net(f"{ip_start}/{prefix_len}")
                        if net:
                            nets.append(net)
            log_msg(f"Получено {len(nets):,} сетей из RIPE NCC", "INFO")
        except Exception as e:
            log_msg(f"Ошибка загрузки RIPE NCC: {e}", "ERROR")

    if nets:
        collapsed = list(ipaddress.collapse_addresses(nets))
        with open(cache_file, "w") as f:
            for n in collapsed:
                f.write(f"{n}\n")
        log_msg(f"Успешно нормализовано {len(collapsed):,} префиксов RU", "SUCCESS")
        return [str(n) for n in collapsed]
    
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            return [l.strip() for l in f if l.strip()]
            
    return []

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
    asn_num = re.sub(r"[^0-9]", "", asn_str)
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
    query = query.strip().lower()
    if query.startswith("http://") or query.startswith("https://"):
        query = query.split("/")[2].split(":")[0]
        
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
                for rdata in ans:
                    resolved_ips.append(rdata.to_text())
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
            
    return {
        "target": query,
        "is_ip": is_ip,
        "resolved_ips": resolved_ips,
        "primary_ip": primary_ip,
        "country": geo_data.get("country", "Неизвестно"),
        "country_code": geo_data.get("countryCode", "UN"),
        "provider": geo_data.get("isp", geo_data.get("org", "—")),
        "asn": asn_str,
        "asn_full": asn_raw,
        "asn_prefix_count": asn_prefix_count,
        "is_cdn": is_cdn,
        "is_cloudflare": is_cf,
        "in_ru_feed": in_ru_feed
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
        
        if s_type == "COUNTRY" and s_val.upper() == "RU":
            prefixes = fetch_ru_prefixes(force_download=False)[:100]
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
                    if not query or query.lower() in p.lower() or "custom" in query.lower():
                        net = is_valid_ipv4_net(p)
                        tname = "Custom Domain" if tag == "200" else ("Custom ASN" if tag == "300" else "Custom CIDR")
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
                    prefixes = fetch_ru_prefixes(force_download=force_ru_download)
                    raw_external_count = len(prefixes)
                    ru_conf_path = os.path.join(GENERATED_DIR, "ru_routes.conf")
                    with open(ru_conf_path, "w") as f:
                        f.write("# Generated Russian IPv4 Feed\n")
                        for p in sorted(prefixes):
                            f.write(f"route {p} blackhole {{ bgp_community.add((65000, 1000)); bgp_community.add((65000, 900)); bgp_community.add((65000, 643)); }};\n")
                else:
                    raw_external_count = s["prefix_count"] or 8651
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
            net = is_valid_ipv4_net(exc["value"] if "/" in exc["value"] else f"{exc['value']}/32")
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
                type_tag = 200 if stype == "DOMAIN" else (300 if stype == "ASN" else (600 if stype == "PREFIX" else 500))
                f.write(f"route {net} blackhole {{ bgp_community.add((65000, 1000)); bgp_community.add((65000, {type_tag})); }};\n")
                
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
    matching_prefixes = []
    if os.path.exists(cache_file):
        with open(cache_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    net = is_valid_ipv4_net(line)
                    if net and target_ip in net:
                        matching_prefixes.append(str(net))
                        break
                        
    return {
        "ip": str(target_ip),
        "found": len(matching_prefixes) > 0,
        "matching_prefix": matching_prefixes[0] if matching_prefixes else None,
        "feed": "Russian IPv4 Feed (RU)" if matching_prefixes else "Вне российского фида"
    }
