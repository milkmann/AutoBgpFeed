from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
import asyncio
import os
import subprocess
import json
import re
import secrets
from .db import init_db, get_db
from .engine import rebuild_all, resolve_domain, fetch_asn, is_valid_ipv4_net, check_ip_in_feed, log_msg, get_mask_distribution, search_routes_in_cache, get_source_prefixes, universal_inspect

app = FastAPI(title="Auto BGP Feed")
security = HTTPBasic()

AUTH_USER = os.environ.get("ADMIN_USER", "admin")
AUTH_PASS = os.environ.get("ADMIN_PASS", "changeme")

def check_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    is_user_ok = secrets.compare_digest(credentials.username.encode("utf8"), AUTH_USER.encode("utf8"))
    is_pass_ok = secrets.compare_digest(credentials.password.encode("utf8"), AUTH_PASS.encode("utf8"))
    if not (is_user_ok and is_pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

TEMPLATES_DIR = os.environ.get("TEMPLATES_DIR", "/app/templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.on_event("startup")
async def startup_event():
    init_db()
    asyncio.create_task(initial_build_task())
    asyncio.create_task(scheduler_task())

async def initial_build_task():
    await asyncio.sleep(1)
    await asyncio.to_thread(rebuild_all, force_ru_download=False)

async def scheduler_task():
    counter = 0
    while True:
        await asyncio.sleep(900)
        counter += 1
        force_ru = (counter % 96 == 0)
        try:
            await asyncio.to_thread(rebuild_all, force_ru_download=force_ru)
        except Exception as e:
            log_msg(f"Ошибка фонового обновления: {e}", "ERROR")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sources ORDER BY id ASC")
    sources = cursor.fetchall()
    
    cursor.execute("SELECT * FROM exclusions ORDER BY id ASC")
    exclusions = cursor.fetchall()
    
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50")
    logs = cursor.fetchall()
    
    cursor.execute("SELECT * FROM stats WHERE id = 1")
    stats = cursor.fetchone()
    conn.close()

    peer_info = {}
    try:
        res = subprocess.run("docker exec public-bgp vtysh -c \"show bgp neighbors json\"", shell=True, capture_output=True, text=True, timeout=3)
        if res.stdout:
            data = json.loads(res.stdout)
            for k, v in data.items():
                if k != "172.30.0.2":
                    peer_info = {
                        "ip": k,
                        "router_id": v.get("remoteRouterId", "—"),
                        "remote_as": v.get("remoteAs", "—"),
                        "state": v.get("bgpState", "—"),
                        "uptime": v.get("bgpTimerUpString", "—"),
                        "sent_prefixes": v.get("addressFamilyInfo", {}).get("ipv4Unicast", {}).get("sentPrefixCounter", 0),
                        "rtt_ms": v.get("estimatedRttInMsecs", "—"),
                        "updates_sent": v.get("messageStats", {}).get("updatesSent", 0),
                        "keepalives": f"{v.get('messageStats', {}).get('keepalivesRecv', 0)} in / {v.get('messageStats', {}).get('keepalivesSent', 0)} out"
                    }
                    break
    except Exception:
        pass

    mask_dist = get_mask_distribution()
    server_ip = os.environ.get("SERVER_IP", "127.0.0.1")
    server_asn = os.environ.get("SERVER_ASN", "65000")

    return templates.TemplateResponse(request=request, name="index.html", context={
        "sources": sources,
        "exclusions": exclusions,
        "logs": logs,
        "stats": stats,
        "peer_info": peer_info,
        "mask_dist": mask_dist,
        "server_ip": server_ip,
        "server_asn": server_asn,
        "current_user": user
    })

@app.get("/api/telemetry")
async def api_telemetry(user: str = Depends(check_credentials)):
    peer_info = {}
    try:
        res = subprocess.run("docker exec public-bgp vtysh -c \"show bgp neighbors json\"", shell=True, capture_output=True, text=True, timeout=3)
        if res.stdout:
            data = json.loads(res.stdout)
            for k, v in data.items():
                if k != "172.30.0.2":
                    peer_info = {
                        "ip": k,
                        "router_id": v.get("remoteRouterId", "—"),
                        "remote_as": v.get("remoteAs", "—"),
                        "state": v.get("bgpState", "—"),
                        "uptime": v.get("bgpTimerUpString", "—"),
                        "sent_prefixes": v.get("addressFamilyInfo", {}).get("ipv4Unicast", {}).get("sentPrefixCounter", 0),
                        "rtt_ms": v.get("estimatedRttInMsecs", "—"),
                        "updates_sent": v.get("messageStats", {}).get("updatesSent", 0),
                        "keepalives": f"{v.get('messageStats', {}).get('keepalivesRecv', 0)} in / {v.get('messageStats', {}).get('keepalivesSent', 0)} out"
                    }
                    break
    except Exception:
        pass
    return {"peer": peer_info, "masks": get_mask_distribution()}

@app.get("/api/routes")
async def api_routes(q: str = Query("", alias="q"), page: int = Query(1), limit: int = Query(50), user: str = Depends(check_credentials)):
    return search_routes_in_cache(query=q, page=page, limit=limit)

@app.get("/api/sources/{source_id}/prefixes")
async def api_source_prefixes(source_id: int, user: str = Depends(check_credentials)):
    return get_source_prefixes(source_id)

@app.get("/api/logs")
async def api_logs(user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 60")
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"logs": logs}

@app.post("/api/tools/inspect")
async def tool_inspect(query: str = Form(...), user: str = Depends(check_credentials)):
    return universal_inspect(query)

@app.post("/api/tools/lookup-ip")
async def tool_lookup_ip(ip: str = Form(...), user: str = Depends(check_credentials)):
    return check_ip_in_feed(ip)

@app.post("/api/tools/lookup-dns")
async def tool_lookup_dns(domain: str = Form(...), user: str = Depends(check_credentials)):
    ips = resolve_domain(domain)
    return {"domain": domain, "count": len(ips), "resolved_ips": ips}

@app.post("/api/tools/lookup-asn")
async def tool_lookup_asn(asn: str = Form(...), user: str = Depends(check_credentials)):
    asn_num = re.sub(r"[^0-9]", "", asn)
    prefixes = fetch_asn(asn_num)
    return {"asn": f"AS{asn_num}", "count": len(prefixes), "prefixes": prefixes}

@app.post("/api/sources/add")
async def add_source(name: str = Form(...), source_type: str = Form(...), value: str = Form(...), user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    
    comm = "65000:1000"
    if source_type == "COUNTRY" charity_comm="65000:643":
        comm = "65000:643"
    elif source_type == "DOMAIN":
        comm = "65000:200"
    elif source_type == "ASN":
        comm = "65000:300"
    elif source_type == "PREFIX":
        comm = "65000:600"
        
    cursor.execute("""
        INSERT INTO sources (name, type, value, enabled, community, status)
        VALUES (?, ?, ?, 1, ?, "pending")
    """, (name, source_type, value, comm))
    conn.close()
    
    log_msg(f"Добавлен источник: {name} ({source_type}: {value})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#sources", status_code=303)

@app.post("/api/sources/{source_id}/toggle")
async def toggle_source(source_id: int, user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE sources SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", (source_id,))
    conn.close()
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#sources", status_code=303)

@app.post("/api/sources/{source_id}/delete")
async def delete_source(source_id: int, user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sources WHERE id = ?", (source_id,))
    conn.close()
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#sources", status_code=303)

@app.post("/api/exclusions/add")
async def add_exclusion(name: str = Form(...), value: str = Form(...), user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO exclusions (name, type, value, enabled) VALUES (?, 'PREFIX', ?, 1)", (name, value))
    conn.close()
    log_msg(f"Добавлено правило исключения: {name} ({value})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#exclusions", status_code=303)

@app.post("/api/exclusions/{exc_id}/delete")
async def delete_exclusion(exc_id: int, user: str = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM exclusions WHERE id = ?", (exc_id,))
    conn.close()
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#exclusions", status_code=303)

@app.post("/api/rebuild")
async def manual_rebuild(user: str = Depends(check_credentials)):
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=True))
    return RedirectResponse(url="/", status_code=303)
