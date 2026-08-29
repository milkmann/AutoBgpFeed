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
import sqlite3
from .db import init_db, get_db, hash_password, verify_password
from .engine import rebuild_all, resolve_domain, fetch_asn, is_valid_ipv4_net, check_ip_in_feed, log_msg, get_mask_distribution, search_routes_in_cache, get_source_prefixes, universal_inspect

app = FastAPI(title="Auto BGP Feed")
security = HTTPBasic()

def check_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username.strip()
    password = credentials.password
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(password, user["password_hash"]):
        return {"username": user["username"], "role": user["role"], "id": user["id"]}
        
    # Fallback to env check for initial setup
    env_user = os.environ.get("ADMIN_USER", "admin")
    env_pass = os.environ.get("ADMIN_PASS", "changeme")
    if secrets.compare_digest(username, env_user) and secrets.compare_digest(password, env_pass):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", (username, hash_password(password)))
        conn.close()
        return {"username": username, "role": "admin", "id": 1}
        
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверный логин или пароль",
        headers={"WWW-Authenticate": "Basic"},
    )

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
async def index(request: Request, user: dict = Depends(check_credentials)):
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
    
    cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
    users_list = cursor.fetchall()
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
        "current_user": user["username"],
        "current_user_role": user["role"],
        "current_user_id": user["id"],
        "users_list": users_list
    })

@app.get("/api/telemetry")
async def api_telemetry(user: dict = Depends(check_credentials)):
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
async def api_routes(
    q: str = Query("", alias="q"),
    page: int = Query(1),
    limit: int = Query(50),
    sort_by: str = Query("default"),
    sort_order: str = Query("asc"),
    user: dict = Depends(check_credentials)
):
    return search_routes_in_cache(query=q, page=page, limit=limit, sort_by=sort_by, sort_order=sort_order)

@app.get("/api/sources/{source_id}/prefixes")
async def api_source_prefixes(source_id: int, user: dict = Depends(check_credentials)):
    return get_source_prefixes(source_id)

@app.get("/api/logs")
async def api_logs(user: dict = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 60")
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"logs": logs}

@app.post("/api/tools/inspect")
async def tool_inspect(query: str = Form(...), user: dict = Depends(check_credentials)):
    return universal_inspect(query)

@app.post("/api/tools/lookup-ip")
async def tool_lookup_ip(ip: str = Form(...), user: dict = Depends(check_credentials)):
    return check_ip_in_feed(ip)

@app.post("/api/tools/lookup-dns")
async def tool_lookup_dns(domain: str = Form(...), user: dict = Depends(check_credentials)):
    ips = resolve_domain(domain)
    return {"domain": domain, "count": len(ips), "resolved_ips": ips}

@app.post("/api/tools/lookup-asn")
async def tool_lookup_asn(asn: str = Form(...), user: dict = Depends(check_credentials)):
    asn_num = re.sub(r"[^0-9]", "", asn)
    prefixes = fetch_asn(asn_num)
    return {"asn": f"AS{asn_num}", "count": len(prefixes), "prefixes": prefixes}

@app.post("/api/sources/add")
async def add_source(name: str = Form(...), source_type: str = Form(...), value: str = Form(...), user: dict = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    
    val_clean = value.strip()
    name_clean = name.strip()
    comm = "65000:1000"
    
    if source_type == "COUNTRY":
        from .engine import resolve_country_input
        iso_code, nice_name, iso_num = resolve_country_input(val_clean)
        val_clean = iso_code
        if not name_clean or name_clean.lower() in ["страна", "country", ""]:
            name_clean = nice_name
        comm = f"65000:{iso_num}"
    elif source_type == "DOMAIN":
        comm = "65000:200"
    elif source_type == "ASN":
        comm = "65000:300"
    elif source_type == "PREFIX":
        comm = "65000:600"
        
    cursor.execute("""
        INSERT INTO sources (name, type, value, enabled, community, status)
        VALUES (?, ?, ?, 1, ?, "pending")
    """, (name_clean, source_type, val_clean, comm))
    conn.close()
    
    log_msg(f"Пользователь {user['username']} добавил источник: {name_clean} ({source_type}: {val_clean})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#sources", status_code=303)

@app.post("/api/sources/{source_id}/toggle")
async def toggle_source(source_id: int, user: dict = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE sources SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", (source_id,))
    conn.close()
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#sources", status_code=303)

@app.post("/api/sources/{source_id}/delete")
async def delete_source(source_id: int, user: dict = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sources WHERE id = ?", (source_id,))
    conn.close()
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#sources", status_code=303)

@app.post("/api/exclusions/add")
async def add_exclusion(name: str = Form(...), value: str = Form(...), user: dict = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO exclusions (name, type, value, enabled) VALUES (?, 'PREFIX', ?, 1)", (name, value))
    conn.close()
    log_msg(f"Пользователь {user['username']} добавил правило исключения: {name} ({value})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#exclusions", status_code=303)

@app.post("/api/exclusions/{exc_id}/delete")
async def delete_exclusion(exc_id: int, user: dict = Depends(check_credentials)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM exclusions WHERE id = ?", (exc_id,))
    conn.close()
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=False))
    return RedirectResponse(url="/#exclusions", status_code=303)

@app.post("/api/rebuild")
async def manual_rebuild(user: dict = Depends(check_credentials)):
    asyncio.create_task(asyncio.to_thread(rebuild_all, force_ru_download=True))
    return RedirectResponse(url="/", status_code=303)

# ----------------- User Management Endpoints -----------------
@app.post("/api/users/add")
async def add_user(username: str = Form(...), password: str = Form(...), role: str = Form("admin"), user: dict = Depends(check_credentials)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Только администраторы могут создавать пользователей")
    u_clean = username.strip()
    if not u_clean or len(password) < 4:
        return RedirectResponse(url="/#settings", status_code=303)
        
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (u_clean, hash_password(password), role))
        log_msg(f"Администратор {user['username']} создал учетную запись «{u_clean}» (роль: {role})", "INFO")
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()
    return RedirectResponse(url="/#settings", status_code=303)

@app.post("/api/users/{user_id}/delete")
async def delete_user(user_id: int, user: dict = Depends(check_credentials)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Только администраторы могут удалять пользователей")
    if user_id == user.get("id"):
        return RedirectResponse(url="/#settings", status_code=303) # Нельзя удалить самого себя
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    if target:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_msg(f"Администратор {user['username']} удалил пользователя «{target['username']}» (ID {user_id})", "INFO")
    conn.close()
    return RedirectResponse(url="/#settings", status_code=303)

@app.post("/api/users/change-password")
async def change_password(old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...), user: dict = Depends(check_credentials)):
    if new_password != confirm_password:
        return JSONResponse({"status": "error", "message": "Новые пароли не совпадают!"}, status_code=400)
    if len(new_password) < 4:
        return JSONResponse({"status": "error", "message": "Пароль должен содержать минимум 4 символа!"}, status_code=400)
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user["id"],))
    db_user = cursor.fetchone()
    
    if not db_user or not verify_password(old_password, db_user["password_hash"]):
        conn.close()
        return JSONResponse({"status": "error", "message": "Неверный текущий пароль!"}, status_code=400)
        
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["id"]))
    conn.close()
    log_msg(f"Пользователь «{user['username']}» успешно изменил свой пароль", "SUCCESS")
    return JSONResponse({"status": "ok", "message": "Пароль успешно изменён! Используйте новый пароль при следующем входе."})
