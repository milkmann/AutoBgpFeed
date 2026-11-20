"""FastAPI web gateway, scheduler, operational metrics, and authenticated admin API for AutoBgpFeed v2."""

import asyncio
from contextlib import asynccontextmanager
import datetime
import json
import logging
import os
import re
import sqlite3
import time

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .auth import (
    LoginRedirectRequired,
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    authenticate_user,
    create_session_token,
    get_client_ip,
    get_current_user_or_none,
    is_https_request,
    login_limiter,
    require_admin,
    require_user,
    verify_csrf,
)
from .bird_client import bird_cleanup_stale_peers, bird_peers, bird_route_count, bird_status
from .db import DEFAULT_VPN_PROFILES, get_db, get_settings, hash_password, init_db, set_settings, verify_password
from .engine import (
    ALLOWED_SOURCE_TYPES,
    apply_preview,
    check_ip_in_feed,
    create_preview,
    export_config_backup,
    export_mikrotik_rsc,
    fetch_asn,
    get_mask_distribution,
    get_server_asn,
    get_server_ip,
    get_source_prefixes,
    import_config_backup,
    invalidate_source_cache,
    list_revisions,
    log_msg,
    rebuild_all,
    resolve_country_input,
    resolve_domain,
    restore_revision,
    save_revision,
    search_routes_in_cache,
    universal_inspect,
    validate_external_url,
)

APP_START_TIME = time.time()
POLLING_PATHS = {"/healthz", "/status.json", "/metrics", "/api/telemetry", "/api/logs"}


class PollingAccessFilter(logging.Filter):
    """Suppress noisy 200 OK polling/healthcheck lines from uvicorn access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            args = record.args
            if isinstance(args, tuple) and len(args) >= 5:
                path_raw = str(args[2]).split("?", 1)[0]
                status_code = int(args[4])
                if status_code == 200 and path_raw in POLLING_PATHS:
                    return False
        except Exception:
            pass
        return True


def _install_access_log_filter() -> None:
    access_logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, PollingAccessFilter) for f in access_logger.filters):
        access_logger.addFilter(PollingAccessFilter())


async def _cleanup_zombie_peers_once() -> None:
    cleaned = await asyncio.to_thread(bird_cleanup_stale_peers, 300)
    if cleaned:
        desc = ", ".join(f"{p['name']} ({p['ip']})" for p in cleaned)
        await asyncio.to_thread(log_msg, f"Очищено неактивных BGP-пиров ({len(cleaned)}): {desc}", "INFO")


async def _initial_build_task() -> None:
    await asyncio.sleep(1)
    try:
        await _cleanup_zombie_peers_once()
        await asyncio.to_thread(rebuild_all, False, False)
    except Exception as exc:
        log_msg(f"Ошибка начальной сборки: {exc}", "ERROR")


async def _bird_maintenance_task() -> None:
    while True:
        await asyncio.sleep(300)
        try:
            await _cleanup_zombie_peers_once()
        except Exception as exc:
            log_msg(f"Ошибка очистки пиров BIRD: {exc}", "WARN")


async def _scheduler_task() -> None:
    cycle = 0
    while True:
        try:
            settings = await asyncio.to_thread(get_settings)
            interval = max(60, int(settings.get("update_interval_sec", "900")))
        except Exception:
            interval = 900
        await asyncio.sleep(interval)
        cycle += 1
        force_full = (cycle % 96) == 0  # Full country refresh once per ~24h
        try:
            await asyncio.to_thread(rebuild_all, force_full, False)
        except Exception as exc:
            log_msg(f"Ошибка фонового обновления: {exc}", "ERROR")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _install_access_log_filter()
    init_db()
    init_task = asyncio.create_task(_initial_build_task())
    sched_task = asyncio.create_task(_scheduler_task())
    maint_task = asyncio.create_task(_bird_maintenance_task())
    try:
        yield
    finally:
        init_task.cancel()
        sched_task.cancel()
        maint_task.cancel()


app = FastAPI(title="AutoBgpFeed v2", lifespan=lifespan)

STATIC_DIR = os.environ.get("STATIC_DIR", "/app/static")
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

TEMPLATES_DIR = os.environ.get("TEMPLATES_DIR", "/app/templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


@app.exception_handler(LoginRedirectRequired)
async def _login_redirect_handler(request: Request, exc: LoginRedirectRequired):
    return RedirectResponse(url="/login", status_code=303)


def _gather_operational_status() -> dict:
    b_stat = bird_status()
    bird_up = bool(b_stat.get("up"))
    live_routes = bird_route_count() if bird_up else 0
    peers = bird_peers() if bird_up else []
    established = sum(1 for p in peers if str(p.get("state", "")).lower() == "established")

    conn = get_db()
    try:
        st = conn.execute("SELECT * FROM stats WHERE id = 1").fetchone()
        stats = dict(st) if st else {}
        err_rows = conn.execute(
            "SELECT name, error FROM sources WHERE enabled = 1 AND status = 'error' ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    degraded = bool(stats.get("degraded"))
    error_sources = [f"{r['name']}: {r['error'] or 'ошибка'}" for r in err_rows]
    error_source_names = [r["name"] for r in err_rows]
    anomaly = bool(stats.get("anomaly"))
    anomaly_reason = stats.get("anomaly_reason") or ""
    route_delta_pct = float(stats.get("route_delta_pct") or 0.0)
    final_count = int(stats.get("final_count") or live_routes or 0)
    ok = bird_up and (live_routes > 0 or final_count == 0)

    issue_parts = []
    if stats.get("degraded_reason"):
        issue_parts.append(str(stats["degraded_reason"]))
    if error_sources:
        issue_parts.append("Ошибки источников: " + "; ".join(error_sources[:3]))
    if anomaly_reason:
        issue_parts.append(anomaly_reason)
    issue_summary = "; ".join(issue_parts)

    duration_raw = str(stats.get("gen_duration") or "0").rstrip("сs")
    try:
        duration_sec = float(duration_raw)
    except ValueError:
        duration_sec = 0.0

    last_apply_ts = 0
    confirmed_path = os.path.join(os.environ.get("DATA_DIR", "/data"), "confirmed_snapshot.json")
    if os.path.exists(confirmed_path):
        try:
            with open(confirmed_path, "r", encoding="utf-8") as f:
                last_apply_ts = int(json.load(f).get("applied_at_unix", 0))
        except Exception:
            pass

    return {
        "ok": ok,
        "bird_up": bird_up,
        "routes": live_routes or final_count,
        "peers_total": len(peers),
        "peers_established": established,
        "degraded": degraded,
        "degraded_reason": stats.get("degraded_reason") or "",
        "error_sources_count": len(error_sources),
        "error_sources": error_source_names,
        "route_delta_pct": route_delta_pct,
        "anomaly": anomaly,
        "anomaly_reason": anomaly_reason,
        "issue_summary": issue_summary,
        "last_gen_time": stats.get("last_gen_time") or "—",
        "gen_duration": stats.get("gen_duration") or "—",
        "duration_seconds": duration_sec,
        "last_apply_timestamp": last_apply_ts,
        "uptime_sec": int(time.time() - APP_START_TIME),
    }


# ----------------- Public Operational Endpoints -----------------


@app.get("/healthz")
async def healthz():
    status_data = await asyncio.to_thread(_gather_operational_status)
    code = 200 if status_data["ok"] else 503
    return JSONResponse(status_data, status_code=code)


@app.get("/status.json")
async def public_status():
    return await asyncio.to_thread(_gather_operational_status)


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    s = await asyncio.to_thread(_gather_operational_status)
    lines = [
        "# HELP autobgp_bird_up Whether BIRD 2 daemon is up (1 or 0).",
        "# TYPE autobgp_bird_up gauge",
        f"autobgp_bird_up {1 if s['bird_up'] else 0}",
        "# HELP autobgp_routes_total Total active IPv4 routes in BIRD.",
        "# TYPE autobgp_routes_total gauge",
        f"autobgp_routes_total {s['routes']}",
        "# HELP autobgp_peers_established Number of established BGP client sessions.",
        "# TYPE autobgp_peers_established gauge",
        f"autobgp_peers_established {s['peers_established']}",
        "# HELP autobgp_degraded Whether route generation is degraded (using stale cache).",
        "# TYPE autobgp_degraded gauge",
        f"autobgp_degraded {1 if s['degraded'] else 0}",
        "# HELP autobgp_error_sources Number of enabled sources currently in error state.",
        "# TYPE autobgp_error_sources gauge",
        f"autobgp_error_sources {s['error_sources_count']}",
        "# HELP autobgp_route_anomaly Whether a sudden route count jump (>=40%) occurred.",
        "# TYPE autobgp_route_anomaly gauge",
        f"autobgp_route_anomaly {1 if s['anomaly'] else 0}",
        "# HELP autobgp_last_gen_duration_seconds Last route compilation duration in seconds.",
        "# TYPE autobgp_last_gen_duration_seconds gauge",
        f"autobgp_last_gen_duration_seconds {s['duration_seconds']}",
        "# HELP autobgp_last_apply_timestamp_seconds Unix timestamp of last successful BIRD apply.",
        "# TYPE autobgp_last_apply_timestamp_seconds gauge",
        f"autobgp_last_apply_timestamp_seconds {s['last_apply_timestamp']}",
        "# HELP autobgp_uptime_seconds Web manager uptime in seconds.",
        "# TYPE autobgp_uptime_seconds gauge",
        f"autobgp_uptime_seconds {s['uptime_sec']}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8")


# ----------------- Authentication Routes -----------------


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_current_user_or_none(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None, "username": ""})


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = get_client_ip(request)
    locked, retry_after = login_limiter.is_locked(client_ip)
    if locked:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": f"Слишком много неудачных попыток. Повторите через {retry_after} сек.", "username": username},
            status_code=429,
        )

    user = await asyncio.to_thread(authenticate_user, username, password)
    if not user:
        now_locked, lock_sec = login_limiter.record_failure(client_ip)
        msg = (
            f"Превышен лимит попыток. Вход заблокирован на {lock_sec // 60} мин."
            if now_locked
            else "Неверный логин или пароль."
        )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": msg, "username": username},
            status_code=429 if now_locked else 401,
        )

    login_limiter.clear(client_ip)
    token = create_session_token(user["id"], user["username"], user["role"])
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=is_https_request(request),
        path="/",
    )
    return resp


@app.post("/logout")
async def logout(user: dict = Depends(verify_csrf)):
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return resp


# ----------------- Main Dashboard & Telemetry -----------------


def _load_dashboard_context(user: dict) -> dict:
    conn = get_db()
    try:
        sources = [dict(r) for r in conn.execute("SELECT * FROM sources ORDER BY id ASC").fetchall()]
        exclusions = [dict(r) for r in conn.execute("SELECT * FROM exclusions ORDER BY id ASC").fetchall()]
        logs = [dict(r) for r in conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 60").fetchall()]
        st_row = conn.execute("SELECT * FROM stats WHERE id = 1").fetchone()
        stats = dict(st_row) if st_row else {}
        users_list = [dict(r) for r in conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC").fetchall()]
        settings = get_settings(conn)
    finally:
        conn.close()

    try:
        vpn_profiles = json.loads(settings.get("vpn_profiles") or "[]")
    except Exception:
        vpn_profiles = DEFAULT_VPN_PROFILES

    b_stat = bird_status()
    peers = bird_peers() if b_stat.get("up") else []
    revisions = list_revisions()
    mask_dist = get_mask_distribution()

    return {
        "sources": sources,
        "exclusions": exclusions,
        "logs": logs,
        "stats": stats,
        "peers": peers,
        "peer_info": peers[0] if peers else {},
        "bird_info": b_stat,
        "mask_dist": mask_dist,
        "server_ip": get_server_ip() or "127.0.0.1",
        "server_asn": get_server_asn(),
        "current_user": user["username"],
        "current_user_role": user["role"],
        "current_user_id": user["id"],
        "csrf_token": user["csrf"],
        "users_list": users_list,
        "settings": settings,
        "vpn_profiles": vpn_profiles,
        "revisions": revisions,
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: dict = Depends(require_user)):
    ctx = await asyncio.to_thread(_load_dashboard_context, user)
    return templates.TemplateResponse(request=request, name="index.html", context=ctx)


@app.get("/api/telemetry")
async def api_telemetry(user: dict = Depends(require_user)):
    def _fetch():
        b_stat = bird_status()
        peers = bird_peers() if b_stat.get("up") else []
        conn = get_db()
        try:
            st = conn.execute("SELECT * FROM stats WHERE id = 1").fetchone()
            stats = dict(st) if st else {}
        finally:
            conn.close()
        return {
            "bird": b_stat,
            "peers": peers,
            "peer": peers[0] if peers else {},
            "masks": get_mask_distribution(),
            "degraded": bool(stats.get("degraded")),
            "degraded_reason": stats.get("degraded_reason") or "",
            "stats": stats,
        }

    return await asyncio.to_thread(_fetch)


@app.get("/api/routes")
async def api_routes(
    q: str = Query("", alias="q"),
    page: int = Query(1),
    limit: int = Query(50),
    sort_by: str = Query("default"),
    sort_order: str = Query("asc"),
    user: dict = Depends(require_user),
):
    return await asyncio.to_thread(search_routes_in_cache, q, page, limit, sort_by, sort_order)


@app.get("/api/sources/{source_id}/prefixes")
async def api_source_prefixes(source_id: int, user: dict = Depends(require_user)):
    return await asyncio.to_thread(get_source_prefixes, source_id)


@app.get("/api/logs")
async def api_logs(user: dict = Depends(require_user)):
    def _fetch_logs():
        conn = get_db()
        try:
            return [dict(r) for r in conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 80").fetchall()]
        finally:
            conn.close()

    return {"logs": await asyncio.to_thread(_fetch_logs)}


# ----------------- Tools & Intelligence -----------------


@app.post("/api/tools/inspect")
async def tool_inspect(query: str = Form(...), user: dict = Depends(verify_csrf)):
    return await asyncio.to_thread(universal_inspect, query)


@app.post("/api/tools/lookup-ip")
async def tool_lookup_ip(ip: str = Form(...), user: dict = Depends(verify_csrf)):
    return await asyncio.to_thread(check_ip_in_feed, ip)


@app.post("/api/tools/lookup-dns")
async def tool_lookup_dns(domain: str = Form(...), user: dict = Depends(verify_csrf)):
    ips = await asyncio.to_thread(resolve_domain, domain)
    return {"domain": domain, "count": len(ips), "resolved_ips": ips}


@app.post("/api/tools/lookup-asn")
async def tool_lookup_asn(asn: str = Form(...), user: dict = Depends(verify_csrf)):
    asn_num = re.sub(r"[^0-9]", "", asn)
    prefixes = await asyncio.to_thread(fetch_asn, asn_num)
    return {"asn": f"AS{asn_num}", "count": len(prefixes), "prefixes": prefixes}


# ----------------- Sources & Exclusions (Admin + CSRF) -----------------


def _normalize_source_fields(
    name: str,
    source_type: str,
    value: str,
    community: str = "",
    gateway: str = "wireguard1",
    cdn_mode: str = "auto",
) -> tuple[str, str, str, str, str, str]:
    s_type = source_type.strip().upper()
    if s_type not in ALLOWED_SOURCE_TYPES:
        raise HTTPException(status_code=400, detail="Неподдерживаемый тип источника")

    val_clean = value.strip()
    name_clean = name.strip()
    gw_clean = re.sub(r"[^A-Za-z0-9_.-]", "", gateway.strip()) or "wireguard1"
    cdn_clean = cdn_mode.strip() if cdn_mode in ("auto", "exact", "subnet24") else "auto"
    asn = get_server_asn()

    if s_type == "COUNTRY":
        iso_code, nice_name, iso_num = resolve_country_input(val_clean)
        val_clean = iso_code
        if not name_clean or name_clean.lower() in ["страна", "country", ""]:
            name_clean = nice_name
        default_comm = f"{asn}:{iso_num}"
    elif s_type == "GOOGLE":
        val_clean = "google-non-cloud"
        if not name_clean:
            name_clean = "Google (без Google Cloud)"
        default_comm = f"{asn}:1000"
    elif s_type in ("EXTERNAL_URL", "DOMAIN_LIST_URL"):
        try:
            validate_external_url(val_clean)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        default_comm = f"{asn}:500"
    elif s_type == "DOMAIN":
        default_comm = f"{asn}:200"
    elif s_type == "ASN":
        default_comm = f"{asn}:300"
    else:
        default_comm = f"{asn}:600"

    if not name_clean:
        name_clean = val_clean
    comm_clean = community.strip()
    if not re.fullmatch(r"\d+:\d+", comm_clean):
        comm_clean = default_comm
    return name_clean, s_type, val_clean, comm_clean, gw_clean, cdn_clean


@app.post("/api/sources/add")
async def add_source(
    name: str = Form(...),
    source_type: str = Form(...),
    value: str = Form(...),
    community: str = Form(""),
    gateway: str = Form("wireguard1"),
    cdn_mode: str = Form("auto"),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    name_clean, s_type, val_clean, comm_clean, gw_clean, cdn_clean = _normalize_source_fields(
        name, source_type, value, community, gateway, cdn_mode
    )

    def _insert():
        conn = get_db()
        try:
            with conn:
                save_revision("add_source", f"{name_clean} ({s_type}: {val_clean})", conn=conn)
                conn.execute(
                    """
                    INSERT INTO sources (name, type, value, enabled, community, status, gateway, cdn_mode)
                    VALUES (?, ?, ?, 1, ?, 'pending', ?, ?)
                    """,
                    (name_clean, s_type, val_clean, comm_clean, gw_clean, cdn_clean),
                )
        finally:
            conn.close()

    await asyncio.to_thread(_insert)
    log_msg(f"Пользователь {user['username']} добавил источник: {name_clean} ({s_type}: {val_clean} -> {gw_clean})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#sources", status_code=303)


@app.post("/api/sources/bulk")
async def bulk_add_sources(
    source_type: str = Form("DOMAIN"),
    entries: str = Form(...),
    community: str = Form(""),
    gateway: str = Form("wireguard1"),
    cdn_mode: str = Form("auto"),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    s_type = source_type.strip().upper()
    if s_type not in {"DOMAIN", "PREFIX", "ASN", "COUNTRY", "EXTERNAL_URL", "DOMAIN_LIST_URL"}:
        raise HTTPException(status_code=400, detail="Массовое добавление не поддерживает этот тип")

    parsed_rows: list[tuple[str, str, str, str, str, str]] = []
    for raw_line in entries.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if "|" in line:
            part_name, part_val = [p.strip() for p in line.split("|", 1)]
        else:
            part_name, part_val = "", line
        if not part_val:
            continue
        parsed_rows.append(_normalize_source_fields(part_name or part_val, s_type, part_val, community, gateway, cdn_mode))

    if not parsed_rows:
        raise HTTPException(status_code=400, detail="Список пуст")
    if len(parsed_rows) > 200:
        raise HTTPException(status_code=400, detail="За один раз можно добавить до 200 записей (для больших списков используйте DOMAIN_LIST_URL)")

    def _insert_bulk():
        conn = get_db()
        try:
            with conn:
                save_revision("bulk_add_sources", f"{len(parsed_rows)} x {s_type}", conn=conn)
                conn.executemany(
                    """
                    INSERT INTO sources (name, type, value, enabled, community, status, gateway, cdn_mode)
                    VALUES (?, ?, ?, 1, ?, 'pending', ?, ?)
                    """,
                    parsed_rows,
                )
        finally:
            conn.close()

    await asyncio.to_thread(_insert_bulk)
    log_msg(f"Пользователь {user['username']} массово добавил {len(parsed_rows)} источников ({s_type})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#sources", status_code=303)


@app.post("/api/sources/{source_id}/update")
async def update_source(
    source_id: int,
    name: str = Form(...),
    source_type: str = Form(...),
    value: str = Form(...),
    community: str = Form(""),
    gateway: str = Form("wireguard1"),
    cdn_mode: str = Form("auto"),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    name_clean, s_type, val_clean, comm_clean, gw_clean, cdn_clean = _normalize_source_fields(
        name, source_type, value, community, gateway, cdn_mode
    )

    def _update():
        conn = get_db()
        try:
            existing = conn.execute("SELECT id FROM sources WHERE id = ?", (source_id,)).fetchone()
            if not existing:
                return False
            with conn:
                save_revision("edit_source", f"ID {source_id}: {name_clean} ({s_type}: {val_clean})", conn=conn)
                conn.execute(
                    """
                    UPDATE sources
                    SET name = ?, type = ?, value = ?, community = ?, gateway = ?, cdn_mode = ?, status = 'pending', error = NULL
                    WHERE id = ?
                    """,
                    (name_clean, s_type, val_clean, comm_clean, gw_clean, cdn_clean, source_id),
                )
            invalidate_source_cache(source_id)
            return True
        finally:
            conn.close()

    ok = await asyncio.to_thread(_update)
    if not ok:
        raise HTTPException(status_code=404, detail="Источник не найден")
    log_msg(f"Пользователь {user['username']} обновил источник #{source_id}: {name_clean} -> {gw_clean} ({comm_clean})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#sources", status_code=303)


@app.post("/api/sources/{source_id}/toggle")
async def toggle_source(source_id: int, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    def _toggle():
        conn = get_db()
        try:
            with conn:
                save_revision("toggle_source", f"ID {source_id}", conn=conn)
                conn.execute("UPDATE sources SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", (source_id,))
        finally:
            conn.close()

    await asyncio.to_thread(_toggle)
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#sources", status_code=303)


@app.post("/api/sources/{source_id}/delete")
async def delete_source(source_id: int, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    def _delete():
        conn = get_db()
        try:
            with conn:
                save_revision("delete_source", f"ID {source_id}", conn=conn)
                conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        finally:
            conn.close()

    await asyncio.to_thread(_delete)
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#sources", status_code=303)


@app.post("/api/exclusions/add")
async def add_exclusion(
    name: str = Form(...),
    value: str = Form(...),
    exc_type: str = Form("PREFIX"),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    t_clean = exc_type.strip().upper()
    if t_clean not in ("PREFIX", "DOMAIN"):
        t_clean = "PREFIX"

    def _insert():
        conn = get_db()
        try:
            with conn:
                save_revision("add_exclusion", f"{name.strip()} ({t_clean}: {value.strip()})", conn=conn)
                conn.execute(
                    "INSERT INTO exclusions (name, type, value, enabled) VALUES (?, ?, ?, 1)",
                    (name.strip(), t_clean, value.strip()),
                )
        finally:
            conn.close()

    await asyncio.to_thread(_insert)
    log_msg(f"Пользователь {user['username']} добавил исключение: {name} ({t_clean}: {value})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#exclusions", status_code=303)


@app.post("/api/exclusions/bulk")
async def bulk_add_exclusions(
    exc_type: str = Form("PREFIX"),
    entries: str = Form(...),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    t_clean = exc_type.strip().upper()
    if t_clean not in ("PREFIX", "DOMAIN"):
        t_clean = "PREFIX"

    parsed: list[tuple[str, str, str]] = []
    for raw_line in entries.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if "|" in line:
            part_name, part_val = [p.strip() for p in line.split("|", 1)]
        else:
            part_name, part_val = line, line
        if part_val:
            parsed.append((part_name or part_val, t_clean, part_val))

    if not parsed:
        raise HTTPException(status_code=400, detail="Список исключений пуст")
    if len(parsed) > 500:
        raise HTTPException(status_code=400, detail="Максимум 500 исключений за один раз")

    def _insert_bulk():
        conn = get_db()
        try:
            with conn:
                save_revision("bulk_add_exclusions", f"{len(parsed)} x {t_clean}", conn=conn)
                conn.executemany(
                    "INSERT INTO exclusions (name, type, value, enabled) VALUES (?, ?, ?, 1)",
                    parsed,
                )
        finally:
            conn.close()

    await asyncio.to_thread(_insert_bulk)
    log_msg(f"Пользователь {user['username']} массово добавил {len(parsed)} исключений ({t_clean})", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#exclusions", status_code=303)


@app.post("/api/exclusions/{exc_id}/toggle")
async def toggle_exclusion(exc_id: int, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    def _toggle():
        conn = get_db()
        try:
            with conn:
                conn.execute("UPDATE exclusions SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", (exc_id,))
        finally:
            conn.close()

    await asyncio.to_thread(_toggle)
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#exclusions", status_code=303)


@app.post("/api/exclusions/{exc_id}/delete")
async def delete_exclusion(exc_id: int, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")

    def _delete():
        conn = get_db()
        try:
            with conn:
                save_revision("delete_exclusion", f"ID {exc_id}", conn=conn)
                conn.execute("DELETE FROM exclusions WHERE id = ?", (exc_id,))
        finally:
            conn.close()

    await asyncio.to_thread(_delete)
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#exclusions", status_code=303)


# ----------------- Previews, Rebuild, Export, Backup & Settings -----------------


@app.post("/api/preview")
async def api_create_preview(user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    try:
        return await asyncio.to_thread(create_preview)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/preview/{preview_id}/apply")
async def api_apply_preview(preview_id: str, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    try:
        res = await asyncio.to_thread(apply_preview, preview_id)
        return {"ok": True, **res}
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/rebuild")
async def manual_rebuild(request: Request, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    asyncio.create_task(asyncio.to_thread(rebuild_all, True, True))
    if "application/json" in request.headers.get("accept", ""):
        return {"ok": True, "message": "Запущено обновление маршрутов"}
    return RedirectResponse(url="/", status_code=303)


@app.get("/api/export/mikrotik.rsc")
async def api_export_mikrotik(list_name: str = Query("autobgpfeed"), user: dict = Depends(require_user)):
    try:
        script = await asyncio.to_thread(export_mikrotik_rsc, list_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    clean_file = f"{list_name.strip()}.rsc"
    return PlainTextResponse(
        script,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{clean_file}"'},
    )


@app.get("/api/backup/export")
async def api_backup_export(user: dict = Depends(require_admin)):
    data = await asyncio.to_thread(export_config_backup)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="autobgpfeed-backup-{ts}.json"'},
    )


@app.post("/api/backup/import")
async def api_backup_import(file: UploadFile = File(...), user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    raw_bytes = await file.read()
    if len(raw_bytes) > 5 * 1024 * 1024:
        return JSONResponse({"error": "Файл конфигурации слишком большой (> 5 МБ)"}, status_code=400)
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
        await asyncio.to_thread(import_config_backup, payload)
    except Exception as exc:
        return JSONResponse({"error": f"Ошибка импорта: {exc}"}, status_code=400)
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, True))
    return {"ok": True, "message": "Конфигурация импортирована, запущена пересборка маршрутов."}


@app.get("/api/revisions")
async def api_revisions(user: dict = Depends(require_user)):
    return {"revisions": await asyncio.to_thread(list_revisions)}


@app.post("/api/revisions/{rev_id}/restore")
async def api_restore_revision(rev_id: int, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    try:
        await asyncio.to_thread(restore_revision, rev_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, True))
    return RedirectResponse(url="/#settings", status_code=303)


@app.post("/api/settings/update")
async def api_update_settings(
    min_prefix_length: int = Form(8),
    allow_broad_routes: str = Form("0"),
    update_interval_sec: int = Form(900),
    dns_resolvers: str = Form("1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222"),
    dns_cache_ttl_sec: int = Form(86400),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    updates = {
        "min_prefix_length": str(max(1, min(32, int(min_prefix_length)))),
        "allow_broad_routes": "1" if allow_broad_routes == "1" else "0",
        "update_interval_sec": str(max(60, min(86400, int(update_interval_sec)))),
        "dns_resolvers": dns_resolvers.strip() or "1.1.1.1,8.8.8.8",
        "dns_cache_ttl_sec": str(max(60, min(604800, int(dns_cache_ttl_sec)))),
    }
    await asyncio.to_thread(set_settings, updates)
    log_msg(f"Пользователь {user['username']} обновил настройки генератора", "INFO")
    asyncio.create_task(asyncio.to_thread(rebuild_all, False, False))
    return RedirectResponse(url="/#settings", status_code=303)


@app.post("/api/vpn-profiles/add")
async def api_add_vpn_profile(
    label: str = Form(...),
    name: str = Form(...),
    community: str = Form(...),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    gw_clean = re.sub(r"[^A-Za-z0-9_.-]", "", name.strip())
    comm_clean = community.strip()
    label_clean = label.strip() or gw_clean
    if not gw_clean:
        raise HTTPException(status_code=400, detail="Укажите корректное имя интерфейса (латиница, цифры, _ . -)")
    if not re.fullmatch(r"\d+:\d+", comm_clean):
        raise HTTPException(status_code=400, detail="Community должно быть в формате ASN:ID (например 65000:104)")

    def _save():
        settings = get_settings()
        try:
            profiles = json.loads(settings.get("vpn_profiles") or "[]")
            if not isinstance(profiles, list):
                profiles = list(DEFAULT_VPN_PROFILES)
        except Exception:
            profiles = list(DEFAULT_VPN_PROFILES)
        profiles = [p for p in profiles if p.get("community") != comm_clean]
        profiles.append({"name": gw_clean, "community": comm_clean, "label": label_clean})
        set_settings({"vpn_profiles": json.dumps(profiles, ensure_ascii=False)})

    await asyncio.to_thread(_save)
    log_msg(f"Пользователь {user['username']} добавил VPN-профиль: {label_clean} ({gw_clean} / {comm_clean})", "INFO")
    return RedirectResponse(url="/#settings", status_code=303)


@app.post("/api/vpn-profiles/delete")
async def api_delete_vpn_profile(
    community: str = Form(...),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    comm_clean = community.strip()
    primary_comm = f"{get_server_asn()}:1000"
    if comm_clean == primary_comm:
        return RedirectResponse(url="/#settings", status_code=303)

    def _remove():
        settings = get_settings()
        try:
            profiles = json.loads(settings.get("vpn_profiles") or "[]")
        except Exception:
            return
        if not isinstance(profiles, list) or len(profiles) <= 1:
            return
        updated = [p for p in profiles if p.get("community") != comm_clean]
        if updated:
            set_settings({"vpn_profiles": json.dumps(updated, ensure_ascii=False)})

    await asyncio.to_thread(_remove)
    log_msg(f"Пользователь {user['username']} удалил VPN-профиль ({comm_clean})", "INFO")
    return RedirectResponse(url="/#settings", status_code=303)


# ----------------- User Management Endpoints -----------------


@app.post("/api/users/add")
async def add_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("admin"),
    user: dict = Depends(verify_csrf),
):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Только администраторы могут создавать пользователей")
    u_clean = username.strip()
    r_clean = role.strip() if role.strip() in ("admin", "viewer") else "viewer"
    if not u_clean or len(password) < 6:
        return RedirectResponse(url="/#settings", status_code=303)

    def _create():
        conn = get_db()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (u_clean, hash_password(password), r_clean),
                )
            log_msg(f"Администратор {user['username']} создал учетную запись «{u_clean}» (роль: {r_clean})", "INFO")
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()

    await asyncio.to_thread(_create)
    return RedirectResponse(url="/#settings", status_code=303)


@app.post("/api/users/{user_id}/delete")
async def delete_user(user_id: int, user: dict = Depends(verify_csrf)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Только администраторы могут удалять пользователей")
    if user_id == user.get("id"):
        return RedirectResponse(url="/#settings", status_code=303)

    def _remove():
        conn = get_db()
        try:
            with conn:
                target = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
                if target:
                    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                    log_msg(f"Администратор {user['username']} удалил пользователя «{target['username']}» (ID {user_id})", "INFO")
        finally:
            conn.close()

    await asyncio.to_thread(_remove)
    return RedirectResponse(url="/#settings", status_code=303)


@app.post("/api/users/change-password")
async def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(verify_csrf),
):
    if new_password != confirm_password:
        return JSONResponse({"status": "error", "message": "Новые пароли не совпадают!"}, status_code=400)
    if len(new_password) < 8:
        return JSONResponse({"status": "error", "message": "Пароль должен содержать минимум 8 символов!"}, status_code=400)

    def _update_pw():
        conn = get_db()
        try:
            db_user = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not db_user or not verify_password(old_password, db_user["password_hash"]):
                return False
            with conn:
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["id"]))
            return True
        finally:
            conn.close()

    ok = await asyncio.to_thread(_update_pw)
    if not ok:
        return JSONResponse({"status": "error", "message": "Неверный текущий пароль!"}, status_code=400)

    log_msg(f"Пользователь «{user['username']}» успешно изменил свой пароль", "SUCCESS")
    return JSONResponse({"status": "ok", "message": "Пароль успешно изменён! Используйте новый пароль при следующем входе."})
