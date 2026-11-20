"""SQLite persistence, schema migrations, password hashing, and settings helpers."""

import hashlib
import json
import os
import secrets
import sqlite3

DEFAULT_VPN_PROFILES = [
    {"name": "wireguard1", "community": "65000:1000", "label": "Primary VPN (wireguard1)"},
    {"name": "wireguard2warp", "community": "65000:102", "label": "WARP (wireguard2warp)"},
    {"name": "wireguard5warpzero", "community": "65000:103", "label": "WARP Zero (wireguard5warpzero)"},
]

DEFAULT_SETTINGS = {
    "default_gateway": "wireguard1",
    "min_prefix_length": "8",
    "allow_broad_routes": "0",
    "update_interval_sec": "900",
    "dns_resolvers": "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222",
    "dns_cache_ttl_sec": "86400",
    "vpn_profiles": json.dumps(DEFAULT_VPN_PROFILES),
}


def get_data_dir() -> str:
    return os.environ.get("DATA_DIR", "/data")


def get_db_path() -> str:
    return os.path.join(get_data_dir(), "routefeed.db")


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000)
    return f"pbkdf2_sha256$100000${salt}${key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash or not stored_hash.startswith("pbkdf2_sha256$"):
            return False
        parts = stored_hash.split("$")
        if len(parts) != 4:
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        target_key = parts[3]
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(key.hex(), target_key)
    except Exception:
        return False


def get_db() -> sqlite3.Connection:
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def _ensure_column(cursor: sqlite3.Cursor, table: str, column: str, definition: str) -> None:
    cols = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    conn = get_db()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    mode TEXT DEFAULT 'default',
                    enabled INTEGER DEFAULT 1,
                    auto_update INTEGER DEFAULT 1,
                    community TEXT DEFAULT '65000:1000',
                    prefix_count INTEGER DEFAULT 0,
                    last_update TEXT,
                    status TEXT DEFAULT 'pending',
                    error TEXT,
                    gateway TEXT DEFAULT 'wireguard1',
                    cdn_mode TEXT DEFAULT 'auto',
                    cached_at TEXT,
                    degraded INTEGER DEFAULT 0
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS exclusions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL DEFAULT 'PREFIX',
                    value TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    level TEXT DEFAULT 'INFO',
                    message TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY,
                    last_gen_time TEXT,
                    gen_duration TEXT,
                    raw_count INTEGER DEFAULT 0,
                    custom_count INTEGER DEFAULT 0,
                    pre_filter_count INTEGER DEFAULT 0,
                    post_filter_count INTEGER DEFAULT 0,
                    final_count INTEGER DEFAULT 0,
                    exclusions_applied INTEGER DEFAULT 0,
                    collapsed_duplicates INTEGER DEFAULT 0,
                    degraded INTEGER DEFAULT 0,
                    degraded_reason TEXT DEFAULT '',
                    routes_sha256 TEXT DEFAULT '',
                    last_apply_time TEXT DEFAULT '—'
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'admin',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS routes_index (
                    prefix TEXT PRIMARY KEY,
                    addresses_count INTEGER,
                    addresses_formatted TEXT,
                    category TEXT,
                    community TEXT,
                    source_name TEXT,
                    date_added TEXT,
                    gateway TEXT DEFAULT 'wireguard1',
                    is_custom INTEGER DEFAULT 0
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS revisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    action TEXT NOT NULL,
                    details TEXT,
                    routes_count INTEGER DEFAULT 0,
                    config_json TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_cache (
                    domain TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    last_seen INTEGER NOT NULL,
                    PRIMARY KEY (domain, ip)
                )
                """
            )

            # Safe migrations for pre-existing v1 databases
            _ensure_column(cursor, "sources", "gateway", "TEXT DEFAULT 'wireguard1'")
            _ensure_column(cursor, "sources", "cdn_mode", "TEXT DEFAULT 'auto'")
            _ensure_column(cursor, "sources", "cached_at", "TEXT")
            _ensure_column(cursor, "sources", "degraded", "INTEGER DEFAULT 0")

            _ensure_column(cursor, "stats", "degraded", "INTEGER DEFAULT 0")
            _ensure_column(cursor, "stats", "degraded_reason", "TEXT DEFAULT ''")
            _ensure_column(cursor, "stats", "routes_sha256", "TEXT DEFAULT ''")
            _ensure_column(cursor, "stats", "last_apply_time", "TEXT DEFAULT '—'")

            _ensure_column(cursor, "revisions", "config_json", "TEXT")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_routes_category ON routes_index(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_routes_addresses ON routes_index(addresses_count)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_routes_date ON routes_index(date_added)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_routes_custom ON routes_index(is_custom)")

            # Seed default RU source only if sources table is completely empty
            cursor.execute("SELECT COUNT(*) FROM sources")
            if cursor.fetchone()[0] == 0:
                asn = os.environ.get("SERVER_ASN", "65000")
                cursor.execute(
                    """
                    INSERT INTO sources (name, type, value, mode, enabled, auto_update, community, status, gateway, cdn_mode)
                    VALUES ('Russian IPv4 Subnets (RIPE & IPverse)', 'COUNTRY', 'RU', 'aggregated', 1, 1, ?, 'pending', 'wireguard1', 'auto')
                    """,
                    (f"{asn}:643",),
                )

            cursor.execute("SELECT COUNT(*) FROM stats WHERE id = 1")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO stats (id, last_gen_time, gen_duration, final_count) VALUES (1, '—', '—', 0)"
                )

            for key, val in DEFAULT_SETTINGS.items():
                cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))

            # Seed initial admin user ONLY if users table is empty (never re-seed hardcoded defaults)
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                admin_user = os.environ.get("ADMIN_USER", "admin").strip() or "admin"
                admin_pass = os.environ.get("ADMIN_PASS", "").strip()
                if not admin_pass:
                    admin_pass = secrets.token_urlsafe(15)
                    print(f"[INIT] Generated initial admin password for '{admin_user}': {admin_pass}")
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                    (admin_user, hash_password(admin_pass)),
                )
    finally:
        conn.close()


def reset_user_password(username: str, new_password: str) -> bool:
    conn = get_db()
    try:
        with conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            return cur.rowcount > 0
    finally:
        conn.close()


def get_settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    own = conn is None
    if own:
        conn = get_db()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        merged = dict(DEFAULT_SETTINGS)
        for r in rows:
            merged[r["key"]] = r["value"]
        return merged
    finally:
        if own:
            conn.close()


def set_settings(updates: dict[str, str], conn: sqlite3.Connection | None = None) -> None:
    own = conn is None
    if own:
        conn = get_db()
    try:
        with conn:
            for k, v in updates.items():
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (str(k), str(v)))
    finally:
        if own:
            conn.close()
