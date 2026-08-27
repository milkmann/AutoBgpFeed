import sqlite3
import os

DB_PATH = os.environ.get("DATA_DIR", "/data") + "/routefeed.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            mode TEXT DEFAULT "default",
            enabled INTEGER DEFAULT 1,
            auto_update INTEGER DEFAULT 1,
            community TEXT DEFAULT "65000:1000",
            prefix_count INTEGER DEFAULT 0,
            last_update TEXT,
            status TEXT DEFAULT "pending",
            error TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exclusions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            level TEXT DEFAULT "INFO",
            message TEXT NOT NULL
        )
    """)
    cursor.execute("""
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
            collapsed_duplicates INTEGER DEFAULT 0
        )
    """)
    
    cursor.execute("SELECT COUNT(*) FROM sources WHERE type = \"COUNTRY\" AND value = \"RU\"")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO sources (name, type, value, mode, enabled, auto_update, community, status)
            VALUES ("Russian IPv4 Subnets (RIPE & IPverse)", "COUNTRY", "RU", "aggregated", 1, 1, "65000:643", "active")
        """)
        
    cursor.execute("SELECT COUNT(*) FROM stats WHERE id = 1")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO stats (id, last_gen_time, gen_duration, final_count) VALUES (1, ?, ?, 0)", ("—", "—"))

    conn.commit()
    conn.close()
