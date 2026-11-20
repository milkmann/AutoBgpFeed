"""Comprehensive unit and API integration tests for AutoBgpFeed v2."""

import ipaddress
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import auth, bird_client, db, engine, main


@pytest.fixture()
def isolated_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    gen_dir = tmp_path / "generated"
    tpl_dir = Path(__file__).resolve().parents[1] / "templates"
    data_dir.mkdir(parents=True, exist_ok=True)
    gen_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("GENERATED_DIR", str(gen_dir))
    monkeypatch.setenv("TEMPLATES_DIR", str(tpl_dir))
    monkeypatch.setenv("SERVER_IP", "198.51.100.10")
    monkeypatch.setenv("SERVER_ASN", "65000")
    monkeypatch.setenv("ADMIN_USER", "testadmin")
    monkeypatch.setenv("ADMIN_PASS", "StrongPass123!")
    monkeypatch.setenv("SESSION_SECRET", "0123456789abcdef" * 4)
    monkeypatch.setenv("MIN_PREFIX_LENGTH", "8")

    main.templates.env.loader.searchpath = [str(tpl_dir)]
    auth.login_limiter.reset()
    db.init_db()
    return data_dir, gen_dir


def test_subtract_networks():
    base = [ipaddress.IPv4Network("198.51.100.0/22")]
    excl = [ipaddress.IPv4Network("198.51.101.0/24"), ipaddress.IPv4Network("198.51.100.10/32")]
    res = engine.subtract_networks(base, excl)
    assert ipaddress.IPv4Network("198.51.101.0/24") not in res
    assert all(ipaddress.IPv4Address("198.51.100.10") not in net for net in res)
    assert any(ipaddress.IPv4Address("198.51.102.1") in net for net in res)


def test_is_valid_ipv4_net_guards(isolated_env):
    assert engine.is_valid_ipv4_net("0.0.0.0/0") is None
    assert engine.is_valid_ipv4_net("1.0.0.0/7") is None  # Broad guard (< /8)
    assert engine.is_valid_ipv4_net("192.168.1.0/24") is None
    assert engine.is_valid_ipv4_net("10.0.0.0/8") is None
    assert engine.is_valid_ipv4_net("100.64.0.0/10") is None
    assert engine.is_valid_ipv4_net("127.0.0.1/32") is None
    assert engine.is_valid_ipv4_net("198.51.100.10/32") is None  # SERVER_IP rejected
    assert str(engine.is_valid_ipv4_net("1.1.1.0/24")) == "1.1.1.0/24"


def test_validate_external_url_ssrf(isolated_env):
    for bad in [
        "file:///etc/passwd",
        "ftp://example.com/list.txt",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/list.txt",
        "http://localhost:8080/healthz",
    ]:
        with pytest.raises(ValueError):
            engine.validate_external_url(bad)

    with patch.object(engine, "_resolve_host_ips", return_value=[ipaddress.IPv4Address("127.0.0.1")]):
        with pytest.raises(ValueError):
            engine.validate_external_url("https://rebind.example.com/list.txt")

    with patch.object(engine, "_resolve_host_ips", return_value=[ipaddress.IPv4Address("93.184.216.34")]):
        assert engine.validate_external_url("https://example.com/list.txt") == "https://example.com/list.txt"


def test_parse_delegated_stats_non_power_of_two():
    sample = "\n".join([
        "ripencc|RU|ipv4|195.0.0.0|768|20200101|allocated",
        "ripencc|DE|ipv4|194.0.0.0|256|20200101|allocated",
    ])
    nets = engine.parse_delegated_stats(sample, "RU")
    assert [str(n) for n in nets] == ["195.0.0.0/23", "195.0.2.0/24"]


def test_google_non_cloud(isolated_env):
    goog_json = json.dumps({"prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv4Prefix": "34.10.0.0/16"}]})
    cloud_json = json.dumps({"prefixes": [{"ipv4Prefix": "34.10.0.0/16"}]})

    def fake_get(url, **kwargs):
        return goog_json if "goog.json" in url else cloud_json

    with patch.object(engine, "_safe_http_get_text", side_effect=fake_get):
        res = engine.fetch_google_non_cloud()
    assert res == ["8.8.8.0/24"]


def test_build_merge_exclusions_noop_and_rollback(isolated_env):
    data_dir, gen_dir = isolated_env
    conn = db.get_db()
    with conn:
        conn.execute("DELETE FROM sources")
        conn.execute(
            "INSERT INTO sources (name, type, value, enabled, community, gateway) VALUES ('RU', 'COUNTRY', 'RU', 1, '65000:643', 'wireguard1')"
        )
        conn.execute(
            "INSERT INTO sources (name, type, value, enabled, community, gateway) VALUES ('Custom', 'PREFIX', '195.0.0.0/24', 1, '65000:102', 'wireguard2warp')"
        )
        conn.execute("INSERT INTO exclusions (name, type, value, enabled) VALUES ('ExcludeHost', 'PREFIX', '195.0.0.55/32', 1)")
    conn.close()

    # Seed RU last-good file
    ru_cache = data_dir / "last-good" / "ru_prefixes.txt"
    ru_cache.parent.mkdir(parents=True, exist_ok=True)
    ru_cache.write_text("195.0.0.0/24\n91.0.0.0/24\n", encoding="utf-8")

    with patch.object(engine, "bird_configure", return_value="0003 Reconfigured") as mock_cfg, \
         patch.object(engine, "bird_route_count", side_effect=[0, 10]):
        snap = engine.build_candidate_snapshot(force_download=False)
        # 195.0.0.55/32 must be subtracted from BOTH RU and Custom!
        assert all(ipaddress.IPv4Address("195.0.0.55") not in ipaddress.IPv4Network(p) for p in snap["prefixes"])
        # No duplicate exact route lines in routes.conf
        route_lines = [l for l in snap["routes_conf_text"].splitlines() if l.startswith("route ")]
        assert len(route_lines) == len(set(l.split()[1] for l in route_lines))
        # Merged communities on shared prefixes include both 643, 102, 1000
        assert "(65000, 102)" in snap["routes_conf_text"]
        assert "(65000, 643)" in snap["routes_conf_text"]

        res1 = engine.apply_snapshot(snap)
        assert res1["changed"] is True
        assert mock_cfg.call_count == 1

        # No-op check when count matches live BIRD
        with patch.object(engine, "bird_route_count", return_value=len(snap["prefixes"])):
            res2 = engine.apply_snapshot(snap)
            assert res2["changed"] is False
            assert mock_cfg.call_count == 1  # BIRD not reloaded unnecessarily

    # Provenance check on excluded IP vs included IP
    chk_excl = engine.check_ip_in_feed("195.0.0.55")
    assert chk_excl["found"] is False
    assert chk_excl["decision"] == "excluded"
    assert len(chk_excl["exclusions"]) == 1

    chk_incl = engine.check_ip_in_feed("91.0.0.1")
    assert chk_incl["found"] is True
    assert chk_incl["decision"] == "included"
    assert chk_incl["sources"][0]["community"] == "65000:643"

    # Export .rsc validation
    rsc = engine.export_mikrotik_rsc("my_feed")
    assert 'list="my_feed"' in rsc
    assert "91.0.0.0/24" in rsc
    with pytest.raises(ValueError):
        engine.export_mikrotik_rsc("bad list!")

    # Rollback test when BIRD rejects next config
    good_text = (gen_dir / "routes.conf").read_text(encoding="utf-8")
    bad_snap = dict(snap)
    bad_snap["routes_conf_text"] = "broken bird syntax;\n"
    bad_snap["routes_sha256"] = "deadbeef"
    bad_snap["prefixes"] = ["8.8.4.4/32"]

    calls = {"n": 0}

    def fail_first_cfg():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("syntax error")
        return "0003 Reconfigured"

    with patch.object(engine, "bird_configure", side_effect=fail_first_cfg):
        with pytest.raises(RuntimeError):
            engine.apply_snapshot(bad_snap, force_reload=True)
    # File rolled back to last-good!
    assert (gen_dir / "routes.conf").read_text(encoding="utf-8") == good_text


def test_bird_parse_protocols_all():
    lines = [
        "Name       Proto      Table      State  Since         Info",
        "device1    Device     ---        up     2026-11-20    ",
        "",
        "public_clients BGP    ---        start  2026-11-20    Passive",
        "  BGP state:          Passive",
        "",
        "client_1   BGP        ---        up     2026-11-20    Established",
        "  BGP state:          Established",
        "    Neighbor address: 198.51.100.10",
        "    Neighbor AS:      64999",
        "    Local AS:         65000",
        "    Neighbor ID:      192.168.120.1",
        "    Hold timer:       150.1/180",
        "    Keepalive timer:  40.2/60",
        "  Channel ipv4",
        "    Routes:         0 imported, 8683 exported, 0 preferred",
        "      Export updates:          8683          0          0        ---       8683",
        "      Export withdraws:            0        ---        ---        ---          0",
        "",
    ]
    peers = bird_client.parse_protocols_all(lines)
    assert len(peers) == 1
    assert peers[0]["name"] == "client_1"
    assert peers[0]["ip"] == "198.51.100.10"
    assert peers[0]["remote_as"] == 64999
    assert peers[0]["exported_routes"] == 8683
    assert peers[0]["updates_sent"] == 8683


def test_api_auth_csrf_rbac_ratelimit_and_backup(isolated_env):
    # Create viewer user and change admin password so ADMIN_PASS env != DB hash
    conn = db.get_db()
    with conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("viewer1", db.hash_password("ViewerPass123"), "viewer"),
        )
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = 'testadmin'",
            (db.hash_password("RotatedPass999!"),),
        )
    conn.close()

    with patch.object(main, "_initial_build_task", return_value=None), \
         patch.object(main, "bird_status", return_value={"up": True, "version": "2.15.1", "router_id": "198.51.100.10"}), \
         patch.object(main, "bird_route_count", return_value=10), \
         patch.object(main, "bird_peers", return_value=[]):
        client = TestClient(main.app)

        # Public healthz/metrics work without auth
        hz = client.get("/healthz")
        assert hz.status_code == 200
        assert hz.json()["ok"] is True
        assert client.get("/metrics").status_code == 200

        # Unauthenticated API blocked
        assert client.get("/api/telemetry").status_code == 401
        assert client.get("/", follow_redirects=False).status_code == 303

        # Old .env ADMIN_PASS must NOT bypass DB password!
        bad_env = client.post("/login", data={"username": "testadmin", "password": "StrongPass123!"}, follow_redirects=False)
        assert bad_env.status_code == 401

        # Rate limiter locks out on 5th failed attempt
        for _ in range(3):
            r = client.post("/login", data={"username": "testadmin", "password": "wrong"}, follow_redirects=False)
            assert r.status_code == 401
        r5 = client.post("/login", data={"username": "testadmin", "password": "wrong"}, follow_redirects=False)
        assert r5.status_code == 429

        # Reset limiter for viewer test
        auth.login_limiter.reset()

        # Viewer login -> allowed read, denied mutations (403)
        rv = client.post("/login", data={"username": "viewer1", "password": "ViewerPass123"}, follow_redirects=False)
        assert rv.status_code == 303
        assert client.get("/api/telemetry").status_code == 200
        v_payload = auth.decode_session_token(client.cookies.get(auth.SESSION_COOKIE_NAME))
        assert client.post(
            "/api/sources/add",
            data={"name": "x", "source_type": "PREFIX", "value": "1.1.1.0/24", "csrf_token": v_payload["csrf"]},
            follow_redirects=False,
        ).status_code == 403
        assert client.get("/api/backup/export").status_code == 403

        # Admin login -> CSRF check + backup roundtrip
        ra = client.post("/login", data={"username": "testadmin", "password": "RotatedPass999!"}, follow_redirects=False)
        assert ra.status_code == 303
        a_payload = auth.decode_session_token(client.cookies.get(auth.SESSION_COOKIE_NAME))
        csrf = a_payload["csrf"]

        # POST without CSRF -> 403
        assert client.post("/api/rebuild", follow_redirects=False).status_code == 403

        # POST Form with CSRF -> 303
        with patch.object(engine, "rebuild_all", return_value=1):
            r_add = client.post(
                "/api/sources/add",
                data={
                    "name": "MyNet",
                    "source_type": "PREFIX",
                    "value": "8.8.4.0/24",
                    "gateway": "wireguard2warp",
                    "community": "65000:102",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert r_add.status_code == 303

        # Backup export excludes password hashes and imports cleanly via UploadFile + X-CSRF-Token
        bk = client.get("/api/backup/export")
        assert bk.status_code == 200
        bk_json = bk.json()
        assert "users" not in bk_json
        assert any(s["value"] == "8.8.4.0/24" for s in bk_json["sources"])

        with patch.object(engine, "rebuild_all", return_value=1):
            imp = client.post(
                "/api/backup/import",
                headers={"X-CSRF-Token": csrf},
                files={"file": ("backup.json", json.dumps(bk_json).encode("utf-8"), "application/json")},
            )
            assert imp.status_code == 200
            assert imp.json()["ok"] is True
