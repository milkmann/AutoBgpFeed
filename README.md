# ⚡ Auto BGP Feed v2

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/BIRD_2-Pure_Dynamic_BGP-FF6B6B?style=for-the-badge" />
  <img src="https://img.shields.io/badge/FastAPI-Hardened_Web_UI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/RouterOS_7_%26_6-Compatible-00D2FF?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Cloudflare_Tunnel-Ready-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" />
</p>

<p align="center">
  <b><a href="#русский">Документация на русском</a></b> | <b><a href="#english">English Documentation</a></b>
</p>

---

<a name="русский"></a>
## 🇷🇺 Документация на русском

**Auto BGP Feed v2** — лёгкий, безопасный и автономный BGP-шлюз с веб-панелью управления маршрутами для выборочной маршрутизации трафика через VPN (**MikroTik RouterOS 7 / 6**, **Keenetic**, **OpenWrt**, **VyOS / EdgeOS**, **Cisco IOS**).

Система разделяет трафик на «прямой» и «через VPN»: локальные банки, госсервисы и домашние сети работают на максимальной скорости напрямую через провайдера, а нужные страны, домены, ASN и списки адресов автоматически анонсируются вашему роутеру по BGP и направляются в выбранный VPN-туннель.

> 💡 *Идея проекта вдохновлена [LeonidOz/BGP-Antifilter](https://github.com/LeonidOz/BGP-Antifilter) и переработана в двухконтейнерную архитектуру на чистом **BIRD 2 Dynamic BGP** (~95 МБ RAM на весь стек) с поддержкой динамических IP клиентов (Dual WAN / CGNAT), мульти-VPN через BGP communities, локальным Smart-DNS и усиленной безопасностью веб-интерфейса.*

---

### 🏗️ Архитектура v2 (Pure BIRD 2)

```text
  [ Источники: Страны (RIPE/RIR), Домены (Smart-DNS), URL-списки, ASN, Google ]
                                       │
                                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  source-manager (FastAPI + SQLite + APScheduler-loop)                      │
│  • Вычитание исключений (address_exclude) из ВСЕХ источников               │
│  • Защита от широких масок (/0–/7) и SSRF                                  │
│  • Предпросмотр Diff • Ревизии • Бэкапы • /healthz /status.json /metrics  │
└──────────────┬───────────────────────────────────────────────┬─────────────┘
               │ routes.conf + birdc configure                 │
               │ (Unix-сокет /run/bird/bird.ctl, без docker.sock)
               ▼                                               ▼
┌──────────────────────────────┐                ┌────────────────────────────┐
│  bgp-core (BIRD 2.15+)       │                │  Web UI (127.0.0.1:8080)   │
│  • Dynamic BGP range 0.0.0.0/0│               │  • Cloudflare Tunnel / WAF │
│  • Автоочистка «зомби»-пиров │                │  • Cookie + CSRF + RBAC    │
└──────────────┬───────────────┘                └────────────────────────────┘
               │ BGP TCP/179 (+ BGP Communities 65000:1000 / 102 / 103)
               ▼
      [ Роутер: MikroTik / Keenetic / OpenWrt ]
        ├── 65000:1000 ──▶ Основной VPN (wireguard1)
        ├── 65000:102  ──▶ Запасной / WARP (wireguard2warp)
        └── 65000:103  ──▶ Дополнительный VPN (wireguard5warpzero)
```

---

### 🌟 Почему v2 лучше классических BGP-фидов и v1

| Возможность | Классические фиды / v1 | **Auto BGP Feed v2** |
| :--- | :--- | :--- |
| **BGP-ядро** | Тяжёлый FRR (`public-bgp` с `privileged`) + BIRD | **Чистый BIRD 2 Dynamic BGP (`0.0.0.0/0`)** — без FRR, без ошибок *Enhanced Route Refresh* в RouterOS 7 |
| **Клиентские IP** | Нужен статический белый IP роутера | **Любой динамический IP / Dual WAN / NAT** + автоочистка зависших `Passive`-пиров от сканеров |
| **Управление BIRD** | `docker exec` через проброс `/var/run/docker.sock` | **Безопасный Unix-сокет** `/run/bird/bird.ctl` — у веб-панели нет доступа к Docker хоста |
| **Веб-доступ** | Открытый порт на `0.0.0.0` и CDN-скрипты | **Локальный bind `127.0.0.1`** (под Cloudflare Tunnel/Proxy), **HttpOnly + CSRF + Rate-Limit + RBAC**, ассеты локально |
| **Исключения** | Только поверх кастомных списков или неполные | **Точное вычитание CIDR (`address_exclude`)** из **всех** источников (включая целые страны), по IP и доменам |
| **Отказоустойчивость** | Перезапись конфига вслепую; сбой источника = пустая таблица | **Атомарный откат** на `routes.last-good.conf`, персистентный **кеш источников (`degraded`-режим)**, защита от `0` маршрутов |
| **Износ SSD и CPU** | Перезагрузка демона и SQLite каждые 15 мин | **SHA-256 контроль:** если маршруты не изменились — 0 записей в БД и 0 перезагрузок BIRD |
| **Cloudflare / CDN** | Резолвит 1 IP, сайт отваливается через 5 мин | **Smart-DNS с TTL-кешем ротации** + умное `/24` расширение для Anycast CDN (Cloudflare / Fastly) |
| **Источники** | Ручное редактирование текстовых файлов | `COUNTRY` (с 5-RIR fallback), `DOMAIN`, `DOMAIN_LIST_URL`, `ASN`, `PREFIX`, `EXTERNAL_URL`, **`GOOGLE` (без Cloud)**, **Bulk-импорт и редактирование** |
| **Контроль изменений** | Применяется «вслепую» | **Предпросмотр Diff (`+добавится / -удалится`)**, **Provenance** (почему IP в фиде или исключён), **30 ревизий** с откатом и **JSON бэкап** |
| **Наблюдаемость** | Логи контейнера | **`/healthz`, `/status.json`, `/metrics` (Prometheus)**, тихие access-логи (без спама healthcheck), совместимость с Home Assistant и Uptime Kuma |

---

### 🚀 Быстрая установка

#### Системные требования
- Любой Linux VPS (**1 vCPU / 512 MB RAM**, Ubuntu 22.04/24.04, Debian 11/12 или Alpine) с Docker Engine и Compose v2.
- **Порт `179/TCP`** открыт на фаерволе для BGP-сессий от ваших роутеров.
- **Веб-панель (по умолчанию `127.0.0.1:8080`)** — рекомендуется открывать **только** через Cloudflare Tunnel, Nginx/Caddy с HTTPS или WireGuard/VPN (не открывать голый HTTP наружу).

#### Вариант 1: Автоматический установщик в 1 команду

```bash
curl -sSL https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/install.sh | bash
```

Скрипт установит Docker (если нужно), создаст `.env` со случайным `SESSION_SECRET` и паролем администратора, соберёт `bgp-core` + `source-manager`, запустит стек и выведет готовые безопасные правила для MikroTik.

#### Вариант 2: Ручная установка через Docker Compose

```bash
git clone https://github.com/milkmann/AutoBgpFeed.git /opt/AutoBgpFeed
cd /opt/AutoBgpFeed
cp .env.example .env
nano .env   # Укажите SERVER_IP, ADMIN_USER, ADMIN_PASS, WEB_BIND/WEB_PORT
mkdir -p data bgp-core/generated
docker compose up -d --build
```

---

### ⚙️ Параметры `.env`

| Переменная | По умолчанию | Назначение |
| :--- | :--- | :--- |
| `SERVER_IP` | `YOUR_SERVER_IP` | Публичный IP вашего VPS (используется как `router id` в BIRD и подсказка для роутеров) |
| `SERVER_ASN` | `65000` | Номер автономной системы BGP-сервера |
| `BGP_PORT` | `179` | Внешний TCP-порт для BGP |
| `WEB_BIND` | `127.0.0.1` | На какой интерфейс биндить веб-панель (`127.0.0.1` за Cloudflare Tunnel/proxy или `0.0.0.0` в приватной сети) |
| `WEB_PORT` | `8080` | Порт веб-панели на хосте |
| `ADMIN_USER` | `admin` | Логин первого администратора (создаётся при пустой БД; далее смена пароля — в настройках панели) |
| `ADMIN_PASS` | *(пусто)* | Начальный пароль администратора; если оставить пустым, при первом старте сгенерируется случайный (см. `docker compose logs source-manager`) |
| `SESSION_SECRET` | *(пусто)* | Секрет подписи cookie-сессий (если пусто — автогенерируется в `/data/.session_secret`) |
| `MIN_PREFIX_LENGTH` | `8` | Защита от слишком широких масок: префиксы шире `/8` (`/0`–`/7`) автоматически отвергаются |
| `CACHE_MAX_AGE` | `604800` | Срок жизни резервного кеша источников в секундах (7 дней) для `degraded`-режима |
| `TRUST_PROXY_HEADERS` | `1` | Доверять `CF-Connecting-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` при работе за Cloudflare Tunnel или Nginx |

---

### 📖 Работа с веб-панелью

1. **Панель (Dashboard):** статистика активных маршрутов, живые BGP-пиры из BIRD 2 (`Established`, префиксы, аптайм, обновления), диаграмма масок подсетей, баннер `Degraded Mode` при сетевых сбоях и лог операций.
2. **База маршрутов (Route Explorer):** поиск по CIDR-префиксу, категории, источнику, community и целевому VPN-шлюзу; быстрые фильтры и сортировка по дате добавления.
3. **Списки и Smart Add:**
   - Типы источников: `COUNTRY` (`UA`, `RU`, `PL`...), `DOMAIN` (Smart-DNS с кешем ротации CDN), `DOMAIN_LIST_URL` (TXT-список доменов по URL, до 500 доменов с параллельным DNS-резолвом), `ASN` (`AS15169`...), `PREFIX` (CIDR), `EXTERNAL_URL` (TXT-список IP/подсетей по URL), `GOOGLE` (официальные диапазоны Google за вычетом Google Cloud).
   - **Массовое добавление (Bulk):** список записей построчно в формате `domain.com` или `Название | domain.com`.
   - **Редактирование (`✎`):** изменение типа, значения, VPN-профиля, community и режима CDN (`auto` / `exact` / `subnet24`) на лету с автосбросом кеша источника.
   - **Правила исключения (Exclusions):** IP/CIDR или домены (одиночно и списком), вычитаемые **из всех** источников.
4. **Инструменты и разведка:**
   - **Универсальный сетевой инспектор:** по домену, IP, ASN или стране сразу определяет провайдера, страну, принадлежность к Cloudflare/Fastly и позволяет в 1 клик добавить в источники.
   - **Provenance проверка IP:** точно объясняет, включён ли IP в текущий фид, какой источник и с какой community/VPN его добавил, или каким исключением он вырезан.
5. **Предпросмотр Diff и Настройки:** кнопка **«Предпросмотр (Diff)»** пересчитывает изменения без перезагрузки BIRD и показывает `+добавляемые / -удаляемые` префиксы; в настройках доступны экспорт `.rsc` для MikroTik (вместо BGP), JSON-бэкап/восстановление, откат к одной из последних 30 ревизий и управление пользователями (`admin` / `viewer`).

---

### 📡 Мониторинг (`/healthz`, `/status.json`, `/metrics`) и Home Assistant

Сервис предоставляет открытые read-only эндпоинты (только счётчики состояния, без конфигов и секретов):
- `GET /healthz` — HTTP `200`, если BIRD жив и маршруты загружены (иначе `503`), удобно для Docker / Uptime Kuma.
- `GET /status.json` — JSON со статусом `ok`, `bird_up`, `routes`, `peers_total`, `peers_established`, `degraded`, `degraded_reason`, `last_gen_time`.
- `GET /metrics` — метрики в формате **Prometheus** (`autobgp_bird_up`, `autobgp_routes_total`, `autobgp_peers_established`, `autobgp_degraded` и др.).

<details>
<summary><b>Пример мониторинга в Home Assistant (REST-сенсор + уведомления в Telegram без спама)</b></summary>

Добавьте REST-сенсор (`sensors.yaml`):
```yaml
- platform: rest
  name: "AutoBgpFeed Status"
  unique_id: autobgpfeed_status_rest
  resource: "https://bgp.example.com/status.json"
  scan_interval: 120
  timeout: 10
  value_template: >-
    {% if value_json is not defined or not value_json.ok %}
      error
    {% elif (value_json.peers_established | int(0)) < 1 %}
      no_peer
    {% elif value_json.degraded %}
      degraded
    {% else %}
      ok
    {% endif %}
  json_attributes:
    - ok
    - bird_up
    - routes
    - peers_total
    - peers_established
    - degraded
    - degraded_reason
    - last_gen_time
```
Далее подключите автоматизацию на срабатывание при `error` / `unavailable` / `no_peer` дольше **3 минут** (или `degraded` > **5 минут**) с подтверждённым восстановлением (`to: "ok"` `for: 3m`) через ваш `notify.telegram_*`.
</details>

---

### 🌐 Примеры безопасной конфигурации роутеров

Во все шаблоны встроена защита на стороне роутера: отклоняются `0.0.0.0/0`, маски шире `/8`, локальные/CGNAT сети (`RFC1918`, `100.64.0.0/10`) и IP самого BGP-сервера.

<details>
<summary><b>1. MikroTik RouterOS 7 (включая пример Мульти-VPN через BGP Communities)</b></summary>

```routeros
# 1. Защита от опасных маршрутов + маршрутизация по разным VPN-туннелям
/routing/filter/rule
add chain=discard disabled=no rule="reject;"
add chain=antifilter-in comment="AutoBgpFeed safety guard" disabled=no \
    rule="if (dst == 0.0.0.0/0 || dst-len < 8 || dst in 10.0.0.0/8 || dst in 172.16.0.0/12 || dst in 192.168.0.0/16 || dst in 100.64.0.0/10 || dst in YOUR_SERVER_IP/32) { reject; }"
# Опционально: дополнительные туннели (раскомментируйте/включите при необходимости)
add chain=antifilter-in comment="AutoBgpFeed WARP (optional)" disabled=yes \
    rule="if (bgp-communities includes 65000:102) { set gw wireguard2warp; accept; }"
add chain=antifilter-in comment="AutoBgpFeed WARP Zero (optional)" disabled=yes \
    rule="if (bgp-communities includes 65000:103) { set gw wireguard5warpzero; accept; }"
add chain=antifilter-in comment="AutoBgpFeed primary VPN" disabled=no \
    rule="if (bgp-communities includes 65000:1000) { set gw wireguard1; accept; } else { reject; }"

# 2. BGP-подключение (для RouterOS 7.20+ предварительно создайте /routing/bgp/instance)
/routing/bgp/connection
add name="bgp-feed" remote.address=YOUR_SERVER_IP remote.port=179 remote.as=65000 \
    as=64999 local.role=ebgp multihop=yes connect=yes listen=no \
    routing-table=main input.filter=antifilter-in input.limit-process-routes-ipv4=25000 output.filter-chain=discard
```
</details>

<details>
<summary><b>2. MikroTik RouterOS 6</b></summary>

```routeros
/routing filter add chain=antifilter-in prefix=0.0.0.0/0 action=reject
/routing filter add chain=antifilter-in prefix=10.0.0.0/8 prefix-length=8-32 action=reject
/routing filter add chain=antifilter-in prefix=172.16.0.0/12 prefix-length=12-32 action=reject
/routing filter add chain=antifilter-in prefix=192.168.0.0/16 prefix-length=16-32 action=reject
/routing filter add chain=antifilter-in bgp-communities=65000:1000 set-gateway=wireguard1 action=accept
/routing filter add chain=antifilter-in action=reject

/routing bgp instance set default as=64999
/routing bgp peer add name="bgp-feed" remote-address=YOUR_SERVER_IP remote-as=65000 \
    multihop=yes in-filter=antifilter-in out-filter=discard hold-time=3m
```
</details>

<details>
<summary><b>3. Keenetic (Entware / BIRD 2)</b></summary>

```bird
protocol bgp bgp_feed {
    local as 64999;
    neighbor YOUR_SERVER_IP as 65000;
    multihop;
    ipv4 {
        import filter {
            if net = 0.0.0.0/0 || net.len < 8 then reject;
            if (65000, 1000) ~ bgp_community then { gw = 10.0.0.1; accept; }
            reject;
        };
        export none;
    };
}
```
</details>

<details>
<summary><b>4. OpenWrt / Linux (BIRD 2)</b></summary>

```bird
protocol bgp bgp_feed {
    local as 64999;
    neighbor YOUR_SERVER_IP as 65000;
    multihop;
    ipv4 {
        import filter {
            if net = 0.0.0.0/0 || net.len < 8 then reject;
            if (65000, 1000) ~ bgp_community then { gw = 10.0.0.1; accept; }
            reject;
        };
        export none;
    };
}
```
</details>

<details>
<summary><b>5. VyOS / Ubiquiti EdgeOS</b></summary>

```bash
set policy route-map BGP-OUT-DISCARD rule 10 action reject
set policy route-map BGP-IN-VPN rule 10 match community 65000:1000
set policy route-map BGP-IN-VPN rule 10 set next-hop 10.0.0.1
set policy route-map BGP-IN-VPN rule 20 action reject
set protocols bgp system-as 64999
set protocols bgp neighbor YOUR_SERVER_IP remote-as 65000
set protocols bgp neighbor YOUR_SERVER_IP ebgp-multihop 10
set protocols bgp neighbor YOUR_SERVER_IP address-family ipv4-unicast route-map import BGP-IN-VPN
set protocols bgp neighbor YOUR_SERVER_IP address-family ipv4-unicast route-map export BGP-OUT-DISCARD
```
</details>

<details>
<summary><b>6. Cisco IOS / IOS-XE</b></summary>

```cisco
ip community-list standard CL-FEED permit 65000:1000
route-map BGP-IN-VPN permit 10
 match community CL-FEED
 set ip next-hop 10.0.0.1
route-map BGP-OUT-DISCARD deny 10
router bgp 64999
 neighbor YOUR_SERVER_IP remote-as 65000
 neighbor YOUR_SERVER_IP ebgp-multihop 10
 address-family ipv4
  neighbor YOUR_SERVER_IP activate
  neighbor YOUR_SERVER_IP route-map BGP-IN-VPN in
  neighbor YOUR_SERVER_IP route-map BGP-OUT-DISCARD out
 exit-address-family
```
</details>

---

### 🛠️ Полезные команды и тестирование

```bash
# Статус контейнеров и логов веб-панели
docker compose ps
docker compose logs -f --tail=50 source-manager

# Живые BGP-сессии и маршруты внутри BIRD 2
docker exec bgp-core birdc -s /run/bird/bird.ctl show protocols all
docker exec bgp-core birdc -s /run/bird/bird.ctl show route count

# Запуск встроенных unit/API-тестов (в изолированном контейнере без сети)
docker run --rm --network none auto-bgp-feed-source-manager pytest -v

# Обновление с GitHub
git pull && docker compose up -d --build
```

---

<a name="english"></a>
## 🌐 English Documentation

**Auto BGP Feed v2** is a lightweight, hardened BGP route feed server and web dashboard for selective VPN split-routing on **MikroTik RouterOS 7 / 6**, **Keenetic**, **OpenWrt**, **VyOS**, and **Cisco IOS**.

> 💡 *Inspired by [LeonidOz/BGP-Antifilter](https://github.com/LeonidOz/BGP-Antifilter) and re-engineered onto a pure **BIRD 2 Dynamic BGP** two-container stack (~95 MB total RAM) without FRR or `docker.sock` mounting.*

### Key Highlights
- **Pure BIRD 2 Dynamic BGP (`neighbor range 0.0.0.0/0 external`)**: supports clients behind dynamic IPs / Dual WAN / CGNAT, with automatic pruning of stale non-`Established` scanner peers.
- **No `docker.sock` & Hardened Web UI**: `source-manager` communicates directly via `/run/bird/bird.ctl`, binds to `127.0.0.1` by default (Cloudflare Tunnel / reverse-proxy ready), and enforces signed `HttpOnly`/`SameSite=Lax` sessions, CSRF protection, login rate-limiting, RBAC (`admin` / `viewer`), SSRF guards, and self-hosted Bootstrap/Chart.js assets.
- **Reliable Route Compilation**:
  - True CIDR subtraction (`address_exclude`) across **all** sources (including country feeds) with IP and domain exclusions.
  - `MIN_PREFIX_LENGTH=8` broad-prefix guard, atomic `routes.conf` writes, `birdc configure` verification, instant rollback to `routes.last-good.conf`, persistent fallback cache (`degraded` mode), and SHA-256 no-op skip.
  - Source types: `COUNTRY` (RIPEstat → IPverse → 5 RIR delegated stats), `DOMAIN` (Smart-DNS with rotating-CDN cache + Cloudflare/Fastly `/24` expansion), `DOMAIN_LIST_URL`, `ASN`, `PREFIX`, `EXTERNAL_URL`, and `GOOGLE` (non-Cloud).
- **Workflow & Observability**: Diff Preview before applying routes, Bulk add & inline editing, IP Provenance lookup, Multi-VPN routing via BGP communities (`65000:1000`, `65000:102`, `65000:103`), `.rsc` Address List export, revision history, JSON backup/restore, quiet access logs, and `/healthz`, `/status.json`, `/metrics` (Prometheus).

### Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/install.sh | bash
```

Or manually:

```bash
git clone https://github.com/milkmann/AutoBgpFeed.git /opt/AutoBgpFeed
cd /opt/AutoBgpFeed
cp .env.example .env
nano .env
mkdir -p data bgp-core/generated
docker compose up -d --build
```

See the Russian section above for full `.env` documentation, router filter templates (with safety guards against `0.0.0.0/0`, RFC1918, and server-IP loops), and Home Assistant / Prometheus monitoring examples.

---

## 📄 License / Лицензия

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
