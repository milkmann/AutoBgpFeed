# ⚡ Auto BGP Feed v2

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/BIRD_2-Dynamic_BGP-FF6B6B?style=for-the-badge" />
  <img src="https://img.shields.io/badge/FastAPI-Secure_Web_UI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/RouterOS_7_%26_6-Compatible-00D2FF?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" />
</p>

**Auto BGP Feed v2** — лёгкий автоматизированный BGP-шлюз и панель управления маршрутами для выборочного VPN-роутинга (MikroTik RouterOS 7/6, Keenetic, OpenWrt, VyOS, Cisco IOS).

### Новое в v2
- **Чистый BIRD 2 Dynamic BGP (`neighbor range 0.0.0.0/0 external`)**: убран отдельный `privileged` FRR-контейнер (`public-bgp`), меньше памяти и нет ошибок Enhanced Route Refresh в RouterOS 7.
- **Прямое общение через Unix-сокет `/run/bird/bird.ctl`**: в веб-контейнере больше нет `/var/run/docker.sock`.
- **Безопасность веб-панели**: подписанные `HttpOnly`/`SameSite=Lax` cookie-сессии, защита от перебора паролей (rate-limit), CSRF-токены, строгий RBAC (`admin`/`viewer`), защита от XSS и SSRF, локальные UI-ассеты без внешних CDN.
- **Надёжность генерации**:
  - Настоящее вычитание подсетей (`address_exclude`) для **всех** источников (включая RU-пул), поддержка исключений по IP/CIDR и доменам.
  - Защита от широких масок (`MIN_PREFIX_LENGTH=8`), атомарная запись конфигов, проверка `birdc configure` и мгновенный откат на `routes.last-good.conf`.
  - Пропуск перезагрузки BIRD и записи в SQLite при неизменном SHA-256 маршрутов (нулевой износ SSD).
  - Персистентный кеш источников (`degraded`-режим при сбоях сети) и TTL-кеш DNS для стабильной работы с ротируемыми CDN.
- **Новые возможности**:
  - **Предпросмотр Diff** (`+added / -removed`) до применения в BIRD.
  - Источник **Google (без Google Cloud)** и fallback стран через все 5 RIR (`summarize_address_range`).
  - **Provenance** в проверке IP (показывает точные источники, community, VPN-шлюз и исключения).
  - Поддержка нескольких VPN-туннелей через BGP Communities (`65000:1000`, `65000:102`, `65000:103`).
  - Экспорт **MikroTik Address List `.rsc`**, JSON бэкап/импорт, история ревизий и эндпоинты `/healthz`, `/status.json`, `/metrics` (Prometheus).

---

## Быстрая установка

```bash
curl -sSL https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/install.sh | bash
```

Или вручную:

```bash
git clone https://github.com/milkmann/AutoBgpFeed.git /opt/AutoBgpFeed
cd /opt/AutoBgpFeed
cp .env.example .env
nano .env
docker compose up -d --build
```

## Безопасное подключение MikroTik (RouterOS 7)

```routeros
/routing/filter/rule
add chain=antifilter-in disabled=no rule="if (dst == 0.0.0.0/0 || dst-len < 8 || dst in 10.0.0.0/8 || dst in 172.16.0.0/12 || dst in 192.168.0.0/16 || dst in 100.64.0.0/10 || dst in YOUR_SERVER_IP/32) { reject; }"
add chain=antifilter-in disabled=no rule="if (bgp-communities includes 65000:1000) { set gw wireguard1; accept; } else { reject; }"
add chain=discard disabled=no rule="reject;"

/routing/bgp/connection
add name="bgp-feed" remote.address=YOUR_SERVER_IP remote.port=179 remote.as=65000 \
    as=64999 local.role=ebgp multihop=yes connect=yes listen=no \
    routing-table=main input.filter=antifilter-in input.limit-process-routes-ipv4=25000 output.filter-chain=discard
```

## Лицензия
Apache License 2.0 — см. [LICENSE](LICENSE).
