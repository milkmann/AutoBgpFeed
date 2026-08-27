# ⚡ Auto BGP Feed

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/BIRD_2-Routing_Engine-FF6B6B?style=for-the-badge" />
  <img src="https://img.shields.io/badge/FRRouting-Dynamic_BGP_Pool-4CAF50?style=for-the-badge" />
  <img src="https://img.shields.io/badge/FastAPI-Modern_Web_UI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/RouterOS_7-Compatible-00D2FF?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Keenetic-OpenWrt-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" />
</p>

Автоматизированный BGP-шлюз и генератор списков маршрутов для выборочной VPN-маршрутизации на любых роутерах (**MikroTik RouterOS 7/6**, Keenetic, OpenWrt, VyOS, OPNsense) и Linux-серверах.

Автоматически отделяет внутригосударственный трафик (банки, госуслуги, стриминги, маркетплейсы) от зарубежного, направляя заблокированные или зарубежные ресурсы в VPN-туннель, а локальные сервисы — напрямую через домашнего провайдера на полной скорости.

> 💡 *Проект вдохновлен концепцией [LeonidOz/BGP-Antifilter](https://github.com/LeonidOz/BGP-Antifilter) и полностью переработан в высокопроизводительную модульную архитектуру с нулевым потреблением ресурсов (~89 MB RAM), динамическим BGP-пулом и интеллектуальной CDN-маршрутизацией.*

---

## 🌟 Возможности и сравнение

| Возможность | Стандартные решения | **Auto BGP Feed** |
| :--- | :--- | :--- |
| **Подключение клиентов** | Требует фиксированного белого IP. При смене IP сессия падает. | **Dynamic BGP Pool (`0.0.0.0/0`)** — роутер подключается с любого динамического или серого IP. |
| **Потребление RAM** | 300–500 MB RAM | **~89 MB RAM на весь стек** (BIRD 2 + FRR + FastAPI). |
| **Cloudflare / CDN** | Добавляет 1 точечный IP (через 5 минут Cloudflare ротирует Anycast-ноду и трафик идет мимо). | **Smart-DNS Anycast Classifier**: авто-детект CDN, покрытие `/24` подсетей и авто-компрессия (`collapse_addresses`). |
| **Сетевая разведка** | Отсутствует | **Network Intelligence**: авто-определение страны, провайдера, ASN, CDN-статуса и добавление в 1 клик. |
| **База маршрутов** | Статический текстовый файл | **Интерактивный Route Explorer** с живым поиском по базе 8.6k+ префиксов. |
| **Телеметрия роутера** | Нет | Живой пинг клиента (RTT в мс), аптайм сессии, счетчики Keepalive/Update сообщений. |
| **Обновления сетей** | Ручной перезапуск демона | **Фоновый цикл автообновления** (каждые 15 мин) + BGP Soft-Reconfiguration без разрыва связи. |

---

## 🏗 Архитектура системы

Система состоит из 3 изолированных легковесных контейнеров, связанных внутренней оверлейной сетью:

```
[ Интернет (RIPE NCC / DNS / IPverse) ]
                   │
                   ▼
     ┌───────────────────────────┐
     │   source-manager (FastAPI)│ ◄─── Web UI (Smart Add & Разведка)
     └─────────────┬─────────────┘
                   │ Генерирует ru_routes.conf & custom_routes.conf
                   ▼
     ┌───────────────────────────┐
     │     bgp-core (BIRD 2)     │ ◄─── Агрегация 8.6k+ префиксов, дедупликация
     └─────────────┬─────────────┘
                   │ Внутренняя eBGP сессия (172.30.0.2 -> 172.30.0.3)
                   ▼
     ┌───────────────────────────┐
     │    public-bgp (FRRouting) │ ◄─── Публичный порт 179/TCP (Dynamic Listen 0.0.0.0/0)
     └─────────────┬─────────────┘
                   │ Внешний BGP eBGP Peer
                   ▼
       [ MikroTik / Keenetic / OpenWrt / Linux ]
```

---

## ⚡ Быстрая установка в 1 команду (One-Line Installer)

Выполните команду на вашем чистом сервере (Ubuntu / Debian / Alpine):

```bash
curl -sSL https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/install.sh | bash
```

*Скрипт сам проверит Docker, спросит желаемые логин/пароль и мгновенно запустит все службы.*

---

## 🐳 Ручная установка через Docker Compose

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/milkmann/AutoBgpFeed.git
cd AutoBgpFeed

# 2. Создайте файл настроек
cp .env.example .env
nano .env

# 3. Запустите стек
docker compose up -d --build
```
Веб-панель управления будет доступна по адресу: **`http://YOUR_SERVER_IP:8080`**.

---

## 🌐 Настройка роутера MikroTik (RouterOS 7)

Выполните в терминале MikroTik (заменив `YOUR_SERVER_IP` на IP вашего сервера):

```routeros
# 1. Создаем фильтр BGP на MikroTik
/routing/filter/rule
add chain=antifilter-in disabled=no rule="if (bgp-communities includes 65000:1000) { set gw wireguard1; accept; } else { reject; }"

# 2. Подключаемся к BGP-серверу
/routing/bgp/connection
add name="bgp-feed" remote.address=YOUR_SERVER_IP remote.port=179 remote.as=65000 \
    as=64999 local.role=ebgp multihop=yes connect=yes listen=no \
    routing-table=main input.filter=antifilter-in output.filter-chain=discard
```

---

## 🎯 Поддерживаемые типы источников

- **`DOMAIN`** — Домен конкретного сайта (`rutracker.org`, `chatgpt.com`). Опрашивает 5 мировых DNS-резолверов и классифицирует CDN.
- **`ASN`** — Автономная система целиком (`AS15169` Google/YouTube, `AS32934` Meta/Instagram, `AS62041` Telegram). Автоматически выгружает все диапазоны из RIPEstat.
- **`IP / CIDR`** — Точечные IP или подсети (`1.1.1.1`, `185.199.108.0/22`).
- **`URL`** — Внешние динамические `.txt` списки сетей.
- **`Exclusions`** — Правила исключения для вырезания локальных IP.

---

## 📄 Лицензия

Распространяется под свободной лицензией **Apache License 2.0**. См. файл [LICENSE](LICENSE) для подробностей.
