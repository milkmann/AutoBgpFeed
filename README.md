# ⚡ Auto BGP Feed

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/BIRD_2-Routing_Engine-FF6B6B?style=for-the-badge" />
  <img src="https://img.shields.io/badge/FRRouting-Dynamic_BGP_Pool-4CAF50?style=for-the-badge" />
  <img src="https://img.shields.io/badge/FastAPI-Modern_Web_UI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/RouterOS_7_%26_6-Compatible-00D2FF?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Keenetic-OpenWrt-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=for-the-badge" />
</p>

<p align="center">
  <b><a href="#english">English Documentation</a></b> | <b><a href="#русский">Документация на русском</a></b>
</p>

---

<a name="english"></a>
## 🌐 English

**Auto BGP Feed** is an automated, high-performance BGP route feed gateway and control panel for selective VPN routing across all major home routers (**MikroTik RouterOS 7/6**, Keenetic, OpenWrt, VyOS/EdgeOS, Cisco IOS, OPNsense/pfSense) and Linux servers.

It dynamically separates domestic internet traffic (banking, government portals, regional streaming, marketplaces) from foreign/restricted traffic, routing blocked or foreign destinations through your VPN tunnel while keeping local traffic over direct ISP connections at full native wire speed.

> 💡 *Inspired by [LeonidOz/BGP-Antifilter](https://github.com/LeonidOz/BGP-Antifilter) and completely re-engineered into an ultra-lightweight microservice architecture (~89 MB RAM), dynamic BGP pool, multi-country feeds, and Anycast CDN classification.*

---

### 🌟 Key Features & Advantages

| Feature | Standard BGP Feeds | **Auto BGP Feed** |
| :--- | :--- | :--- |
| **Client Connection** | Requires static public IP. Drops on IP change. | **Dynamic BGP Pool (`0.0.0.0/0`)** — Connect from any dynamic, private, or NATed IP. |
| **RAM Footprint** | 300–500 MB RAM | **~89 MB RAM for the entire stack** (BIRD 2 + FRR + FastAPI). |
| **Country Feeds** | Hardcoded to a single country. | **Universal Country Feeds (`COUNTRY`)** — 1-click addition of any country (`UA`, `PL`, `KZ`, `US`, `DE`...). |
| **Cloudflare / CDN** | Resolves 1 host IP (Cloudflare rotates edge nodes every 5m, breaking VPN routing). | **Smart-DNS Anycast Classifier**: Auto-detects CDNs, covers `/24` blocks, and aggregates adjacent ranges (`collapse_addresses`). |
| **Network Intelligence** | None | **Universal Inspector**: 1-click lookup for Country, ISP, ASN, CDN status, and live links to 5 BGP aggregators. |
| **Route Explorer** | Static text file | **Interactive Route Explorer** with real-time instant search across 8.6k+ prefixes. |
| **Multi-User & Security**| Single shared password in plaintext | **Role-Based Access Control (Admin / Viewer)** + PBKDF2-SHA256 password hashing. |
| **Client Telemetry** | None | Real-time client RTT ping (ms), session uptime, Keepalive/Update packet counters. |
| **Auto-Updates** | Manual daemon restart | **Automated background cycle** (every 15 min) + BGP Soft-Reconfiguration with zero downtime. |

---

### 🚀 Quick Start Guide

#### System Requirements:
- Any VPS with **512 MB RAM** and **1 vCPU** (Ubuntu 22.04/24.04, Debian 11/12, or Alpine).
- Open incoming ports on firewall/provider:
  - **`179/TCP`** (BGP protocol for router communication)
  - **`8080/TCP`** (Web management panel)

---

#### Method 1: Automatic 1-Click Installer (Recommended)

Run this single command on your clean server:

```bash
curl -sSL https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/install.sh | bash
```

The script will automatically:
1. Install Docker & Docker Compose if missing.
2. Interactively prompt for your desired web port, admin username, and password.
3. Build and launch all 3 microservice containers in the background.
4. Output your ready-to-use MikroTik connection script.

---

#### Method 2: Manual Installation via Docker Compose

```bash
# 1. Install Docker & Docker Compose (if not already installed)
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 2. Clone the repository
git clone https://github.com/milkmann/AutoBgpFeed.git /opt/AutoBgpFeed
cd /opt/AutoBgpFeed

# 3. Create configuration file
cp .env.example .env
nano .env   # Set SERVER_IP, ADMIN_USER, ADMIN_PASS, WEB_PORT

# 4. Build and start containers
docker compose up -d --build
```

Access the dashboard at: **`http://YOUR_SERVER_IP:8080`**.

---

### 📖 How to Use AutoBgpFeed

1. **Log in to the Web Panel:** Open `http://YOUR_SERVER_IP:8080` and log in with your credentials.
2. **Connect your Router:** Go to the **Settings** tab, choose your router platform (MikroTik RouterOS 7/6, Keenetic, OpenWrt, etc.), and copy the generated BGP configuration.
3. **Add Blocked Sites or Countries:**
   - Go to **Lists & Smart Add** or **Tools & Intelligence**.
   - Type any domain (`youtube.com`, `rutracker.org`), ASN (`AS62041`), IP (`1.1.1.1`), or Country (`Ukraine`, `Poland`, `UA`, `PL`) ➔ click **Add**.
4. **Instant Synchronization:** Within seconds, the BGP engine generates the new routing tables and pushes them to your connected routers without interrupting active connections.

---

### 🌐 Router Connection Examples

<details>
<summary><b>1. MikroTik RouterOS 7</b></summary>

```routeros
# 1. Create BGP routing filter on MikroTik (replace wireguard1 with your VPN interface)
/routing/filter/rule
add chain=antifilter-in disabled=no rule="if (bgp-communities includes 65000:1000) { set gw wireguard1; accept; } else { reject; }"

# 2. Connect to the BGP Server
/routing/bgp/connection
add name="bgp-feed" remote.address=YOUR_SERVER_IP remote.port=179 remote.as=65000 \
    as=64999 local.role=ebgp multihop=yes connect=yes listen=no \
    routing-table=main input.filter=antifilter-in output.filter-chain=discard
```
</details>

<details>
<summary><b>2. MikroTik RouterOS 6</b></summary>

```routeros
# 1. Create BGP filters
/routing filter add chain=antifilter-in bgp-communities=65000:1000 set-gateway=wireguard1 action=accept
/routing filter add chain=antifilter-in action=reject

# 2. Configure BGP Peer
/routing bgp instance set default as=64999
/routing bgp peer add name="bgp-feed" remote-address=YOUR_SERVER_IP remote-as=65000 \
    multihop=yes in-filter=antifilter-in out-filter=discard hold-time=3m
```
</details>

<details>
<summary><b>3. Keenetic (Entware / BIRD 2)</b></summary>

Install BIRD2 (`opkg install bird2`) and add to `/opt/etc/bird.conf`:

```bird
protocol bgp bgp_feed {
    local as 64999;
    neighbor YOUR_SERVER_IP as 65000;
    multihop;
    ipv4 {
        import filter {
            if (65000, 1000) ~ bgp_community then {
                gw = 10.0.0.1; # IP of your VPN gateway
                accept;
            }
            reject;
        };
        export none;
    };
}
```
</details>

<details>
<summary><b>4. OpenWrt (BIRD 2)</b></summary>

Install BIRD2 (`opkg install bird2`) and add to `/etc/bird.conf`:

```bird
protocol bgp bgp_feed {
    local as 64999;
    neighbor YOUR_SERVER_IP as 65000;
    multihop;
    ipv4 {
        import filter {
            if (65000, 1000) ~ bgp_community then {
                gw = 10.0.0.1; # IP of your VPN gateway (wg0/tun0)
                accept;
            }
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
# 1. Routing Policy
set policy route-map BGP-OUT-DISCARD rule 10 action reject
set policy route-map BGP-IN-VPN rule 10 match community 65000:1000
set policy route-map BGP-IN-VPN rule 10 set next-hop 10.0.0.1
set policy route-map BGP-IN-VPN rule 20 action reject

# 2. BGP Peer
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
! 1. Route-Map & Communities
ip community-list standard CL-FEED permit 65000:1000
!
route-map BGP-IN-VPN permit 10
 match community CL-FEED
 set ip next-hop 10.0.0.1
route-map BGP-OUT-DISCARD deny 10
!
! 2. BGP Configuration
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

<a name="русский"></a>
## 🇷🇺 Русский

**Auto BGP Feed** — это автоматизированный BGP-шлюз и веб-панель управления списками маршрутов для выборочной VPN-маршрутизации на любых домашних роутерах (**MikroTik RouterOS 7/6**, Keenetic, OpenWrt, VyOS/EdgeOS, Cisco IOS, OPNsense/pfSense) и Linux-серверах.

Система в реальном времени разделяет внутригосударственный трафик (банки, госуслуги, стриминги, маркетплейсы) и зарубежный/заблокированный, автоматически направляя нужные ресурсы через VPN-туннель, а весь локальный трафик оставляя через прямого домашнего провайдера на максимальной скорости.

> 💡 *Проект вдохновлен концепцией [LeonidOz/BGP-Antifilter](https://github.com/LeonidOz/BGP-Antifilter) и полностью переработан в высокопроизводительную модульную архитектуру с минимальным потреблением ресурсов (~89 MB RAM), динамическим BGP-пулом, поддержкой стран целиком и умной CDN-маршрутизацией.*

---

### 🌟 Преимущества перед аналогами

| Параметр | Стандартные BGP-фиды | **Auto BGP Feed** |
| :--- | :--- | :--- |
| **Подключение клиентов** | Требует фиксированного белого IP. При смене IP сессия падает. | **Dynamic BGP Pool (`0.0.0.0/0`)** — роутер подключается с любого динамического, серого или NAT IP. |
| **Потребление памяти** | 300–500 MB RAM | **Всего ~89 MB RAM на весь стек** (BIRD 2 + FRR + FastAPI). |
| **Страновые пулы** | Жестко привязаны к 1 стране. | **Универсальные страновые фиды (`COUNTRY`)** — добавление любой страны в 1 клик (`UA`, `PL`, `KZ`, `US`, `DE`...). |
| **Cloudflare / CDN** | Добавляет 1 точечный IP (через 5 минут Cloudflare меняет ноду и сайт перестает открываться). | **Smart-DNS Anycast Classifier**: авто-детект CDN, охват `/24` подсетей и авто-компрессия (`collapse_addresses`). |
| **Сетевая разведка** | Отсутствует | **Network Intelligence**: мгновенное определение страны, провайдера, ASN, CDN-статуса и ссылки на 5 независимых BGP-агрегаторов. |
| **База сетей** | Статический текстовый файл | **Интерактивный Route Explorer** со сквозным поиском по базе 8.6k+ префиксов. |
| **Пользователи и безопасность** | Один пароль в файле | **Управление пользователями (Admin / Viewer)** + PBKDF2-SHA256 криптохэширование паролей. |
| **Телеметрия роутера** | Нет | Живой пинг клиента (RTT в мс), аптайм сессии, счетчики Keepalive/Update сообщений. |
| **Автообновление** | Ручной перезапуск демона | **Фоновый цикл автообновления** (каждые 15 мин) + BGP Soft-Reconfiguration без разрыва связи. |

---

### 🚀 Пошаговое руководство по установке

#### Системные требования:
* Любой VPS-сервер: **512 МБ RAM** и **1 ядро CPU** (Ubuntu 22.04/24.04, Debian 11/12 или Alpine).
* Открытые входящие порты:
  * **`179/TCP`** — для подключения роутеров по протоколу BGP.
  * **`8080/TCP`** (или 8088) — для веб-панели управления.

---

#### Способ 1: Автоматическая установка в 1 команду (Рекомендуется)

Подключитесь к вашему VPS по SSH и выполните команду:

```bash
curl -sSL https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/install.sh | bash
```

Установщик сделает всё сам:
1. Установит Docker и Docker Compose (если их ещё нет).
2. Запросит желаемый порт панели, логин и пароль администратора.
3. Скачает актуальные файлы, соберет и запустит 3 легковесных контейнера.
4. Выведет готовые команды для подключения вашего роутера.

---

#### Способ 2: Ручная установка через Docker Compose

Если вы предпочитаете ручной контроль:

```bash
# 1. Установите Docker (если не установлен)
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 2. Клонируйте репозиторий проекта
git clone https://github.com/milkmann/AutoBgpFeed.git /opt/AutoBgpFeed
cd /opt/AutoBgpFeed

# 3. Настройте файл окружения
cp .env.example .env
nano .env
# Укажите ваш SERVER_IP, ADMIN_USER, ADMIN_PASS и WEB_PORT

# 4. Соберите и запустите проект в фоновом режиме
docker compose up -d --build
```

Панель управления откроется по адресу: **`http://IP_ВАШЕГО_СЕРВЕРА:8080`**.

---

### 🎯 Как с этим работать (Инструкция пользователя)

1. **Вход в панель:** Перейдите в браузере по адресу `http://IP_СЕРВЕРА:8080` и введите логин и пароль.
2. **Подключение роутера к серверу:**
   * Откройте вкладку **«Настройки»**.
   * Выберите вкладку вашей платформы (*MikroTik RouterOS 7/6*, *Keenetic*, *OpenWrt*, *VyOS* или *Cisco*).
   * Скопируйте готовый скрипт и выполните его в терминале вашего роутера.
   * На вкладке **«Панель»** статус BGP сменится на `Established` (с показом пинга и аптайма).
3. **Добавление ресурсов в VPN:**
   * **Через вкладку «Инструменты и Разведка»:** Введите любой домен (например, `instagram.com`, `t.me`), ASN (`AS62041`) или страну (`Украина`, `Польша`, `UA`, `PL`). Система проверит сервер и предложит нажать одну кнопку для добавления.
   * **Через вкладку «Списки и Smart Add»:** Выберите тип источника (`COUNTRY`, `DOMAIN`, `ASN`, `IP/CIDR`, `URL`) и сохраните правило.
4. **Автоматическая синхронизация:** Роутер мгновенно получает маршруты по BGP без перезагрузки и разрыва соединений.
5. **Проверка работы:** Проверьте доступность добавленного сайта на компьютере или выполните `traceroute domain.com` — пакеты пойдут через ваш VPN-шлюз!

---

### 🛠️ Полезные команды управления сервером

```bash
# Просмотр логов всех сервисов в реальном времени:
docker compose logs -f

# Перезапуск стека:
docker compose restart

# Обновление проекта до последней версии с GitHub:
git pull
docker compose up -d --build

# Остановка контейнеров:
docker compose down
```

---

### 🌐 Примеры конфигурации роутеров

<details>
<summary><b>1. MikroTik RouterOS 7</b></summary>

```routeros
# 1. Создаем правило фильтрации входящих BGP-маршрутов (замените wireguard1 на имя вашего VPN-интерфейса)
/routing/filter/rule
add chain=antifilter-in disabled=no rule="if (bgp-communities includes 65000:1000) { set gw wireguard1; accept; } else { reject; }"

# 2. Подключаемся к BGP-узлу
/routing/bgp/connection
add name="bgp-feed" remote.address=YOUR_SERVER_IP remote.port=179 remote.as=65000 \
    as=64999 local.role=ebgp multihop=yes connect=yes listen=no \
    routing-table=main input.filter=antifilter-in output.filter-chain=discard
```
</details>

<details>
<summary><b>2. MikroTik RouterOS 6</b></summary>

```routeros
# 1. Создаем фильтры маршрутизации
/routing filter add chain=antifilter-in bgp-communities=65000:1000 set-gateway=wireguard1 action=accept
/routing filter add chain=antifilter-in action=reject

# 2. Настраиваем BGP Peer
/routing bgp instance set default as=64999
/routing bgp peer add name="bgp-feed" remote-address=YOUR_SERVER_IP remote-as=65000 \
    multihop=yes in-filter=antifilter-in out-filter=discard hold-time=3m
```
</details>

<details>
<summary><b>3. Keenetic (Entware / BIRD 2)</b></summary>

Установите BIRD2 (`opkg update && opkg install bird2`) и добавьте в `/opt/etc/bird.conf`:

```bird
protocol bgp bgp_feed {
    local as 64999;
    neighbor YOUR_SERVER_IP as 65000;
    multihop;
    ipv4 {
        import filter {
            if (65000, 1000) ~ bgp_community then {
                gw = 10.0.0.1; # IP адрес вашего VPN-шлюза
                accept;
            }
            reject;
        };
        export none;
    };
}
```
</details>

<details>
<summary><b>4. OpenWrt (BIRD 2)</b></summary>

Установите BIRD2 (`opkg update && opkg install bird2`) и добавьте в `/etc/bird.conf`:

```bird
protocol bgp bgp_feed {
    local as 64999;
    neighbor YOUR_SERVER_IP as 65000;
    multihop;
    ipv4 {
        import filter {
            if (65000, 1000) ~ bgp_community then {
                gw = 10.0.0.1; # IP адрес VPN-шлюза (wg0/tun0)
                accept;
            }
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
# 1. Настройка политик фильтрации
set policy route-map BGP-OUT-DISCARD rule 10 action reject
set policy route-map BGP-IN-VPN rule 10 match community 65000:1000
set policy route-map BGP-IN-VPN rule 10 set next-hop 10.0.0.1
set policy route-map BGP-IN-VPN rule 20 action reject

# 2. Настройка BGP пира
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
! 1. Фильтры Community и Route-Map
ip community-list standard CL-FEED permit 65000:1000
!
route-map BGP-IN-VPN permit 10
 match community CL-FEED
 set ip next-hop 10.0.0.1
route-map BGP-OUT-DISCARD deny 10
!
! 2. Настройка BGP
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

## 📄 License / Лицензия

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
