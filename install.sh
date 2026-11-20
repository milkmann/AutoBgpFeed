#!/usr/bin/env bash
# ==============================================================================
# Auto BGP Feed v2 — Automated 1-Click Installer
# https://github.com/milkmann/AutoBgpFeed
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "   ___         _         ___             ___            _   ___  "
echo "  / _ \  _   _| |_  ___ | _ ) __ _ _ __ | __|___ ___ __| | |_  ) "
echo " / /_\ \| | | | __|/ _ \| _ \/ _\` | '_ \| _/ -_) -_) _\` |  / /  "
echo " \__,_/ \__,_|\__|\___/|___/\__, | .__/|_| \___\___\__,_| /___| "
echo "                            |___/|_|                            "
echo -e "${NC}"
echo -e "${BOLD}Автоматическая установка Auto BGP Feed v2 (Pure BIRD 2 Dynamic BGP)${NC}"
echo "------------------------------------------------------------------"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Пожалуйста, запустите скрипт с правами root (sudo)${NC}"
  exit 1
fi

DETECTED_IP=$(curl -s --max-time 4 ifconfig.me || curl -s --max-time 4 api.ipify.org || echo "YOUR_SERVER_IP")

if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[*] Docker не найден. Устанавливаем Docker...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi

if ! command -v git &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq git || apk add --no-cache git || true
fi

INSTALL_DIR="/opt/AutoBgpFeed"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${YELLOW}[*] Обновляем существующий репозиторий в $INSTALL_DIR...${NC}"
    git -C "$INSTALL_DIR" pull --ff-only
else
    rm -rf "$INSTALL_DIR"
    git clone https://github.com/milkmann/AutoBgpFeed.git "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

echo -e "\n${CYAN}${BOLD}Настройка параметров доступа:${NC}"

read -r -p "Публичный IP вашего сервера [$DETECTED_IP]: " INPUT_IP
SERVER_IP=${INPUT_IP:-$DETECTED_IP}

read -r -p "Адрес привязки веб-панели (127.0.0.1 за reverse proxy или 0.0.0.0) [0.0.0.0]: " INPUT_BIND
WEB_BIND=${INPUT_BIND:-0.0.0.0}

read -r -p "Порт веб-панели [8088]: " INPUT_PORT
WEB_PORT=${INPUT_PORT:-8088}

read -r -p "Логин администратора веб-панели [admin]: " INPUT_USER
ADMIN_USER=${INPUT_USER:-admin}

GEN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20 || echo "AutoPass2026Secure")
read -r -p "Пароль администратора [$GEN_PASS]: " INPUT_PASS
ADMIN_PASS=${INPUT_PASS:-$GEN_PASS}

SESSION_SECRET=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
SERVER_ASN="65000"
BGP_PORT="179"

mkdir -p data bgp-core/generated

cat <<EOF > .env
SERVER_IP=$SERVER_IP
SERVER_ASN=$SERVER_ASN
BGP_PORT=$BGP_PORT
WEB_BIND=$WEB_BIND
WEB_PORT=$WEB_PORT
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
SESSION_SECRET=$SESSION_SECRET
MIN_PREFIX_LENGTH=8
CACHE_MAX_AGE=604800
TRUST_PROXY_HEADERS=1
EOF
chmod 600 .env

echo -e "\n${YELLOW}[*] Сборка и запуск Docker-контейнеров...${NC}"
docker compose up -d --build

echo -e "\n${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}  ✓ Auto BGP Feed v2 успешно установлен и запущен!${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "Веб-панель управления:  ${CYAN}http://$SERVER_IP:$WEB_PORT${NC}"
echo -e "Логин:                  ${BOLD}$ADMIN_USER${NC}"
echo -e "Пароль:                 ${BOLD}$ADMIN_PASS${NC}"
echo -e "BGP Сервер:             ${BOLD}$SERVER_IP:$BGP_PORT (ASN $SERVER_ASN)${NC}"
echo "----------------------------------------------------------------"
echo -e "${YELLOW}${BOLD}Безопасная команда подключения для MikroTik (RouterOS 7):${NC}"
echo -e "${CYAN}/routing/filter/rule add chain=antifilter-in disabled=no rule=\"if (dst == 0.0.0.0/0 || dst-len < 8 || dst in 10.0.0.0/8 || dst in 172.16.0.0/12 || dst in 192.168.0.0/16 || dst in 100.64.0.0/10 || dst in $SERVER_IP/32) { reject; }\"${NC}"
echo -e "${CYAN}/routing/filter/rule add chain=antifilter-in disabled=no rule=\"if (bgp-communities includes $SERVER_ASN:1000) { set gw wireguard1; accept; } else { reject; }\"${NC}"
echo -e "${CYAN}/routing/filter/rule add chain=discard disabled=no rule=\"reject;\"${NC}"
echo -e "${CYAN}/routing/bgp/connection add name=\"bgp-feed\" remote.address=$SERVER_IP remote.port=$BGP_PORT remote.as=$SERVER_ASN as=64999 local.role=ebgp multihop=yes connect=yes listen=no routing-table=main input.filter=antifilter-in input.limit-process-routes-ipv4=25000 output.filter-chain=discard${NC}"
echo "----------------------------------------------------------------"
