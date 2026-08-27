#!/usr/bin/env bash
# ==============================================================================
# Auto BGP Feed — Automated 1-Click Installer
# https://github.com/milkmann/AutoBgpFeed
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ___         _          ___   ____  ____    _____             _ "
echo " / _ \  _   _| |_  ___  | __ )/ ___||  _ \  |  ___|__   ___   __| |"
echo "| |_| || | | | __|/ _ \ |  _ \| |  _ | |_) | | |_ / _ \ / _ \ / _\` |"
echo "|  _  || |_| | |_| (_) || |_) | |_| ||  __/  |  _|  __/|  __/| (_| |"
echo "|_| |_| \__,_|\__|\___/ |____/ \____||_|     |_|  \___| \___| \__,_|"
echo -e "${NC}"
echo -e "${BOLD}Автоматическая установка и запуск Auto BGP Feed Gateway${NC}"
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

INSTALL_DIR="/opt/AutoBgpFeed"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo -e "\n${CYAN}${BOLD}Настройка параметров доступа:${NC}"

read -r -p "Публичный IP вашего сервера [$DETECTED_IP]: " INPUT_IP
SERVER_IP=${INPUT_IP:-$DETECTED_IP}

read -r -p "Порт веб-панели [8080]: " INPUT_PORT
WEB_PORT=${INPUT_PORT:-8080}

read -r -p "Логин администратора веб-панели [admin]: " INPUT_USER
ADMIN_USER=${INPUT_USER:-admin}

GEN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 14 || echo "AutoPass2026")
read -r -p "Пароль администратора [$GEN_PASS]: " INPUT_PASS
ADMIN_PASS=${INPUT_PASS:-$GEN_PASS}

SERVER_ASN="65000"
BGP_PORT="179"

echo -e "\n${YELLOW}[*] Скачиваем актуальные файлы проекта...${NC}"

curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/docker-compose.yml" -o docker-compose.yml

mkdir -p bgp-core public-bgp source-manager/app source-manager/templates data bgp-core/generated

curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/bgp-core/Dockerfile" -o bgp-core/Dockerfile
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/bgp-core/bird.conf" -o bgp-core/bird.conf

curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/public-bgp/Dockerfile" -o public-bgp/Dockerfile
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/public-bgp/daemons" -o public-bgp/daemons
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/public-bgp/frr.conf" -o public-bgp/frr.conf

curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/source-manager/Dockerfile" -o source-manager/Dockerfile
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/source-manager/app/__init__.py" -o source-manager/app/__init__.py
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/source-manager/app/db.py" -o source-manager/app/db.py
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/source-manager/app/engine.py" -o source-manager/app/engine.py
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/source-manager/app/main.py" -o source-manager/app/main.py
curl -sSL "https://raw.githubusercontent.com/milkmann/AutoBgpFeed/main/source-manager/templates/index.html" -o source-manager/templates/index.html

cat <<EOF > .env
SERVER_IP=$SERVER_IP
SERVER_ASN=$SERVER_ASN
BGP_PORT=$BGP_PORT
WEB_PORT=$WEB_PORT
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
EOF

echo -e "\n${YELLOW}[*] Сборка и запуск Docker-контейнеров...${NC}"
docker compose up -d --build

echo -e "\n${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}  ✓ Auto BGP Feed успешно установлен и запущен!${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "Веб-панель управления:  ${CYAN}http://$SERVER_IP:$WEB_PORT${NC}"
echo -e "Логин:                  ${BOLD}$ADMIN_USER${NC}"
echo -e "Пароль:                 ${BOLD}$ADMIN_PASS${NC}"
echo -e "BGP Сервер:             ${BOLD}$SERVER_IP:179 (ASN $SERVER_ASN)${NC}"
echo "----------------------------------------------------------------"
echo -e "${YELLOW}${BOLD}Команда подключения для MikroTik (RouterOS 7):${NC}"
echo -e "${CYAN}/routing/filter/rule add chain=antifilter-in disabled=no rule=\"if (bgp-communities includes 65000:1000) { set gw wireguard1; accept; } else { reject; }\"${NC}"
echo -e "${CYAN}/routing/bgp/connection add name=\"bgp-feed\" remote.address=$SERVER_IP remote.port=179 remote.as=$SERVER_ASN as=64999 local.role=ebgp multihop=yes connect=yes listen=no routing-table=main input.filter=antifilter-in output.filter-chain=discard${NC}"
echo "----------------------------------------------------------------"
