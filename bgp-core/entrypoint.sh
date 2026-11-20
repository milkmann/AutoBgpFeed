#!/bin/sh
set -eu

mkdir -p /etc/bird/generated /run/bird

ROUTES_FILE="/etc/bird/generated/routes.conf"
if [ ! -f "$ROUTES_FILE" ]; then
    printf '# Empty initial routes\n' > "$ROUTES_FILE"
fi

RAW_IP="${SERVER_IP:-}"
if printf '%s' "$RAW_IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    ROUTER_ID="$RAW_IP"
else
    ROUTER_ID="172.30.0.2"
fi

RAW_ASN="${SERVER_ASN:-65000}"
if printf '%s' "$RAW_ASN" | grep -Eq '^[0-9]+$'; then
    ASN_NUM="$RAW_ASN"
else
    ASN_NUM="65000"
fi

sed \
    -e "s/__ROUTER_ID__/${ROUTER_ID}/g" \
    -e "s/__SERVER_ASN__/${ASN_NUM}/g" \
    /etc/bird/bird.conf.template > /etc/bird/bird.conf

bird -p -c /etc/bird/bird.conf

exec bird -f -c /etc/bird/bird.conf -s /run/bird/bird.ctl -u root -g root
