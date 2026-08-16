#!/usr/bin/env bash
set -e

DOMAIN="nomadik.site"
EMAIL="kalen.vandenbos@gmail.com"
RSA_KEY_SIZE=4096
DATA_PATH="./certbot"
STAGING=0 # Set to 1 for testing against Let's Encrypt staging environment

if [ -d "$DATA_PATH/conf/live/$DOMAIN" ]; then
  echo "[*] Existing certificate found for $DOMAIN. Skipping dummy cert generation."
else
  echo "[*] Creating dummy certificate for $DOMAIN to bootstrap Nginx..."
  mkdir -p "$DATA_PATH/conf/live/$DOMAIN"
  openssl req -x509 -nodes -newkey rsa:$RSA_KEY_SIZE -days 1 \
    -keyout "$DATA_PATH/conf/live/$DOMAIN/privkey.pem" \
    -out "$DATA_PATH/conf/live/$DOMAIN/fullchain.pem" \
    -subj "/CN=localhost"
fi

echo "[*] Starting Nginx reverse proxy..."
docker compose up --force-recreate -d nginx-proxy telemetry-engine

echo "[*] Deleting dummy certificate..."
rm -Rf "$DATA_PATH/conf/live/$DOMAIN"
rm -Rf "$DATA_PATH/conf/archive/$DOMAIN"
rm -Rf "$DATA_PATH/conf/renewal/$DOMAIN.conf"

echo "[*] Requesting Let's Encrypt SSL certificate for $DOMAIN..."
STAGING_ARG=""
if [ $STAGING -ne 0 ]; then
  STAGING_ARG="--staging"
fi

docker compose run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $STAGING_ARG \
    --email $EMAIL \
    -d $DOMAIN \
    -d api.$DOMAIN \
    --rsa-key-size $RSA_KEY_SIZE \
    --agree-tos \
    --force-renewal \
    --non-interactive" certbot

echo "[*] Reloading Nginx with new certificate..."
docker compose exec nginx-proxy nginx -s reload

echo "[✓] Automated SSL Certificate Provisioning Complete."
