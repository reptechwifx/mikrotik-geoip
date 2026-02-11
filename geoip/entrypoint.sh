#!/bin/sh
set -eu

DATA_DIR="/data/geoip"
IPV4_DIR="$DATA_DIR/ipv4"
IPV6_DIR="$DATA_DIR/ipv6"

mkdir -p "$DATA_DIR"
mkdir -p "$IPV4_DIR" "$IPV6_DIR"

copy_if_missing() {
  src="$1"
  dst="$2"
  if [ ! -f "$dst" ] && [ -f "$src" ]; then
    cp "$src" "$dst"
  fi
}

copy_if_missing "/app/geoip.yaml" "/data/geoip.yaml"
copy_if_missing "/app/defaults/countries.yaml" "$DATA_DIR/countries.yaml"
copy_if_missing "/app/defaults/zones.yaml" "$DATA_DIR/zones.yaml"
copy_if_missing "/app/defaults/config.yaml" "$DATA_DIR/config.yaml"

exec "$@"
