# geoip-wifx

Web service to generate MikroTik GEOIP address lists (custom.rsc / geoip.rsc),
with country/zone selection and map visualization.

## Docker Compose (example)

```yaml
version: '3.4'
services:
  geoip:
    image: registry.wifx.net/technical/geoip-wifx:main
    environment:
      GEOIP_REFRESH_HOURS: 24
      GEOIP_COUNTRY_PREFIX: geoip-
    volumes:
      - ./data:/data/geoip
```

## Environment variables

Default values are shown in parentheses.

- `GEOIP_REFRESH_HOURS` (24): GEOIP data refresh frequency.
- `FETCH_TIMEOUT` (20): download timeout (seconds).
- `GEOIP_COUNTRY_PREFIX` (`geoip-`): prefix for `geoip.rsc` lists.
- `GEOIP_CONFIG_PATH` (`/data/geoip/config.yaml`): YAML config.
- `GEOIP_CONFIG_FILE` (`/app/config.json`): legacy zones config.
- `GEOIP_COUNTRIES_URL` (`https://www.ipdeny.com/ipblocks/`): HTML country source.
- `GEOIP_IPV4_URL` (`https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz`)
- `GEOIP_IPV6_URL` (`https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz`)
- `GEOIP_COUNTRIES_FILE` (`/data/geoip/countries.yaml`)
- `GEOIP_ZONES_FILE` (`/data/geoip/zones.yaml`)
- `GEOIP_DOWNLOAD_DIR` (`/data/downloads`)
- `GEOIP_IPV4_DIR` (`/data/geoip/ipv4`)
- `GEOIP_IPV6_DIR` (`/data/geoip/ipv6`)
- `GEOIP_TMPFS_MAX_SIZE` (`20M`): size for the MikroTik `tmpfs` RAM disk used in the generated script.
- `GEOIP_ENTRY_TIMEOUT` (`1d 01:00:00`): timeout for each address-list entry in generated scripts.

## Volumes to mount

Minimum recommended:

- `/data/geoip`: IPv4/IPv6 persistence (must contain `/data/geoip/ipv4` and `/data/geoip/ipv6`).

Optional:

- `/data/downloads`: cache for downloaded archives.
- `/app/config.json`: if you use the legacy zones configuration.

## Usage

1. Open the service URL (e.g. `https://geoip.wifx.net/`).
2. Select countries/zones.
3. Generate the `custom.rsc` or `geoip.rsc` URLs.

Notes:

- On startup, `config.yaml`, `countries.yaml`, and `zones.yaml` are copied into `/data/geoip` only if they are missing.
- If you edit `countries.yaml` manually, it will not be overwritten by automatic updates.
- The `tmpfs` size should be adjusted based on the expected size of the downloaded list.
- Generated scripts use a fast list swap (`<list>` -> `<list>-old`) before adding new entries.
  Keep both lists in your firewall rules so updates are seamless.

Example firewall rules (include both lists):

```rsc
/ip firewall raw
add chain=prerouting action=drop src-address-list=geoip-at
add chain=prerouting action=drop src-address-list=geoip-at-old

/ip firewall filter
add chain=forward action=drop src-address-list=geoip-at
add chain=forward action=drop src-address-list=geoip-at-old
```

Useful endpoints:

- `/custom.rsc`
- `/geoip.rsc`
- `/health`
