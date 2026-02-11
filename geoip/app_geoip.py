import os
import tarfile
import time
import json
import ipaddress
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Set, Optional

import requests
import yaml
from fastapi import FastAPI, Query
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Config via env or geoip.yaml
# ---------------------------------------------------------------------------

GEOIP_CONFIG_PATH = Path(os.getenv("GEOIP_CONFIG_PATH", "/data/geoip/config.yaml"))


def load_yaml_config(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[GEOIP] ERROR loading config YAML {path}: {e}")
        return {}


def get_config_value(config: Dict[str, Any], keys: List[str], default: Any) -> Any:
    cur: Any = config
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return default if cur is None else cur


GEOIP_CONFIG = load_yaml_config(GEOIP_CONFIG_PATH)

GEOIP_COUNTRIES_URL = os.getenv("GEOIP_COUNTRIES_URL") or get_config_value(
    GEOIP_CONFIG, ["sources", "countries_html"], "https://www.ipdeny.com/ipblocks/"
)
GEOIP_IPV4_URL = os.getenv("GEOIP_IPV4_URL") or get_config_value(
    GEOIP_CONFIG,
    ["sources", "ipv4_tar_gz"],
    "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz",
)
GEOIP_IPV6_URL = os.getenv("GEOIP_IPV6_URL") or get_config_value(
    GEOIP_CONFIG,
    ["sources", "ipv6_tar_gz"],
    "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz",
)

GEOIP_COUNTRIES_FILE = Path(
    os.getenv("GEOIP_COUNTRIES_FILE")
    or get_config_value(GEOIP_CONFIG, ["files", "countries_yaml"], "/data/geoip/countries.yaml")
)
GEOIP_ZONES_FILE = Path(
    os.getenv("GEOIP_ZONES_FILE")
    or get_config_value(GEOIP_CONFIG, ["files", "zones_yaml"], "/data/geoip/zones.yaml")
)

GEOIP_DOWNLOAD_DIR = Path(
    os.getenv("GEOIP_DOWNLOAD_DIR")
    or get_config_value(GEOIP_CONFIG, ["paths", "download_dir"], "/data/downloads")
)
GEOIP_IPV4_DIR = Path(
    os.getenv("GEOIP_IPV4_DIR")
    or get_config_value(GEOIP_CONFIG, ["paths", "ipv4_dir"], "/data/geoip/ipv4")
)
GEOIP_IPV6_DIR = Path(
    os.getenv("GEOIP_IPV6_DIR")
    or get_config_value(GEOIP_CONFIG, ["paths", "ipv6_dir"], "/data/geoip/ipv6")
)

GEOIP_REFRESH_HOURS = int(
    os.getenv("GEOIP_REFRESH_HOURS")
    or get_config_value(GEOIP_CONFIG, ["refresh_hours"], 24)
)
FETCH_TIMEOUT = int(
    os.getenv("FETCH_TIMEOUT") or get_config_value(GEOIP_CONFIG, ["fetch_timeout"], 20)
)
GEOIP_TMPFS_MAX_SIZE = os.getenv("GEOIP_TMPFS_MAX_SIZE") or get_config_value(
    GEOIP_CONFIG, ["tmpfs_max_size"], "20M"
)
GEOIP_ENTRY_TIMEOUT = os.getenv("GEOIP_ENTRY_TIMEOUT") or get_config_value(
    GEOIP_CONFIG, ["entry_timeout"], "1d 01:00:00"
)

# Prefix pour /geoip.rsc (d??faut: geoip- ??' listes geoip-ch, geoip-fr, ...)
GEOIP_COUNTRY_PREFIX = os.getenv("GEOIP_COUNTRY_PREFIX", "geoip-")

# Suffix used for temporary list swap (list-old)
GEOIP_OLD_SUFFIX = os.getenv("GEOIP_OLD_SUFFIX", "-old")

# Fichier legacy pour les zones
LEGACY_ZONE_CONFIG_FILE = Path(os.getenv("GEOIP_CONFIG_FILE", "/app/config.json"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize_list_name(raw: Optional[str]) -> str:
    """Default list name for custom.rsc: geoip"""
    import re

    if not raw:
        return "geoip"
    raw = raw.strip()
    if not raw:
        return "geoip"
    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", raw)
    if not cleaned:
        return "geoip"
    return cleaned[:63]


def normalize_prefix(raw: Optional[str], default_prefix: str) -> str:
    """Normalize a base name for geoip lists (no trailing dash)."""
    import re

    if not raw:
        base = default_prefix
    else:
        base = raw.strip() or default_prefix

    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", base)
    cleaned = cleaned.rstrip("-")
    if not cleaned:
        cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", default_prefix).rstrip("-")
    if not cleaned:
        cleaned = "geoip"
    return cleaned[:40]  # enough for a prefix


def maybe_collapse_networks(nets, aggregate: bool):
    """Optionally aggregate subnets (ipaddress.collapse_addresses)."""
    nets_list = list(nets)
    if not aggregate or not nets_list:
        return sorted(nets_list, key=lambda n: int(n.network_address))
    return sorted(ipaddress.collapse_addresses(nets_list), key=lambda n: int(n.network_address))


def parse_custom_cidrs(raw: Optional[str]) -> List[ipaddress.IPv4Network]:
    """Parse custom list (CIDR, one per line)."""
    if raw is None or not raw.strip():
        return []
    nets: List[ipaddress.IPv4Network] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            nets.append(net)
    return nets


def list_old_name(list_name: str) -> str:
    """Temporary list name used during fast swaps."""
    if not list_name:
        return f"geoip{GEOIP_OLD_SUFFIX}"
    return f"{list_name}{GEOIP_OLD_SUFFIX}"


# ---------------------------------------------------------------------------
# Logical zones (loaded from zones.yaml)
# ---------------------------------------------------------------------------

ZONE_DEFS: Dict[str, List[str]] = {}
_country_catalog: Dict[str, str] = {}
_zone_catalog: Dict[str, str] = {}


def load_zone_defs() -> None:
    # Load logical zones from zones.yaml (or legacy config.json).
    global ZONE_DEFS, _zone_catalog

    zones_data: Optional[Dict[str, Any]] = None
    zone_names: Dict[str, str] = {}

    if GEOIP_ZONES_FILE.is_file():
        try:
            data = yaml.safe_load(GEOIP_ZONES_FILE.read_text()) or {}
            if isinstance(data, dict):
                zones_data = data.get("zones") if "zones" in data else data
                if isinstance(zones_data, dict):
                    print(f"[GEOIP] Loaded {len(zones_data)} zones from {GEOIP_ZONES_FILE}")
                elif isinstance(zones_data, list):
                    mapping: Dict[str, List[str]] = {}
                    for item in zones_data:
                        if not isinstance(item, dict):
                            continue
                        code = item.get("code")
                        countries = item.get("countries")
                        name = item.get("name")
                        if isinstance(code, str) and isinstance(countries, list):
                            mapping[code] = countries
                            if isinstance(name, str) and name.strip():
                                zone_names[code.strip().upper()] = name.strip()
                    zones_data = mapping if mapping else None
                    if zones_data:
                        print(f"[GEOIP] Loaded {len(zones_data)} zones from {GEOIP_ZONES_FILE}")
                else:
                    zones_data = None
            elif isinstance(data, list):
                mapping = {}
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    code = item.get("code")
                    countries = item.get("countries")
                    name = item.get("name")
                    if isinstance(code, str) and isinstance(countries, list):
                        mapping[code] = countries
                        if isinstance(name, str) and name.strip():
                            zone_names[code.strip().upper()] = name.strip()
                zones_data = mapping if mapping else None
                if zones_data:
                    print(f"[GEOIP] Loaded {len(zones_data)} zones from {GEOIP_ZONES_FILE}")
        except Exception as e:
            print(f"[GEOIP] ERROR loading zones YAML: {e}")

    if zones_data is None and LEGACY_ZONE_CONFIG_FILE.is_file():
        try:
            data = json.loads(LEGACY_ZONE_CONFIG_FILE.read_text())
            if isinstance(data, dict):
                zones_data = data
                print(f"[GEOIP] Loaded {len(zones_data)} zones from {LEGACY_ZONE_CONFIG_FILE}")
        except Exception as e:
            print(f"[GEOIP] ERROR loading zones config JSON: {e}")

    if zones_data is None:
        zones_data = {
            "EU": [
                "at", "be", "bg", "ch", "cy", "cz", "de", "dk", "ee", "es", "fi", "fr",
                "gr", "hr", "hu", "ie", "is", "it", "lt", "lu", "lv", "mt", "nl", "no",
                "pl", "pt", "ro", "se", "si", "sk",
            ],
            "US": ["us"],
        }
        print("[GEOIP] Using built-in default zones (2 zones).")

    cleaned: Dict[str, List[str]] = {}
    for zone_name, countries in zones_data.items():
        if not isinstance(zone_name, str):
            continue
        if not isinstance(countries, list):
            continue
        zn = zone_name.strip().upper()
        if not zn:
            continue
        ccodes: List[str] = []
        for c in countries:
            if isinstance(c, str) and c.strip():
                ccodes.append(c.strip().lower())
        if ccodes:
            cleaned[zn] = ccodes

    ZONE_DEFS = cleaned
    _zone_catalog = zone_names


def load_country_catalog() -> None:
    # Load country code/name from countries.yaml for the UI.
    global _country_catalog

    if not GEOIP_COUNTRIES_FILE.is_file():
        _country_catalog = {}
        return

    try:
        data = yaml.safe_load(GEOIP_COUNTRIES_FILE.read_text()) or []
        mapping: Dict[str, str] = {}

        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                code = item.get("code")
                name = item.get("name")
                if isinstance(code, str) and isinstance(name, str):
                    code = code.strip().lower()
                    name = name.strip()
                    if code and name:
                        mapping[code] = name
        elif isinstance(data, dict):
            for code, name in data.items():
                if isinstance(code, str) and isinstance(name, str):
                    code = code.strip().lower()
                    name = name.strip()
                    if code and name:
                        mapping[code] = name

        _country_catalog = mapping
        if mapping:
            print(f"[GEOIP] Loaded {len(mapping)} countries from {GEOIP_COUNTRIES_FILE}")
    except Exception as e:
        print(f"[GEOIP] ERROR loading countries YAML: {e}")
        _country_catalog = {}


# ---------------------------------------------------------------------------
# In-memory GEOIP cache
# ---------------------------------------------------------------------------

_country_nets: Dict[str, List[ipaddress.IPv4Network]] = {}
_last_refresh_ts: Optional[float] = None

BASE_DIR = Path(__file__).resolve().parent
FAVICON_PATH = BASE_DIR / "html" / "favico.svg"

app = FastAPI(title="WIFX GEOIP Mikrotik Service")
app.mount("/html", StaticFiles(directory=str(BASE_DIR / "html")), name="html")


# ---------------------------------------------------------------------------
# GEOIP download and parsing
# ---------------------------------------------------------------------------



def download_tar(url: str, dest: Path) -> None:
    if not url:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[GEOIP] Downloading {url} ...")
    resp = requests.get(url, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()
    dest.write_bytes(resp.content)


def extract_tar(tar_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)

    for f in dest_dir.glob("*.zone"):
        try:
            f.unlink()
        except Exception:
            pass

    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.name.endswith(".zone"):
                continue
            member.name = os.path.basename(member.name)  # type: ignore[attr-defined]
            tf.extract(member, path=dest_dir)


def fetch_countries_catalog() -> None:
    if not GEOIP_COUNTRIES_URL:
        return
    if GEOIP_COUNTRIES_FILE.is_file():
        # Respect user-managed countries.yaml and avoid overwriting it.
        return
    try:
        print(f"[GEOIP] Fetching countries list from {GEOIP_COUNTRIES_URL} ...")
        resp = requests.get(GEOIP_COUNTRIES_URL, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        html = resp.text

        import re

        pattern = re.compile(r"<p>([^<]+?)\s*\(([A-Z]{2})\)")
        matches = pattern.findall(html)

        items = []
        seen = set()
        for name, code in matches:
            code = code.strip().upper()
            if code in seen:
                continue
            seen.add(code)
            items.append({"code": code, "name": name.strip()})

        if not items:
            return

        GEOIP_COUNTRIES_FILE.parent.mkdir(parents=True, exist_ok=True)
        GEOIP_COUNTRIES_FILE.write_text(
            yaml.safe_dump(items, sort_keys=False, allow_unicode=False),
            encoding="utf-8",
        )
        print(f"[GEOIP] Updated countries list at {GEOIP_COUNTRIES_FILE}")
    except Exception as e:
        print(f"[GEOIP] ERROR updating countries list: {e}")


def download_and_extract_geoip() -> None:
    ipv4_tar = GEOIP_DOWNLOAD_DIR / "all-zones.tar.gz"
    ipv6_tar = GEOIP_DOWNLOAD_DIR / "ipv6-all-zones.tar.gz"

    if GEOIP_IPV4_URL:
        download_tar(GEOIP_IPV4_URL, ipv4_tar)
        extract_tar(ipv4_tar, GEOIP_IPV4_DIR)

    if GEOIP_IPV6_URL:
        download_tar(GEOIP_IPV6_URL, ipv6_tar)
        extract_tar(ipv6_tar, GEOIP_IPV6_DIR)

    print("[GEOIP] Extraction done.")


def load_country_nets_from_disk() -> None:
    """Load country codes only (XX.zone files, XX = 2 letters).

    Files like eu.zone or ap.zone are ignored to avoid treating them as
    countries. Logical zones are handled via zones.yaml (ZONE_DEFS).
    """
    global _country_nets, _last_refresh_ts
    nets: Dict[str, List[ipaddress.IPv4Network]] = {}

    for zone_file in GEOIP_IPV4_DIR.glob("*.zone"):
        code = zone_file.stem.lower()  # "ch", "fr", "eu", ...
        # Filter: ISO country codes only (2 letters)
        if len(code) != 2 or not code.isalpha():
            continue

        cidrs: List[ipaddress.IPv4Network] = []
        for line in zone_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network):
                cidrs.append(net)
        if cidrs:
            nets[code] = cidrs

    _country_nets = nets
    _last_refresh_ts = time.time()
    print(f"[GEOIP] Loaded {len(_country_nets)} country files into memory.")


def refresh_geoip_full() -> None:
    try:
        fetch_countries_catalog()
        load_country_catalog()
        download_and_extract_geoip()
        load_country_nets_from_disk()
    except Exception as e:
        print(f"[GEOIP] ERROR refreshing geoip data: {e}")


async def geoip_refresh_loop():
    # Load zones once (also at startup)
    load_zone_defs()
    load_country_catalog()

    # Initial GEOIP load
    refresh_geoip_full()
    print("[GEOIP] Ready.")

    while True:
        await asyncio.sleep(GEOIP_REFRESH_HOURS * 3600)
        print("[GEOIP] Periodic refresh...")
        refresh_geoip_full()


@app.on_event("startup")
async def on_startup():
    # Zones + countries catalog
    load_zone_defs()
    load_country_catalog()
    # Refresh task
    asyncio.create_task(geoip_refresh_loop())


# ---------------------------------------------------------------------------
# HTML / index
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WIFX GEOIP for MikroTik</title>
  <link rel="icon" href="/html/favico.svg" type="image/svg+xml">
  <style>
    body { margin:0; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; background:#f5f6f8; }
    header { background:#0747a6; color:#fff; padding:8px 16px; display:flex; align-items:center; }
    header img { height:28px; margin-right:12px; }
    header .title { font-size:18px; font-weight:600; }
    main { max-width:1000px; margin:24px auto; background:#fff; padding:24px 28px; border-radius:6px; box-shadow:0 1px 3px rgba(9,30,66,0.13); }
    h1 { margin-top:0; font-size:22px; color:#172b4d; }
    h2 { color:#172b4d; }
    h3 { color:#172b4d; }
    p { color:#42526e; }
    footer { text-align:center; padding:16px; font-size:12px; color:#6b778c; }
    footer a { color:#0747a6; text-decoration:none; }

    .builder { margin-top:16px; padding:16px; border-radius:6px; background:#f4f5f7; display:flex; gap:24px; flex-wrap:wrap; }
    .builder > div { flex:1 1 260px; }

    .settings label { display:block; margin-bottom:8px; font-size:13px; color:#172b4d; }
    .settings input[type="text"] { width:100%; box-sizing:border-box; }

    .scroll-box { max-height:360px; overflow:auto; border:1px solid #ddd; border-radius:6px; padding:8px 12px; background:#fafbfc; }
    .quick-search { width:100%; box-sizing:border-box; margin:6px 0; padding:6px 8px; border:1px solid #c1c7d0; border-radius:4px; font-size:12px; }
    .is-hidden { display:none; }
    .map-panel { margin-top:16px; }
    .map-container { background:#f4f5f7; border-radius:6px; padding:12px; border:1px solid #e0e0e0; }
    .world-map { width:100%; height:auto; max-height:320px; display:block; }
    .country { fill:#c7c7c7; stroke:#666; stroke-width:0.6; vector-effect: non-scaling-stroke; transition:fill 0.2s ease; }
    .country.on { fill:#36b37e; }
    .map-legend { display:flex; gap:12px; font-size:12px; color:#6b778c; margin-top:8px; flex-wrap:wrap; }
    .legend-swatch { width:12px; height:12px; display:inline-block; border-radius:2px; margin-right:4px; background:#36b37e; vertical-align:middle; }
    .legend-swatch.inactive { background:#dfe1e6; border:1px solid #c1c7d0; }
    ul { margin:0; padding:0; list-style:none; }
    li { margin:2px 0; font-size:13px; }
    label { cursor:pointer; }

    .outputs { margin-top:16px; }
    .outputs h3 { margin-bottom:4px; }
    .outputs input { width:100%; box-sizing:border-box; margin-bottom:4px; font-size:12px; }
    .outputs button { padding:6px 12px; border-radius:4px; border:0; cursor:pointer; background:#0747a6; color:#fff; font-size:13px; margin-right:6px; }
    .note { font-size:12px; color:#6b778c; }
    .settings textarea { width:100%; box-sizing:border-box; min-height:80px; }
    code { background:#f4f5f7; padding:2px 4px; border-radius:3px; font-size:90%; }
    pre code { display:block; padding:12px; white-space:pre; overflow-x:auto; }
  </style>
</head>
<body>
<header>
  <img src="/html/logo.png" alt="WIFX">
  <div class="title">WIFX GEOIP for MikroTik</div>
</header>
<main>
  <h1>GEOIP address-lists for MikroTik</h1>
  <p>
    Select countries and zones to generate <code>.rsc</code> URLs:
    <ul>
      <li><strong>custom.rsc</strong> - all selected countries/zones merged into <em>one</em> address-list (default list=<code>geoip</code>)</li>
      <li><strong>geoip.rsc</strong> - one address-list per country and per zone (default name <code>geoip-ch</code>, <code>geoip-eu</code>, ...)</li>
    </ul>
  </p>

  <section class="builder">
    <div class="settings">
      <h3>Settings</h3>
      <label>
        Address-list name for <code>custom.rsc</code>:
        <input id="list-name" type="text" placeholder="geoip" />
      </label>
        <label>
          Prefix for <code>geoip.rsc</code> lists:
          <input id="prefix" type="text" placeholder="geoip-" />
        </label>
        <label style="margin-top:6px;">
          <input id="aggregate" type="checkbox" checked />
          Aggregate subnets (collapse overlapping/contiguous prefixes)
        </label>
        <p class="note">
          Countries are identified by their ISO code (e.g. CH, FR, DE).
          Zones are loaded from <code>zones.yaml</code>.
        </p>
        <label>
          Custom list (one per line):
          <textarea id="custom-cidr" placeholder="10.0.0.0/8&#10;192.168.0.0/16"></textarea>
        </label>
    </div>

    <div>
      <h3>Countries</h3>
      <label class="note">
        <input id="countries-select-all" type="checkbox" />
        Select all
      </label>
      <input id="countries-search" class="quick-search" type="text" placeholder="Quick search..." />
      <div class="scroll-box">
        <ul id="countries-list">
          {{COUNTRIES}}
        </ul>
      </div>
    </div>

    <div>
      <h3>Zones</h3>
      <label class="note">
        <input id="zones-select-all" type="checkbox" />
        Select all
      </label>
      <div class="scroll-box">
        <ul id="zones-list">
          {{ZONES}}
        </ul>
      </div>
    </div>
  </section>



  <section class="map-panel">
    <h3>World map</h3>
    <div class="map-container">
      <svg xmlns="http://www.w3.org/2000/svg" width="1000" height="492" viewBox="0 0 1000 492">
  
  
  <g id="countries">
    <path id="FJ" class="country" data-iso2="FJ" data-iso3="FJI" data-name="Fiji" d="M990.00,281.18L990.00,282.51L986.53,283.75L986.18,282.73L990.00,281.18ZM984.90,285.09L985.57,284.64L986.51,285.43L986.06,286.85L982.87,286.89L982.61,285.69L983.66,284.75L984.90,285.09ZM10.56,281.05L10.22,282.36L10.00,282.51L10.00,281.18L10.56,281.05Z"/>
    <path id="TZ" class="country" data-iso2="TZ" data-iso3="TZA" data-name="Tanzania" d="M592.29,240.03L602.62,245.87L602.81,247.45L606.72,250.17L605.46,253.52L605.62,255.07L607.36,256.06L606.67,260.54L609.75,265.52L607.58,267.10L599.40,269.35L594.08,268.80L593.32,265.10L591.85,263.07L583.68,260.14L582.21,256.71L580.63,255.19L579.87,249.69L581.00,249.56L583.71,246.58L582.95,244.01L583.73,243.67L583.89,242.06L582.81,240.53L592.29,240.03Z"/>
    <path id="EH" class="country" data-iso2="EH" data-iso3="ESH" data-name="W. Sahara" d="M476.41,162.15L476.35,166.99L467.42,166.84L467.50,173.81L464.95,174.05L464.29,175.45L464.80,179.38L454.14,179.37L453.55,180.27L453.67,179.12L459.84,178.91L462.19,172.95L465.97,170.01L467.25,166.58L468.10,166.38L468.99,164.26L476.06,163.61L476.41,162.15Z"/>
    <path id="CA" class="country" data-iso2="CA" data-iso3="CAN" data-name="Canada" d="M165.60,104.05L158.02,100.19L153.09,99.07L151.58,96.66L151.96,94.99L148.48,93.83L148.00,91.63L144.71,89.66L144.65,88.25L146.17,86.94L146.09,85.22L141.46,83.49L136.98,78.43L131.20,74.68L125.82,77.09L121.50,74.11L116.17,73.27L116.20,47.67L128.41,49.88L134.09,47.90L138.14,48.23L146.67,46.36L148.54,47.48L150.57,46.85L151.18,45.57L157.66,48.30L161.29,46.45L161.66,48.52L166.03,47.28L169.33,47.43L179.86,49.58L186.27,49.86L189.94,51.24L186.11,52.59L191.04,53.18L200.70,52.38L203.60,54.01L206.57,52.63L203.79,51.48L205.54,50.55L211.04,50.15L215.97,52.28L219.01,52.06L223.82,53.29L232.02,52.92L231.70,51.23L234.12,50.75L238.34,51.68L238.32,54.25L240.06,52.08L242.25,52.15L243.48,49.42L237.38,46.64L237.60,43.63L240.82,41.66L247.16,43.29L250.86,46.36L248.45,47.70L253.51,48.25L253.50,51.03L257.14,48.90L260.39,50.65L259.58,52.67L262.21,54.51L267.04,50.19L267.19,47.20L275.08,47.81L278.74,49.16L278.90,50.52L276.87,51.97L278.79,53.42L278.45,54.75L273.12,56.65L269.33,57.07L266.52,56.25L262.29,61.11L259.13,62.95L255.23,63.13L253.08,64.28L252.90,66.05L249.74,66.39L243.45,71.66L242.40,73.81L242.25,76.97L246.25,77.42L248.75,82.04L252.56,81.50L268.58,86.89L276.04,87.31L275.59,89.67L276.44,92.41L278.41,95.45L282.46,98.04L284.56,97.15L286.03,94.35L284.61,90.05L282.69,88.62L287.04,87.35L291.64,83.54L291.41,81.72L289.57,79.41L286.26,77.36L289.47,74.51L287.38,67.79L289.27,67.16L296.74,68.17L298.99,67.45L304.88,69.95L305.70,71.01L310.56,71.22L311.38,76.94L313.87,77.37L315.84,78.97L319.78,77.46L324.19,73.19L332.86,82.36L331.77,84.07L337.84,87.16L343.93,88.73L345.01,91.04L348.22,92.43L348.42,95.48L344.49,97.46L340.00,98.43L336.58,100.67L319.25,100.70L316.97,102.66L313.50,103.86L306.44,109.98L308.75,109.53L313.12,105.96L318.83,103.69L322.90,103.42L325.31,104.75L322.74,106.58L324.49,111.57L328.03,112.93L332.53,112.53L335.26,109.47L335.45,111.45L337.20,112.43L325.11,116.94L322.06,118.90L320.00,118.70L319.89,116.40L324.62,114.14L317.24,114.56L315.46,113.03L315.46,109.31L311.52,108.28L307.65,113.69L305.35,114.92L296.20,114.94L290.88,118.67L285.71,118.68L284.48,119.11L285.11,120.75L275.58,123.99L273.67,123.17L276.40,118.83L275.28,113.99L272.44,112.72L272.78,112.23L270.95,110.82L269.69,111.02L268.95,109.77L259.42,105.95L256.98,106.72L250.54,106.39L243.22,104.95L241.89,102.99L240.96,103.00L240.96,104.05L165.60,104.05ZM271.35,67.43L273.37,66.17L277.11,66.20L273.87,68.23L271.35,67.43ZM282.83,39.25L279.84,37.81L279.95,36.83L287.49,36.94L292.19,38.44L292.43,39.19L282.83,39.25ZM281.36,68.43L282.41,67.61L284.22,68.23L283.15,69.66L281.36,68.43ZM245.17,33.33L243.68,34.38L236.43,33.47L237.88,32.24L241.79,31.51L245.17,33.33ZM244.55,26.41L238.20,26.32L237.48,25.56L242.96,25.60L244.55,26.41ZM236.61,23.02L239.87,23.97L239.13,24.95L235.10,25.51L232.88,24.88L231.50,22.73L236.61,23.02ZM260.04,34.93L248.41,33.71L247.13,30.87L244.40,29.68L235.61,28.51L236.64,27.39L250.63,28.43L252.98,29.33L252.36,30.35L257.21,31.61L279.15,31.33L282.07,32.36L282.67,33.48L276.92,34.79L260.04,34.93ZM197.11,24.69L200.95,25.12L200.05,25.93L194.97,26.71L190.93,25.83L197.11,24.69ZM197.93,22.92L201.47,23.47L193.64,24.00L196.47,22.79L197.93,22.92ZM348.64,97.74L345.39,101.84L347.17,100.92L348.99,101.50L348.04,102.45L354.42,103.37L353.58,105.37L355.49,104.90L356.68,108.04L355.53,110.43L352.51,110.02L353.10,107.79L352.35,107.45L349.19,109.81L347.56,109.71L349.49,108.43L346.87,107.77L338.66,107.85L338.25,107.05L339.94,106.09L338.76,105.35L341.04,103.71L343.86,99.37L347.91,96.89L349.17,97.00L348.64,97.74ZM271.65,60.20L277.75,61.98L277.99,63.27L280.00,63.06L281.94,63.96L279.52,64.82L275.29,64.16L273.76,62.94L267.19,65.80L266.25,64.20L262.56,64.47L264.93,63.12L266.21,58.48L268.17,58.71L268.68,59.90L270.07,59.48L271.65,60.20ZM285.57,40.48L288.14,39.40L297.93,42.07L298.29,43.26L303.34,42.65L306.18,44.38L312.75,45.45L317.70,49.10L312.70,50.37L323.43,52.74L327.34,55.24L331.63,55.43L330.78,57.34L326.00,60.50L318.37,56.72L314.85,57.06L314.50,58.62L322.18,62.17L323.96,64.87L323.02,66.83L312.76,63.91L319.88,68.85L312.50,67.76L306.66,66.18L303.36,64.86L304.31,64.09L296.28,61.37L296.33,62.16L288.46,62.59L286.15,61.66L287.95,59.65L298.67,59.26L297.76,58.28L298.71,56.93L302.23,54.28L300.43,52.14L290.75,49.89L292.49,49.20L289.61,47.51L285.06,46.43L278.67,47.58L258.59,45.77L256.32,44.81L259.17,43.57L255.30,43.56L254.44,40.80L256.53,38.36L259.33,37.25L266.36,36.53L264.36,38.29L266.50,39.99L269.02,37.79L275.92,36.67L280.59,39.49L280.18,41.27L285.57,40.48ZM242.74,35.63L248.41,35.72L253.61,36.38L249.54,38.81L246.30,39.34L243.38,41.37L240.27,41.27L238.57,38.88L238.62,37.53L242.74,35.63ZM165.56,30.23L175.77,26.43L183.68,26.07L183.31,28.16L181.21,29.11L169.25,30.82L165.56,30.23ZM138.73,90.33L141.35,90.11L140.53,93.20L142.90,95.39L141.82,95.39L137.80,92.04L137.45,89.98L138.73,90.33ZM212.83,21.56L225.53,22.93L228.67,25.36L213.69,24.07L216.32,23.26L213.02,22.61L212.83,21.56ZM163.78,105.38L162.41,105.76L157.94,104.53L154.20,101.83L151.39,101.34L150.58,99.23L157.67,100.52L163.78,105.38ZM169.15,34.77L179.99,35.49L185.55,37.42L175.46,40.02L172.08,41.93L172.08,43.12L164.92,44.43L163.48,43.24L157.19,41.80L162.61,36.87L159.95,35.20L169.15,34.77ZM206.49,30.97L211.77,30.63L212.25,31.97L210.59,33.26L194.50,34.86L190.36,34.92L190.02,34.03L195.67,32.83L179.57,32.67L183.28,30.01L185.84,29.25L203.10,31.98L199.20,29.38L201.70,28.39L204.51,28.70L206.49,30.97ZM210.02,38.51L213.07,39.61L215.62,44.18L225.11,46.82L224.81,48.01L220.34,48.23L222.08,49.28L221.16,50.28L211.55,49.12L191.54,50.87L190.06,49.59L183.93,49.15L180.57,46.99L193.98,45.89L179.04,45.41L177.60,44.41L183.91,43.32L174.96,42.64L179.14,39.52L186.43,37.86L189.21,38.39L187.85,39.66L193.91,38.84L197.70,40.21L200.77,38.82L203.26,39.71L205.49,42.39L206.85,41.26L204.92,38.47L210.02,38.51ZM226.58,39.52L223.59,37.74L226.81,36.42L234.91,36.65L235.62,37.44L233.08,38.74L237.20,39.91L236.71,42.36L232.24,43.42L220.97,40.05L221.03,39.18L226.58,39.52ZM209.81,37.08L213.46,36.97L215.53,37.57L213.13,39.37L208.89,37.46L209.81,37.08ZM231.86,28.59L233.94,29.85L232.79,33.27L228.30,33.55L225.37,33.12L225.43,31.53L220.97,31.74L220.79,29.63L231.86,28.59ZM238.62,18.02L243.30,17.00L242.11,16.38L248.44,16.24L251.92,17.69L260.96,18.79L263.11,20.59L266.39,21.47L257.63,24.32L247.17,24.17L244.24,23.06L244.29,22.07L246.44,21.35L241.46,21.37L236.73,19.23L238.62,18.02ZM250.68,14.50L267.25,12.44L273.57,13.35L275.63,11.88L284.11,11.14L301.74,10.86L331.63,12.51L331.51,13.23L315.82,15.57L321.75,15.56L310.89,17.98L306.23,20.21L290.64,21.50L294.39,21.85L292.51,22.33L294.76,23.67L282.88,27.26L283.26,27.87L287.91,27.77L287.97,28.43L280.69,30.07L256.39,29.26L256.05,27.96L261.08,27.34L259.74,25.38L268.68,26.36L264.96,24.62L260.55,24.09L267.58,22.39L268.35,21.44L264.51,20.38L263.35,18.98L272.94,19.39L277.19,18.40L261.54,18.26L256.72,17.33L251.28,15.43L250.68,14.50ZM295.25,53.84L290.42,54.78L289.75,53.45L290.90,51.92L293.40,51.55L295.52,52.30L295.25,53.84ZM237.97,48.27L239.63,49.31L237.93,50.27L228.33,48.52L232.63,46.49L237.97,48.27ZM324.36,101.67L328.89,102.13L331.75,103.76L326.90,102.96L324.36,101.67ZM325.74,109.40L326.69,110.72L331.19,111.01L328.84,112.30L325.39,111.15L324.71,110.24L325.74,109.40Z"/>
    <path id="US" class="country" data-iso2="US" data-iso3="USA" data-name="United States of America" d="M165.60,104.05L240.96,104.05L240.96,103.00L241.89,102.99L243.22,104.95L250.54,106.39L256.98,106.72L259.42,105.95L268.95,109.77L269.69,111.02L270.95,110.82L272.78,112.23L272.44,112.72L275.28,113.99L276.40,118.83L273.73,122.89L274.90,123.99L285.11,120.75L284.48,119.11L285.71,118.68L290.88,118.67L296.20,114.94L305.35,114.92L307.65,113.69L311.52,108.28L315.46,109.31L315.46,113.03L317.71,115.46L309.13,118.52L307.23,120.75L307.20,122.19L308.10,123.64L309.23,123.70L308.94,122.71L309.76,123.32L309.54,124.09L299.34,126.02L304.15,126.02L298.69,126.51L297.86,127.26L298.66,127.39L298.07,129.34L296.09,131.44L294.40,129.92L295.68,132.89L293.27,136.13L293.87,134.17L292.48,133.13L292.16,130.86L291.63,132.04L292.21,133.77L290.42,133.34L292.29,134.22L293.85,140.66L292.12,142.68L284.78,146.26L278.58,151.85L278.65,155.68L282.07,164.27L281.18,168.82L279.03,168.84L277.57,167.02L274.45,161.53L275.01,159.72L272.12,155.95L271.06,155.53L268.31,156.76L264.80,154.68L256.11,155.34L257.13,157.70L256.61,158.06L252.60,158.09L250.57,156.65L246.22,156.36L242.23,157.19L235.56,161.68L234.91,164.78L235.56,167.02L234.50,167.10L230.45,165.65L229.08,162.47L225.17,157.46L223.25,156.37L221.03,156.43L219.31,158.58L217.05,157.76L215.64,156.94L214.06,154.02L210.06,151.00L205.35,151.00L205.34,152.12L197.77,152.14L187.45,148.90L187.70,148.37L181.15,148.87L180.69,147.48L177.36,144.81L171.64,143.23L171.31,141.73L168.67,139.00L166.50,134.58L163.19,131.40L162.81,129.18L161.36,127.70L161.86,123.11L160.99,121.02L162.72,113.51L162.23,109.86L160.57,106.27L160.90,105.74L164.84,106.66L166.29,109.23L166.96,108.51L165.60,104.05ZM76.96,182.78L78.58,184.33L76.18,185.95L75.13,183.80L75.71,182.27L76.96,182.78ZM75.35,180.91L74.21,181.44L73.40,180.47L73.67,180.24L75.35,180.91ZM73.27,179.79L73.18,180.09L71.73,180.01L71.93,179.67L73.27,179.79ZM69.82,178.32L70.83,179.40L70.69,179.55L69.54,179.42L69.09,178.70L69.82,178.32ZM66.17,176.97L65.90,177.87L64.99,177.37L65.54,176.91L66.17,176.97ZM46.84,73.06L49.00,73.31L49.26,74.35L47.59,74.77L44.15,73.53L46.84,73.06ZM82.88,79.63L85.84,80.66L80.76,82.99L79.37,82.29L78.95,81.02L82.88,79.63ZM116.20,47.67L116.17,73.27L121.50,74.11L125.82,77.09L131.20,74.68L136.98,78.43L141.46,83.49L146.09,85.22L146.17,86.94L144.65,88.25L140.76,86.36L139.99,83.99L136.48,81.79L135.01,79.22L128.07,78.97L119.25,75.36L111.88,73.88L108.11,74.11L99.52,71.70L96.50,72.27L97.06,74.16L86.99,76.40L86.60,74.80L87.83,72.13L90.72,71.29L89.98,70.61L80.73,75.87L82.72,77.20L80.14,79.15L74.49,81.12L73.82,82.33L69.57,83.73L68.71,85.01L56.09,88.56L50.99,88.88L59.53,85.28L62.91,84.97L68.03,82.23L70.64,80.72L72.50,77.05L68.48,77.41L67.01,78.40L65.23,77.01L64.50,77.99L63.48,76.63L59.08,77.72L59.34,75.10L57.59,74.13L54.05,74.66L49.89,72.72L49.88,71.18L47.78,70.02L48.83,68.46L52.02,65.54L56.09,65.78L58.29,64.46L62.34,63.85L61.84,62.61L60.31,62.12L62.33,61.07L56.94,62.30L50.94,62.00L46.95,61.35L42.37,58.67L52.26,56.20L54.50,56.20L54.13,57.56L59.88,57.46L49.77,52.21L46.03,51.35L47.55,49.92L52.38,49.84L55.82,48.60L56.47,47.27L59.25,45.98L69.56,44.64L73.75,43.19L77.87,43.76L79.84,44.99L85.65,44.62L85.49,45.25L89.65,45.71L105.50,46.91L109.12,46.47L116.20,47.67ZM32.51,63.81L35.89,64.05L40.79,65.13L38.50,66.00L35.39,64.92L32.99,65.07L32.51,63.81Z"/>
    <path id="KZ" class="country" data-iso2="KZ" data-iso3="KAZ" data-name="Kazakhstan" d="M737.81,103.46L735.74,105.28L733.48,105.53L733.35,108.26L731.84,109.49L726.44,108.60L724.47,113.47L717.69,115.16L720.14,119.89L718.27,120.60L718.49,122.15L715.44,120.78L705.90,120.72L702.02,119.57L700.48,120.14L700.06,121.74L693.78,121.19L693.18,122.38L688.02,124.78L686.83,126.73L685.82,126.75L685.07,125.46L681.61,125.37L681.06,123.14L679.73,123.12L679.93,120.39L676.67,118.40L668.81,119.01L666.21,116.56L659.26,113.34L652.25,114.95L652.36,124.99L650.96,125.12L647.22,122.22L642.92,123.70L642.92,120.95L639.77,120.02L636.94,116.00L639.59,116.26L639.70,114.27L644.39,114.23L644.39,109.89L639.36,109.36L633.66,111.13L632.28,110.69L632.56,109.29L630.82,107.47L628.80,107.55L626.49,105.70L629.44,100.09L632.24,101.67L632.58,99.68L638.20,96.72L642.45,96.65L651.67,99.64L654.56,98.49L658.88,98.43L662.36,99.84L663.15,99.04L666.97,99.15L667.66,97.86L663.24,95.99L665.86,94.67L665.35,93.92L667.96,93.22L666.00,91.35L667.24,90.42L677.43,89.47L688.02,86.67L692.91,87.25L693.77,90.08L696.61,89.41L700.11,90.34L699.88,91.83L702.49,91.67L709.31,89.10L708.32,89.96L711.79,92.06L717.87,98.97L719.33,97.55L723.08,99.12L726.99,98.42L732.86,102.16L736.37,101.80L737.81,103.46Z"/>
    <path id="UZ" class="country" data-iso2="UZ" data-iso3="UZB" data-name="Uzbekistan" d="M652.36,124.99L652.25,114.95L659.26,113.34L666.21,116.56L668.81,119.01L676.67,118.40L679.93,120.39L679.73,123.12L681.06,123.14L681.61,125.37L685.07,125.46L685.82,126.75L686.83,126.73L688.02,124.78L693.18,122.38L693.98,122.65L691.70,124.41L693.71,125.44L695.65,124.76L698.87,126.19L695.39,128.15L692.19,127.96L692.37,125.94L688.73,126.57L686.57,129.82L684.30,129.69L683.59,130.89L685.59,131.54L686.18,133.57L684.65,136.32L681.08,135.73L681.15,134.06L674.69,131.57L669.80,128.40L668.46,125.60L664.60,125.23L663.56,124.67L663.27,122.50L659.60,121.06L654.98,123.58L655.43,124.95L652.36,124.99Z"/>
    <path id="PG" class="country" data-iso2="PG" data-iso3="PNG" data-name="Papua New Guinea" d="M883.83,244.52L893.59,247.95L896.98,250.71L897.40,252.32L901.93,254.00L902.59,255.44L900.09,255.74L900.69,257.55L903.12,259.34L904.89,262.22L906.45,262.13L906.34,263.34L910.52,265.46L910.21,266.25L902.65,265.02L898.99,261.78L897.58,259.40L894.03,258.21L890.06,259.89L890.40,261.89L888.27,262.83L883.93,262.26L883.83,244.52ZM915.52,247.40L916.88,249.69L916.03,250.41L914.88,247.76L910.14,244.90L910.89,244.24L915.52,247.40ZM911.88,253.34L907.54,254.63L903.76,253.08L903.98,252.24L907.91,252.43L908.71,251.05L908.98,252.50L910.53,252.29L912.82,250.39L912.52,248.78L914.15,248.73L914.65,250.69L913.73,252.35L911.88,253.34ZM921.29,251.98L924.72,255.24L924.34,256.00L922.40,255.23L920.62,251.43L921.29,251.98Z"/>
    <path id="ID" class="country" data-iso2="ID" data-iso3="IDN" data-name="Indonesia" d="M883.83,244.52L883.93,262.26L881.50,260.03L878.74,259.48L878.07,260.25L874.62,260.34L875.77,258.12L877.49,257.37L875.47,252.12L867.95,249.59L863.86,247.07L862.01,248.64L861.39,246.45L859.31,245.12L864.18,244.19L863.95,243.47L859.97,243.46L858.89,241.84L856.46,241.34L855.30,239.99L860.37,238.45L864.74,239.56L865.93,244.98L868.75,246.61L871.02,243.72L874.14,242.08L876.56,242.07L883.83,244.52ZM840.19,261.65L840.52,263.01L838.74,265.04L836.09,265.31L837.50,262.73L840.19,261.65ZM865.35,256.21L865.08,254.16L866.14,252.26L866.75,254.36L865.35,256.21ZM820.90,226.18L819.35,228.63L821.35,231.21L820.88,232.46L823.94,234.98L820.71,235.30L819.80,237.16L819.92,239.63L817.30,241.49L816.18,248.36L815.78,247.39L812.69,248.62L811.61,246.96L808.31,245.93L805.07,246.91L804.08,245.59L800.05,245.43L799.64,241.78L796.97,238.69L796.59,236.31L796.91,233.79L798.53,231.98L798.98,233.80L800.84,235.33L804.34,234.98L807.23,233.36L809.80,234.12L812.02,233.54L815.41,225.72L820.90,226.18ZM852.18,245.07L855.17,245.86L856.16,247.94L853.86,246.82L848.17,246.68L848.81,245.18L852.18,245.07ZM845.38,247.76L843.50,247.26L842.97,246.09L845.72,245.96L846.40,246.86L845.38,247.76ZM848.26,231.52L848.46,233.01L850.06,233.24L850.32,234.36L850.18,236.74L848.77,236.47L848.36,238.13L849.48,239.56L848.72,239.89L846.81,234.68L848.26,231.52ZM834.64,235.06L837.77,234.94L840.46,232.97L840.93,233.57L838.75,236.27L836.70,236.80L827.17,236.79L826.78,238.85L829.21,241.27L830.68,240.04L835.76,239.12L835.54,240.37L834.35,239.97L833.17,241.57L830.77,242.62L833.35,246.11L832.85,247.05L835.30,250.19L835.28,251.98L833.82,252.78L832.75,251.82L834.07,249.59L831.40,250.65L830.72,249.89L831.07,248.84L829.11,247.24L829.31,244.59L827.50,245.42L827.84,252.49L826.11,252.88L824.94,252.08L825.72,249.58L825.30,246.95L824.16,246.93L823.31,245.07L826.19,237.02L829.08,233.88L834.64,235.06ZM827.47,265.37L823.86,263.46L826.40,262.92L828.78,264.58L828.61,265.31L827.47,265.37ZM830.32,260.68L832.13,260.47L834.57,259.47L834.17,260.99L826.46,261.42L826.45,260.43L828.61,259.86L830.32,260.68ZM821.93,260.20L823.61,259.98L824.29,261.14L817.79,262.03L818.73,260.46L820.22,260.44L820.95,259.48L821.93,260.20ZM795.33,254.92L795.70,255.89L800.91,256.16L801.51,255.04L806.56,256.35L807.55,258.11L811.64,258.61L814.98,260.23L811.87,261.26L808.88,260.17L794.76,258.58L789.79,257.46L789.32,256.29L786.83,256.09L788.70,253.49L795.33,254.92ZM784.12,240.39L785.53,243.81L787.53,244.05L788.85,245.77L788.06,253.37L785.04,253.43L779.26,248.93L770.22,236.94L768.41,232.48L759.65,223.91L759.41,222.52L765.38,223.16L773.97,231.72L776.74,231.77L779.02,233.63L780.60,235.91L782.67,237.15L781.58,239.38L784.12,240.39Z"/>
    <path id="AR" class="country" data-iso2="AR" data-iso3="ARG" data-name="Argentina" d="M313.16,380.73L315.57,384.03L322.92,386.34L321.69,387.71L319.11,387.84L317.72,386.88L313.16,386.81L313.16,380.73ZM343.13,319.69L340.76,331.17L344.22,333.50L343.85,335.38L345.55,336.56L345.41,337.89L342.79,341.38L338.76,342.84L330.31,343.14L330.82,348.17L329.19,349.13L326.40,349.50L323.78,348.51L322.73,349.23L323.11,351.93L324.95,352.75L326.44,351.89L327.25,353.31L322.56,355.84L321.52,360.04L318.95,360.05L316.81,361.44L316.03,363.48L318.71,365.48L321.31,366.03L320.37,368.47L317.16,370.00L315.39,373.20L311.79,375.54L312.67,378.37L314.48,379.95L304.23,379.02L303.10,377.43L303.16,375.39L301.34,375.57L300.38,374.58L300.15,371.69L302.24,370.50L303.10,368.77L302.78,367.39L305.22,361.47L304.93,359.87L306.12,359.35L304.56,357.78L305.46,356.64L304.23,355.61L303.59,352.47L304.69,351.91L304.23,348.59L305.60,343.38L307.23,342.39L306.39,337.23L308.45,335.45L308.39,333.18L309.94,330.52L309.95,328.02L307.99,322.82L309.66,320.02L309.41,317.39L310.38,314.91L314.08,310.67L313.27,309.60L313.75,304.18L316.72,302.84L317.32,299.33L319.59,296.87L323.15,297.53L324.75,299.50L325.81,297.31L328.92,297.42L334.36,302.45L342.72,305.94L343.11,307.14L340.43,311.28L346.23,312.43L348.38,311.99L350.85,309.91L351.30,307.51L352.65,306.99L354.01,308.56L353.96,310.73L349.84,313.34L343.13,319.69Z"/>
    <path id="CL" class="country" data-iso2="CL" data-iso3="CHL" data-name="Chile" d="M313.16,380.73L313.16,386.81L317.72,386.88L314.48,388.83L306.71,387.31L300.50,384.32L296.75,381.27L306.43,384.64L308.72,381.53L311.23,380.41L313.16,380.73ZM310.56,285.30L312.26,289.11L313.69,290.26L312.83,292.90L315.36,299.70L317.32,299.33L317.65,300.01L316.72,302.84L313.75,304.18L313.27,309.60L314.08,310.67L310.38,314.91L309.41,317.39L309.66,320.02L307.99,322.82L309.95,328.02L309.94,330.52L308.39,333.18L308.45,335.45L306.39,337.23L307.23,342.39L305.60,343.38L304.23,348.59L304.69,351.91L303.59,352.47L304.23,355.61L305.46,356.64L304.56,357.78L306.12,359.35L304.93,359.87L305.22,361.47L302.78,367.39L303.10,368.77L302.24,370.50L300.15,371.69L300.38,374.58L301.34,375.57L303.16,375.39L303.10,377.43L304.23,379.02L313.33,379.81L310.91,379.79L307.14,381.44L306.70,383.99L305.55,384.05L295.98,379.71L294.18,369.94L295.34,367.32L298.21,365.22L294.08,364.42L296.67,362.02L297.60,357.50L300.62,358.46L302.05,352.82L300.22,352.09L299.37,355.49L297.65,355.11L299.43,346.17L300.69,344.31L299.68,338.59L300.82,338.50L305.53,325.69L304.90,321.61L305.71,319.37L305.39,316.01L306.98,312.68L309.20,295.68L308.43,287.39L310.56,285.30Z"/>
    <path id="CD" class="country" data-iso2="CD" data-iso3="COD" data-name="Dem. Rep. Congo" d="M579.87,249.69L580.63,255.19L582.21,256.71L583.68,260.14L578.22,260.65L577.45,262.39L578.06,263.59L577.24,269.54L579.87,271.09L580.62,270.59L580.85,273.53L578.77,273.51L576.64,270.85L574.56,270.47L573.95,269.04L572.28,269.90L570.10,269.52L569.19,268.28L566.19,268.10L566.03,267.25L560.31,267.61L559.15,257.29L555.85,257.31L556.08,256.33L554.69,256.34L552.86,256.92L551.77,259.18L547.57,259.40L544.44,253.44L533.54,254.04L533.16,253.20L534.39,251.03L537.02,249.69L538.51,249.72L539.70,250.97L543.57,247.06L543.48,244.82L544.66,242.18L548.02,238.60L550.48,226.00L553.00,223.74L560.99,226.47L562.18,224.62L563.42,224.89L566.45,223.53L568.41,224.03L569.83,223.13L574.52,223.19L576.17,225.44L577.39,225.77L580.89,224.91L583.94,227.89L583.77,231.07L584.86,231.44L581.33,235.81L579.01,245.17L579.87,249.69Z"/>
    <path id="SO" class="country" data-iso2="SO" data-iso3="SOM" data-name="Somalia" d="M613.20,242.02L611.59,239.78L611.56,229.86L614.68,225.91L616.43,225.86L618.85,223.94L622.40,223.82L633.22,211.71L633.25,206.38L639.14,204.71L638.96,208.47L637.61,212.40L632.29,222.90L626.76,229.67L617.43,236.64L613.20,242.02Z"/>
    <path id="KE" class="country" data-iso2="KE" data-iso3="KEN" data-name="Kenya" d="M606.72,250.17L602.81,247.45L602.62,245.87L592.29,240.03L592.27,237.14L595.38,232.25L592.57,225.87L596.09,222.45L597.50,222.91L597.50,224.44L598.43,225.33L600.33,225.33L603.77,227.64L607.69,228.12L610.98,225.85L612.08,226.77L613.94,226.77L611.56,229.86L611.59,239.78L613.20,242.02L609.60,244.44L607.81,249.27L606.72,250.17Z"/>
    <path id="SD" class="country" data-iso2="SD" data-iso3="SDN" data-name="Sudan" d="M566.88,215.04L564.80,213.85L563.86,213.06L564.12,209.97L562.55,208.27L560.67,203.01L559.72,203.17L561.28,199.07L560.72,198.44L562.68,194.75L565.03,194.94L564.93,182.99L568.06,182.99L568.06,177.55L600.36,177.55L602.03,186.77L604.56,188.44L600.32,191.28L598.74,200.52L594.55,207.74L593.26,208.50L592.49,213.80L591.80,209.33L590.40,208.26L590.40,204.28L589.13,204.10L587.31,204.85L588.20,207.28L585.35,210.73L583.95,211.01L581.66,209.42L578.85,211.86L572.82,211.67L570.21,209.10L568.25,209.47L566.80,213.16L565.03,213.97L566.88,215.04Z"/>
    <path id="TD" class="country" data-iso2="TD" data-iso3="TCD" data-name="Chad" d="M564.89,184.14L565.03,194.94L562.68,194.75L560.72,198.44L561.28,199.07L559.72,203.17L560.67,203.01L562.24,207.11L559.14,208.67L557.17,211.64L554.61,212.90L551.21,212.99L551.48,213.94L548.90,215.96L541.59,217.23L542.02,216.50L540.78,213.49L537.99,211.44L538.58,210.16L542.11,210.26L540.63,207.79L539.73,201.15L537.99,201.09L537.99,199.34L536.86,198.33L538.04,194.74L541.51,192.18L543.29,181.94L541.10,179.43L540.43,175.20L543.18,173.71L564.89,184.14Z"/>
    <path id="HT" class="country" data-iso2="HT" data-iso3="HTI" data-name="Haiti" d="M304.78,183.77L304.81,186.30L304.15,186.76L304.79,188.32L298.77,188.35L297.31,187.51L297.55,186.63L302.11,187.23L303.09,186.62L301.87,184.40L300.15,183.98L300.76,183.22L304.78,183.77Z"/>
    <path id="DO" class="country" data-iso2="DO" data-iso3="DOM" data-name="Dominican Rep." d="M304.79,188.32L304.15,186.76L305.12,183.31L309.58,183.95L310.07,184.92L311.56,184.86L311.47,185.68L314.02,186.77L313.01,187.88L309.57,187.27L308.04,187.94L307.62,187.28L305.63,189.53L304.79,188.32Z"/>
    <path id="RU" class="country" data-iso2="RU" data-iso3="RUS" data-name="Russia" d="M986.53,43.89L990.00,42.76L990.00,44.62L987.01,44.76L986.53,43.89ZM633.66,111.13L632.42,112.74L629.78,113.19L627.08,116.00L629.55,118.59L629.29,120.42L632.26,123.63L630.16,125.42L624.61,122.85L623.78,121.74L619.59,121.60L615.41,119.78L608.77,119.20L599.84,114.27L601.82,113.84L604.08,111.56L602.56,110.48L606.57,109.37L606.50,108.78L604.05,109.22L604.14,108.01L608.18,107.05L608.00,104.64L609.08,102.41L603.47,101.56L601.79,100.28L599.70,100.71L596.25,99.76L595.34,98.04L593.17,97.91L593.62,96.51L591.88,94.97L586.53,95.61L585.22,92.96L589.00,92.20L586.38,91.00L583.73,88.23L584.05,86.22L579.96,85.89L576.70,84.53L575.60,81.61L574.28,80.98L575.45,80.12L574.64,77.58L576.58,76.01L576.17,75.53L579.26,74.03L576.41,72.74L584.77,67.69L585.79,66.30L581.76,64.43L582.88,62.66L580.43,60.63L582.26,58.30L579.09,55.20L581.61,53.15L577.44,51.34L577.83,49.43L587.47,47.14L591.94,48.79L599.40,49.43L611.77,53.81L611.95,55.62L604.49,57.77L592.33,55.70L590.34,56.05L594.77,58.04L595.13,62.09L600.76,63.63L601.11,62.31L599.47,61.14L601.20,60.10L607.78,61.80L610.07,61.14L608.24,59.14L614.59,56.48L619.64,57.58L621.23,55.71L618.96,54.09L620.29,52.46L618.29,50.77L625.90,51.65L627.46,53.17L624.01,53.51L624.03,55.02L626.17,55.95L630.38,55.36L631.04,53.63L646.23,49.99L648.28,50.13L645.60,51.78L648.98,52.06L650.93,51.13L656.03,51.06L660.07,49.93L663.17,51.57L666.27,49.77L663.41,48.19L664.83,47.29L672.87,48.12L686.51,52.08L688.33,50.65L685.48,48.64L682.20,48.37L683.10,47.08L681.56,44.08L686.58,41.62L688.37,39.14L690.39,38.61L697.60,39.33L698.17,40.84L695.59,43.05L697.28,43.92L698.16,45.82L697.54,49.55L700.54,51.22L699.37,53.03L694.04,56.90L697.15,57.30L701.23,55.62L701.95,54.28L704.31,52.98L702.72,51.43L703.99,49.64L701.02,49.41L700.36,47.90L702.53,45.16L699.00,42.94L703.87,41.11L703.24,39.17L704.60,39.11L706.03,40.62L704.95,43.25L707.87,43.75L706.63,41.78L711.18,40.71L716.83,40.57L721.86,42.12L719.44,39.85L719.17,36.95L736.35,36.17L734.14,34.74L737.29,32.96L752.90,31.17L753.80,30.42L763.18,30.78L769.29,29.33L774.29,29.38L777.64,27.05L784.07,25.93L788.74,26.81L785.03,27.48L791.20,27.90L791.93,29.24L802.38,28.62L810.70,30.96L810.02,32.38L797.81,35.50L805.21,36.57L807.66,36.06L809.05,37.80L814.60,36.67L823.34,37.12L824.00,38.39L835.38,38.80L835.54,36.72L845.66,37.18L850.05,38.61L851.31,40.35L849.70,41.49L853.12,43.64L857.40,44.74L860.02,41.88L864.39,43.11L869.03,42.38L874.30,43.21L876.30,42.45L880.76,42.83L878.79,40.31L882.39,39.13L906.97,40.89L909.29,42.51L916.42,44.59L932.83,44.52L935.09,45.65L934.76,47.64L938.12,48.42L956.89,48.02L961.63,50.44L965.00,49.57L962.80,47.83L964.01,46.62L978.36,47.22L990.00,49.70L990.00,60.55L986.48,61.76L982.95,61.56L988.29,65.99L987.90,67.83L982.83,67.24L972.80,69.61L964.68,73.19L963.68,74.43L959.78,72.54L952.69,74.68L951.45,73.67L948.83,74.84L945.19,74.46L944.31,76.25L941.05,78.89L941.14,79.99L944.24,80.60L943.88,84.56L941.35,84.66L940.19,86.94L941.32,88.11L936.56,89.50L935.61,92.61L931.56,93.27L930.74,96.04L926.82,98.58L923.12,86.68L924.43,82.90L926.73,81.28L926.87,80.01L931.10,79.40L940.65,73.17L945.55,71.00L947.73,67.16L944.43,67.39L942.79,69.63L935.89,72.62L933.66,69.28L926.63,70.20L919.82,74.76L922.06,76.43L911.78,77.42L911.98,75.46L907.74,75.04L904.37,76.38L896.05,75.91L887.09,76.72L867.84,88.45L872.13,88.80L873.47,90.50L876.12,91.11L877.86,89.75L880.84,89.92L884.77,92.92L884.87,95.23L882.74,97.95L881.28,105.56L876.26,111.38L867.14,119.30L863.52,120.90L861.80,120.93L860.09,119.61L856.01,122.51L855.61,120.65L857.00,120.57L857.40,117.36L856.68,115.03L859.02,114.06L862.32,114.55L867.57,105.47L860.71,107.35L856.58,107.34L855.47,104.79L852.25,102.85L847.51,101.98L842.85,93.73L836.39,91.91L829.40,92.48L827.15,93.83L828.64,94.48L828.68,95.98L824.71,99.74L824.73,100.94L820.89,102.66L817.63,101.63L814.38,101.86L811.32,100.65L807.33,102.57L801.25,103.70L795.29,103.28L790.98,100.58L782.23,101.08L778.36,99.94L777.84,97.90L769.12,95.75L766.30,98.58L767.41,100.18L764.76,102.07L758.11,101.29L756.29,100.02L751.08,99.14L741.75,102.77L737.81,103.46L736.37,101.80L732.86,102.16L726.99,98.42L723.08,99.12L719.33,97.55L717.87,98.97L711.79,92.06L708.32,89.96L709.31,89.10L702.49,91.67L699.88,91.83L700.11,90.34L696.61,89.41L693.77,90.08L692.91,87.25L688.02,86.67L677.43,89.47L667.24,90.42L666.00,91.35L667.96,93.22L665.35,93.92L665.86,94.67L663.24,95.99L667.66,97.86L666.97,99.15L663.15,99.04L662.36,99.84L658.88,98.43L654.56,98.49L651.67,99.64L642.45,96.65L638.20,96.72L632.58,99.68L632.24,101.67L629.44,100.09L626.49,105.70L628.80,107.55L630.82,107.47L632.56,109.29L632.28,110.69L633.66,111.13ZM755.28,16.87L761.17,16.26L772.73,20.26L772.06,22.71L766.12,23.05L754.02,21.22L751.93,19.27L748.22,18.73L755.28,16.87ZM779.95,21.62L786.85,23.16L786.04,24.27L770.69,25.32L775.67,21.75L779.95,21.62ZM877.93,30.18L885.12,30.30L894.96,31.74L892.82,33.76L878.27,34.33L872.87,32.56L874.34,30.69L877.93,30.18ZM903.49,32.33L910.33,33.04L907.18,34.12L897.77,32.80L898.42,31.92L903.49,32.33ZM880.74,37.71L886.72,36.38L890.92,38.14L886.79,38.16L880.74,37.71ZM622.08,18.06L631.53,17.53L632.09,18.26L636.22,17.16L640.26,17.76L629.54,19.63L626.59,18.99L628.14,18.14L622.08,18.06ZM561.88,89.55L556.87,89.59L553.52,89.28L554.14,88.08L557.90,87.20L561.95,88.11L561.88,89.55ZM645.66,36.68L652.18,34.29L651.44,33.05L666.52,29.86L685.54,27.99L687.43,29.07L667.64,32.56L659.19,35.15L650.86,40.43L651.42,42.69L656.62,44.92L646.12,44.81L645.40,43.60L640.47,42.87L640.07,41.40L642.86,40.81L642.76,39.33L648.16,37.01L645.66,36.68ZM889.05,91.24L889.92,96.55L893.78,104.11L889.75,103.22L888.08,107.15L890.73,109.94L890.65,111.84L888.59,110.20L886.81,112.31L886.30,104.43L887.05,98.74L885.45,96.06L885.69,92.34L888.21,91.09L887.13,89.83L888.34,89.44L889.05,91.24ZM23.81,54.49L23.57,56.18L25.41,56.86L24.78,54.88L32.17,55.29L37.50,57.83L34.80,59.02L30.33,59.30L30.27,61.96L29.18,62.53L20.93,60.70L20.32,59.52L14.46,59.43L12.99,58.48L13.58,57.47L10.32,58.11L11.54,59.39L10.00,60.55L10.00,49.70L23.81,54.49ZM13.56,44.45L10.00,44.62L10.00,42.76L16.59,43.43L13.56,44.45ZM591.02,112.29L591.74,111.62L596.67,113.82L599.44,113.66L598.91,114.63L592.24,116.68L590.72,116.12L591.32,114.84L588.35,114.05L591.02,112.29Z"/>
    <path id="BS" class="country" data-iso2="BS" data-iso3="BHS" data-name="Bahamas" d="M285.00,164.51L288.07,164.37L288.16,165.08L285.19,165.52L285.00,164.51ZM288.24,163.83L290.39,165.06L289.92,166.99L289.46,165.22L288.24,163.83ZM287.15,168.81L287.97,168.92L288.93,172.76L288.27,172.90L286.55,170.54L287.15,168.81Z"/>
    <path id="FK" class="country" data-iso2="FK" data-iso3="FLK" data-name="Falkland Is." d="M333.40,378.59L336.67,376.95L338.98,377.63L340.61,376.54L342.79,377.77L341.97,378.72L338.30,379.54L337.07,378.59L334.76,379.81L333.40,378.59Z"/>
    <path id="NO" class="country" data-iso2="NO" data-iso3="NOR" data-name="Norway" d="M541.22,20.55L542.26,19.62L546.25,19.52L558.65,22.50L551.80,23.57L550.28,25.58L547.90,26.09L546.60,28.35L543.32,28.45L537.46,26.79L539.93,25.83L530.55,22.74L528.43,20.61L535.85,19.63L537.34,20.59L541.22,20.55ZM584.66,48.09L577.83,49.43L578.99,47.52L575.49,46.44L571.27,47.36L569.93,49.35L567.34,50.56L560.86,50.04L557.83,48.60L554.51,49.43L554.11,51.22L548.98,50.78L548.26,52.30L545.65,52.29L536.90,61.07L537.89,62.00L536.95,63.08L534.25,63.04L532.48,65.59L532.65,69.20L534.38,70.58L533.48,73.78L530.02,77.22L528.19,75.55L522.82,78.70L519.19,79.34L515.42,77.95L513.59,68.74L516.10,66.99L523.28,64.70L528.66,61.89L540.18,52.84L552.22,47.38L558.20,46.19L562.68,46.33L566.82,44.08L576.67,43.66L585.19,45.65L581.68,46.38L584.66,48.09ZM574.61,19.51L570.57,20.97L562.68,21.29L554.65,20.84L554.16,20.09L550.26,20.04L547.28,18.79L555.69,18.03L559.64,18.69L562.39,17.87L574.61,19.51ZM567.30,25.50L561.22,26.62L556.42,25.98L558.30,25.28L556.65,24.41L562.30,23.87L563.38,24.89L567.30,25.50Z"/>
    <path id="GL" class="country" data-iso2="GL" data-iso3="GRL" data-name="Greenland" d="M372.70,12.51L381.84,10.88L391.39,11.00L394.86,10.00L426.23,10.08L443.25,12.24L438.23,13.29L413.16,13.67L432.37,14.80L437.65,13.96L439.92,14.94L436.93,16.52L457.08,14.46L465.24,14.98L466.77,16.15L454.13,18.71L445.43,19.18L451.73,19.31L446.36,23.06L446.44,26.09L449.71,27.87L440.98,28.84L446.01,30.28L446.65,32.60L443.74,32.85L447.26,35.19L441.22,35.39L444.37,36.49L443.48,37.45L435.85,37.88L439.26,39.73L439.30,40.94L433.91,39.81L432.51,40.54L439.75,42.88L440.78,45.08L435.93,45.60L430.47,42.99L431.40,44.84L428.23,46.27L439.16,46.53L424.47,51.05L413.50,52.00L406.89,55.92L401.04,57.83L391.62,59.25L389.29,60.93L389.25,62.84L387.88,64.63L383.44,66.80L384.53,68.93L381.91,73.84L378.08,74.01L374.06,71.78L368.62,71.77L359.44,64.23L358.06,62.46L357.69,60.01L353.92,57.50L354.90,55.50L353.08,54.54L355.78,51.35L359.87,50.34L361.52,47.08L354.48,48.83L351.14,47.95L350.96,46.10L352.02,44.65L360.10,45.33L352.99,42.67L348.01,42.38L351.04,39.84L343.95,34.06L340.49,33.00L340.52,31.86L333.21,30.27L313.52,30.38L305.63,27.80L318.25,26.80L300.47,24.99L300.84,23.93L321.12,21.31L322.17,20.32L314.83,19.34L317.20,18.26L330.58,16.06L329.45,14.84L344.27,13.70L352.63,13.67L355.60,14.52L362.83,13.02L378.80,15.14L372.33,13.67L372.70,12.51Z"/>
    <path id="TF" class="country" data-iso2="TF" data-iso3="ATF" data-name="Fr. S. Antarctic Lands" d="M687.66,369.81L691.98,371.00L692.08,371.52L691.32,372.76L687.14,372.94L687.66,369.81Z"/>
    <path id="TL" class="country" data-iso2="TL" data-iso3="TLS" data-name="Timor-Leste" d="M840.19,261.65L842.86,260.39L846.64,260.30L840.52,263.01L840.19,261.65Z"/>
    <path id="ZA" class="country" data-iso2="ZA" data-iso3="ZAF" data-name="South Africa" d="M544.49,315.23L545.80,313.88L547.33,315.79L550.27,316.51L554.16,314.92L554.16,304.86L556.51,307.86L556.87,310.47L558.82,310.19L563.46,306.23L565.91,307.32L569.86,306.82L570.62,304.67L572.10,304.45L573.83,301.61L580.12,297.58L584.91,298.01L586.92,303.78L586.67,307.79L584.51,307.49L583.53,310.24L585.16,311.72L586.75,311.42L587.31,310.21L589.37,310.24L587.66,315.71L576.82,326.65L570.18,329.84L561.45,329.62L554.64,332.16L550.03,330.37L548.80,326.21L549.67,325.72L549.60,323.63L544.49,315.23ZM578.89,316.26L577.70,315.42L576.42,315.98L573.50,318.77L575.54,320.86L576.51,320.59L578.53,319.30L579.83,317.08L578.89,316.26Z"/>
    <path id="LS" class="country" data-iso2="LS" data-iso3="LSO" data-name="Lesotho" d="M578.89,316.26L579.83,317.08L578.53,319.30L576.51,320.59L575.54,320.86L573.50,318.77L576.42,315.98L577.70,315.42L578.89,316.26Z"/>
    <path id="MX" class="country" data-iso2="MX" data-iso3="MEX" data-name="Mexico" d="M181.15,148.87L187.70,148.37L187.45,148.90L197.77,152.14L205.34,152.12L205.35,151.00L210.06,151.00L214.06,154.02L215.64,156.94L217.05,157.76L219.31,158.58L221.03,156.43L223.25,156.37L225.17,157.46L229.08,162.47L230.45,165.65L235.56,167.02L234.03,171.36L233.57,176.34L235.43,181.26L238.94,186.19L241.83,186.91L242.95,188.05L251.17,186.05L252.90,184.94L254.24,180.27L263.03,178.79L263.59,180.68L261.48,183.96L261.98,184.43L260.89,187.73L259.11,187.11L258.14,188.76L252.27,188.94L252.27,190.47L251.04,190.47L253.81,192.77L253.74,193.69L250.24,193.70L248.93,195.92L248.94,197.86L244.45,194.05L242.23,193.34L237.15,194.83L225.52,190.70L222.56,188.67L218.25,187.64L212.82,183.14L212.18,181.81L213.08,181.55L213.44,179.12L211.37,175.44L204.91,168.91L202.57,167.80L202.48,165.46L199.49,163.50L198.81,161.60L197.35,161.38L194.49,158.62L191.98,152.58L187.55,150.87L187.12,151.98L187.83,155.33L196.16,164.86L198.77,171.29L200.09,171.38L202.16,173.84L200.95,175.32L197.97,172.10L194.62,170.10L194.29,166.63L186.79,161.97L188.11,161.92L189.23,159.68L185.53,156.98L181.15,148.87Z"/>
    <path id="UY" class="country" data-iso2="UY" data-iso3="URY" data-name="Uruguay" d="M343.13,319.69L344.90,319.40L353.58,324.68L355.15,326.53L353.95,327.82L354.71,329.36L353.53,331.07L350.45,332.59L346.97,332.34L342.61,331.25L340.95,329.75L343.13,319.69Z"/>
    <path id="BR" class="country" data-iso2="BR" data-iso3="BRA" data-name="Brazil" d="M354.71,329.36L353.95,327.82L355.15,326.53L353.58,324.68L344.90,319.40L343.13,319.69L349.84,313.34L353.96,310.73L354.01,308.56L352.65,306.99L351.30,307.51L352.20,302.83L349.19,302.66L348.11,298.30L342.28,297.57L342.46,293.88L341.66,292.36L342.51,291.80L342.25,290.25L343.48,286.91L342.83,285.22L341.35,284.46L341.45,281.81L336.24,281.70L335.19,278.53L335.98,278.48L335.30,274.94L332.00,274.16L327.97,271.81L324.92,271.36L321.96,268.93L322.13,264.01L318.57,264.47L314.15,267.42L307.95,267.41L308.13,263.27L305.90,264.88L303.50,264.81L302.47,263.36L300.66,263.20L301.24,262.03L298.59,257.92L299.31,256.27L300.95,255.49L301.57,251.80L307.28,249.01L309.73,249.14L311.02,240.50L309.39,237.94L309.40,235.97L311.48,235.80L311.57,234.76L309.98,234.47L309.94,232.77L315.25,232.83L316.15,231.89L317.43,234.36L319.45,235.47L321.56,235.29L327.50,231.45L325.04,230.64L324.77,227.10L323.56,226.40L328.25,227.17L334.03,225.09L335.03,224.05L334.67,223.28L336.72,223.79L336.36,224.99L337.92,226.66L336.74,229.94L337.63,232.57L339.30,233.85L340.64,233.99L343.92,232.13L347.57,232.49L347.63,230.61L355.89,231.65L359.38,226.12L360.30,226.00L362.50,232.26L363.96,232.71L364.03,234.59L361.99,236.83L362.83,237.65L367.64,238.08L367.74,240.81L369.81,239.02L377.76,241.66L379.09,243.26L378.64,244.77L381.80,243.93L387.10,245.37L391.17,245.26L398.67,250.56L403.09,251.46L404.08,252.32L405.46,257.43L404.37,261.93L394.72,272.98L393.11,286.08L391.76,290.79L389.00,294.35L388.54,297.16L386.34,298.34L385.70,299.97L378.46,301.01L370.29,305.18L367.98,307.88L368.04,311.42L366.91,315.50L354.71,329.36Z"/>
    <path id="BO" class="country" data-iso2="BO" data-iso3="BOL" data-name="Bolivia" d="M310.72,267.25L314.15,267.42L318.57,264.47L322.13,264.01L321.96,268.93L324.92,271.36L327.97,271.81L332.00,274.16L335.30,274.94L335.98,278.48L335.19,278.53L336.24,281.70L341.45,281.81L341.35,284.46L342.83,285.22L343.48,286.91L342.25,290.25L342.51,291.80L341.66,292.36L341.61,291.53L339.08,290.13L331.80,290.89L329.36,298.01L325.81,297.31L324.75,299.50L323.15,297.53L319.59,296.87L317.32,299.33L315.36,299.70L312.83,292.90L313.69,290.26L312.26,289.11L310.56,285.30L312.28,282.36L311.11,280.07L311.73,279.15L311.24,278.15L312.31,276.79L313.08,271.63L310.72,267.25Z"/>
    <path id="PE" class="country" data-iso2="PE" data-iso3="PER" data-name="Peru" d="M309.73,249.14L307.28,249.01L301.57,251.80L300.95,255.49L299.31,256.27L298.59,257.92L301.24,262.03L300.66,263.20L302.47,263.36L303.50,264.81L305.90,264.88L308.13,263.27L307.95,267.41L310.72,267.25L313.08,271.63L312.31,276.79L311.24,278.15L311.73,279.15L311.11,280.07L312.28,282.36L309.83,286.69L308.43,287.39L305.70,285.82L305.46,284.71L293.09,277.32L291.96,275.07L292.41,274.28L282.87,257.02L278.82,254.14L279.70,252.93L278.38,250.33L279.23,248.43L281.40,246.71L281.02,249.49L283.24,249.56L284.39,250.94L285.92,249.82L288.11,245.61L291.38,244.54L294.35,241.69L295.20,239.92L294.82,237.85L295.54,237.59L299.48,240.87L301.09,243.72L307.23,243.58L309.31,244.86L307.56,247.63L309.73,249.14Z"/>
    <path id="CO" class="country" data-iso2="CO" data-iso3="COL" data-name="Colombia" d="M317.95,234.03L317.43,234.36L316.15,231.89L315.25,232.83L309.94,232.77L309.98,234.47L311.57,234.76L311.48,235.80L309.40,235.97L309.39,237.94L311.02,240.50L309.73,249.14L307.56,247.63L309.31,244.86L307.23,243.58L301.09,243.72L299.48,240.87L295.54,237.59L292.32,236.31L289.23,236.36L284.97,232.83L285.98,232.63L286.50,230.28L287.85,230.10L290.04,226.96L289.04,226.31L289.52,221.53L287.99,217.77L288.34,216.45L289.73,215.84L289.10,214.23L294.00,211.73L294.53,208.53L296.09,207.27L300.15,206.88L304.67,203.58L305.63,203.75L306.35,204.46L305.82,205.38L304.07,205.84L301.54,208.99L300.45,212.53L301.85,212.71L302.80,214.56L302.79,217.23L304.11,218.41L309.19,218.49L311.11,220.83L316.68,220.85L315.37,225.18L316.79,228.41L315.41,229.76L317.12,231.31L317.95,234.03Z"/>
    <path id="PA" class="country" data-iso2="PA" data-iso3="PAN" data-name="Panama" d="M289.43,213.84L289.73,215.84L288.34,216.45L287.99,217.77L286.50,215.52L287.17,214.79L284.62,212.95L281.18,214.85L282.21,216.89L279.81,217.78L279.34,216.16L278.09,216.46L277.54,215.36L274.55,214.87L274.46,215.46L274.24,211.64L275.29,211.40L276.21,212.95L278.30,213.52L283.38,211.27L284.89,211.43L289.43,213.84Z"/>
    <path id="CR" class="country" data-iso2="CR" data-iso3="CRI" data-name="Costa Rica" d="M275.29,211.40L274.24,211.64L274.82,213.14L274.15,215.05L272.67,214.44L272.33,212.80L268.68,209.98L268.31,211.42L266.81,210.40L266.82,208.16L266.05,207.78L267.08,206.90L271.62,208.24L272.27,207.66L275.29,211.40Z"/>
    <path id="NI" class="country" data-iso2="NI" data-iso3="NIC" data-name="Nicaragua" d="M272.27,207.66L271.62,208.24L266.67,207.25L261.35,202.30L263.89,201.33L263.83,200.00L265.63,199.22L266.43,199.77L268.82,197.18L270.11,197.64L273.65,196.62L271.73,206.48L272.27,207.66Z"/>
    <path id="HN" class="country" data-iso2="HN" data-iso3="HND" data-name="Honduras" d="M273.65,196.62L270.11,197.64L268.82,197.18L266.43,199.77L265.63,199.22L263.83,200.00L263.89,201.33L262.30,202.09L261.01,201.00L260.83,199.62L259.07,199.75L256.76,198.17L257.30,196.42L260.71,194.25L268.66,193.89L273.65,196.62Z"/>
    <path id="SV" class="country" data-iso2="SV" data-iso3="SLV" data-name="El Salvador" d="M256.76,198.17L259.07,199.75L261.20,199.91L260.71,201.64L254.74,200.05L256.76,198.17Z"/>
    <path id="GT" class="country" data-iso2="GT" data-iso3="GTM" data-name="Guatemala" d="M248.94,197.86L248.93,195.92L250.24,193.70L253.74,193.69L253.81,192.77L251.04,190.47L252.27,190.47L252.27,188.94L257.33,188.96L257.10,194.19L259.83,194.62L257.30,196.42L256.76,198.17L254.74,200.05L251.65,199.52L248.94,197.86Z"/>
    <path id="BZ" class="country" data-iso2="BZ" data-iso3="BLZ" data-name="Belize" d="M257.33,188.96L259.11,187.11L260.15,187.49L259.48,192.44L257.91,194.19L257.10,194.19L257.33,188.96Z"/>
    <path id="VE" class="country" data-iso2="VE" data-iso3="VEN" data-name="Venezuela" d="M334.67,223.28L335.03,224.05L334.03,225.09L328.25,227.17L323.56,226.40L324.77,227.10L325.04,230.64L327.50,231.45L321.56,235.29L319.45,235.47L315.41,229.76L316.79,228.41L315.37,225.18L316.68,220.85L311.11,220.83L309.19,218.49L304.11,218.41L302.79,217.23L302.80,214.56L301.85,212.71L300.45,212.53L301.54,208.99L304.07,205.84L305.82,205.38L304.14,206.34L305.00,209.00L303.80,210.58L304.83,212.74L306.00,212.57L306.61,210.60L305.63,207.58L309.02,206.47L308.64,205.19L309.60,204.33L310.58,206.24L312.49,206.29L314.36,208.71L319.71,208.45L323.35,210.01L324.91,208.47L331.55,208.27L329.23,209.07L330.16,210.36L332.34,210.56L334.41,211.90L334.84,214.08L337.32,214.66L335.17,216.26L334.93,217.25L335.86,218.26L333.51,219.21L332.83,221.22L334.67,223.28Z"/>
    <path id="GY" class="country" data-iso2="GY" data-iso3="GUY" data-name="Guyana" d="M346.09,232.27L343.92,232.13L340.64,233.99L337.63,232.57L336.74,229.94L337.92,226.66L336.36,224.99L336.72,223.79L334.67,223.28L332.83,221.22L333.51,219.21L335.86,218.26L334.93,217.25L335.17,216.26L337.32,214.66L340.80,217.44L340.87,218.84L344.43,221.18L344.00,223.63L342.34,224.34L341.99,226.38L343.20,228.36L344.07,228.36L346.09,232.27Z"/>
    <path id="SR" class="country" data-iso2="SR" data-iso3="SUR" data-name="Suriname" d="M351.57,231.15L347.63,230.61L347.57,232.49L346.09,232.27L344.07,228.36L343.20,228.36L341.99,226.38L342.34,224.34L344.00,223.63L344.43,221.18L353.11,221.77L351.70,224.11L352.98,227.58L351.57,231.15Z"/>
    <path id="FR" class="country" data-iso2="FR" data-iso3="FRA" data-name="France" d="M359.38,226.12L355.89,231.65L351.57,231.15L352.98,227.58L351.70,224.11L353.11,221.77L356.04,222.71L359.38,226.12ZM516.84,102.79L522.05,104.00L520.33,107.81L518.34,108.02L516.44,110.24L516.39,111.47L517.69,111.05L518.63,112.24L519.32,114.03L518.37,114.86L519.08,116.97L520.55,117.31L520.24,118.49L517.77,120.03L512.41,119.30L508.44,120.18L508.13,121.82L504.97,122.17L501.91,120.94L500.92,121.53L495.91,120.29L494.82,119.23L496.23,117.60L496.75,112.18L491.93,107.94L487.77,106.90L487.50,104.91L491.03,104.32L495.60,105.02L494.74,101.94L497.31,103.10L503.64,100.98L504.46,98.75L506.84,98.20L507.24,99.16L508.50,99.20L511.67,101.58L516.84,102.79ZM523.81,121.40L525.56,120.36L526.02,122.69L525.13,124.79L523.89,124.24L523.26,122.41L523.81,121.40Z"/>
    <path id="EC" class="country" data-iso2="EC" data-iso3="ECU" data-name="Ecuador" d="M294.82,237.85L295.20,239.92L294.35,241.69L291.38,244.54L288.11,245.61L285.92,249.82L284.39,250.94L283.24,249.56L281.02,249.49L281.40,246.71L282.85,244.67L282.26,243.48L281.22,244.75L279.59,243.56L279.68,240.32L280.63,239.91L281.98,235.35L285.34,233.68L288.57,235.19L289.23,236.36L292.32,236.31L294.82,237.85Z"/>
    <path id="PR" class="country" data-iso2="PR" data-iso3="PRI" data-name="Puerto Rico" d="M319.56,187.04L321.45,187.82L320.75,188.50L317.11,188.58L317.34,187.02L319.56,187.04Z"/>
    <path id="JM" class="country" data-iso2="JM" data-iso3="JAM" data-name="Jamaica" d="M288.84,187.10L290.67,187.35L292.57,188.75L289.83,189.25L286.75,187.82L288.84,187.10Z"/>
    <path id="CU" class="country" data-iso2="CU" data-iso3="CUB" data-name="Cuba" d="M276.05,174.31L280.54,174.54L284.18,176.46L286.72,176.16L291.69,179.71L294.20,180.23L294.01,180.99L298.07,182.22L295.94,183.20L288.33,183.39L290.16,181.87L287.29,180.98L285.71,178.64L276.32,176.50L277.34,175.82L274.67,175.68L271.19,177.79L268.68,177.83L271.94,175.40L276.05,174.31Z"/>
    <path id="ZW" class="country" data-iso2="ZW" data-iso3="ZWE" data-name="Zimbabwe" d="M584.91,298.01L580.12,297.58L576.28,295.93L575.47,293.24L571.23,289.96L568.77,285.72L573.62,286.27L578.80,281.11L582.41,279.65L582.59,280.67L584.86,280.62L589.42,282.94L588.91,292.71L584.91,298.01Z"/>
    <path id="BW" class="country" data-iso2="BW" data-iso3="BWA" data-name="Botswana" d="M580.12,297.58L573.83,301.61L572.10,304.45L570.62,304.67L569.86,306.82L565.91,307.32L563.46,306.23L558.82,310.19L556.87,310.47L556.51,307.86L554.16,304.86L554.16,296.92L556.84,296.82L556.92,287.13L563.15,286.08L564.19,287.20L568.77,285.72L571.23,289.96L575.47,293.24L576.28,295.93L580.12,297.58Z"/>
    <path id="NA" class="country" data-iso2="NA" data-iso3="NAM" data-name="Namibia" d="M554.16,304.86L554.16,314.92L550.27,316.51L547.33,315.79L545.80,313.88L544.49,315.23L541.41,311.19L538.81,297.63L532.11,286.63L531.94,284.54L536.65,283.64L538.27,284.87L549.72,284.56L551.60,285.86L558.19,286.25L565.43,284.52L568.27,285.29L564.19,287.20L563.15,286.08L556.92,287.13L556.84,296.82L554.16,296.92L554.16,304.86Z"/>
    <path id="SN" class="country" data-iso2="SN" data-iso3="SEN" data-name="Senegal" d="M454.50,200.43L452.02,197.34L453.22,196.82L456.12,192.64L460.32,192.25L463.42,193.78L466.87,197.65L468.66,203.57L457.67,203.06L454.60,203.72L454.15,201.64L462.31,200.68L461.76,199.89L460.02,200.33L458.94,199.66L454.50,200.43Z"/>
    <path id="ML" class="country" data-iso2="ML" data-iso3="MLI" data-name="Mali" d="M468.66,203.57L466.87,197.65L468.24,195.55L471.01,196.24L474.00,195.28L484.93,195.24L485.53,193.33L482.43,169.50L486.60,169.45L504.96,181.33L505.61,182.61L508.57,183.83L508.60,185.56L511.62,185.29L511.62,191.56L509.90,195.06L503.77,195.72L502.77,196.69L497.10,196.68L491.55,200.58L489.09,200.76L485.79,205.55L485.29,209.21L483.53,209.95L483.11,208.79L481.35,209.84L478.14,209.65L477.45,208.06L476.53,208.01L477.20,206.42L475.15,203.93L472.33,205.20L469.96,204.20L468.81,204.56L468.66,203.57Z"/>
    <path id="MR" class="country" data-iso2="MR" data-iso3="MRT" data-name="Mauritania" d="M453.55,180.27L454.14,179.37L464.80,179.38L464.29,175.45L464.95,174.05L467.50,173.81L467.42,166.84L476.35,166.99L476.36,162.86L486.60,169.45L482.43,169.50L485.53,193.33L484.93,195.24L474.00,195.28L471.01,196.24L468.24,195.55L466.87,197.65L463.42,193.78L460.32,192.25L456.12,192.64L455.18,193.52L456.05,188.14L455.69,182.74L453.55,180.27Z"/>
    <path id="BJ" class="country" data-iso2="BJ" data-iso3="BEN" data-name="Benin" d="M507.33,220.40L505.08,220.72L504.53,212.59L502.10,208.94L503.94,206.00L507.75,204.13L509.83,205.70L510.34,208.22L510.09,210.04L507.41,214.28L507.33,220.40Z"/>
    <path id="NE" class="country" data-iso2="NE" data-iso3="NER" data-name="Niger" d="M540.43,175.20L541.10,179.43L543.29,181.94L541.51,192.18L538.04,194.74L536.86,198.33L537.99,199.34L537.99,201.09L539.73,201.15L538.60,203.46L535.62,200.43L533.49,201.95L529.92,201.00L524.54,202.52L521.25,201.12L518.57,201.74L514.82,199.69L511.18,200.60L509.83,205.70L507.75,204.13L505.86,204.94L505.93,203.07L502.79,202.45L501.17,199.36L501.02,196.80L509.90,195.06L511.62,191.56L511.62,185.29L515.46,184.08L532.67,173.54L536.97,174.72L538.50,176.21L540.43,175.20Z"/>
    <path id="NG" class="country" data-iso2="NG" data-iso3="NGA" data-name="Nigeria" d="M507.33,220.40L507.41,214.28L510.09,210.04L510.02,203.27L511.89,200.02L514.82,199.69L518.57,201.74L521.25,201.12L524.54,202.52L529.92,201.00L533.49,201.95L535.62,200.43L539.68,204.54L536.95,208.04L531.97,218.43L530.10,219.35L527.54,218.28L525.13,219.90L523.14,224.45L516.06,225.84L511.78,220.37L507.33,220.40Z"/>
    <path id="CM" class="country" data-iso2="CM" data-iso3="CMR" data-name="Cameroon" d="M539.46,202.43L540.54,204.18L540.63,207.79L542.11,210.26L538.58,210.16L537.99,211.44L540.78,213.49L542.02,216.50L539.57,220.49L539.41,224.56L543.18,229.24L543.39,232.74L539.03,231.37L526.27,231.22L526.66,229.07L523.11,225.20L523.84,222.52L525.13,219.90L527.54,218.28L530.10,219.35L531.97,218.43L536.95,208.04L539.24,205.94L539.68,204.54L538.60,203.46L539.46,202.43Z"/>
    <path id="TG" class="country" data-iso2="TG" data-iso3="TGO" data-name="Togo" d="M502.45,207.50L502.10,208.94L504.53,212.59L505.08,220.72L502.89,221.30L501.55,218.62L501.94,214.81L501.00,209.70L499.86,208.29L500.06,207.44L502.45,207.50Z"/>
    <path id="GH" class="country" data-iso2="GH" data-iso3="GHA" data-name="Ghana" d="M500.06,207.44L501.94,214.81L501.55,218.62L502.89,221.30L494.65,224.62L492.22,223.84L491.17,220.42L493.03,215.06L492.00,207.60L500.06,207.44Z"/>
    <path id="CI" class="country" data-iso2="CI" data-iso3="CIV" data-name="Côte d'Ivoire" d="M478.14,209.65L481.35,209.84L483.11,208.79L483.53,209.95L485.29,209.21L488.21,211.28L490.44,210.49L492.30,211.19L493.03,215.06L491.17,220.42L492.22,223.84L487.34,223.37L479.01,225.56L479.39,221.90L476.58,219.83L477.41,214.80L478.68,214.09L477.38,210.79L478.14,209.65Z"/>
    <path id="GN" class="country" data-iso2="GN" data-iso3="GIN" data-name="Guinea" d="M462.70,203.18L468.66,203.57L468.81,204.56L469.96,204.20L472.33,205.20L475.15,203.93L477.20,206.42L476.53,208.01L477.45,208.06L478.14,209.65L477.38,210.79L478.68,214.09L477.41,214.80L477.46,216.51L474.93,217.53L473.44,214.19L471.40,214.71L471.08,212.21L469.74,210.09L466.17,210.66L463.94,213.20L458.81,207.38L460.02,206.06L462.59,205.29L462.70,203.18Z"/>
    <path id="GW" class="country" data-iso2="GW" data-iso3="GNB" data-name="Guinea-Bissau" d="M454.60,203.72L462.70,203.18L462.59,205.29L460.02,206.06L458.81,207.38L456.21,206.07L454.60,203.72Z"/>
    <path id="LR" class="country" data-iso2="LR" data-iso3="LBR" data-name="Liberia" d="M477.03,216.52L476.58,219.83L479.39,221.90L479.01,225.56L475.49,224.28L468.86,218.97L472.15,214.56L473.44,214.19L474.93,217.53L477.03,216.52Z"/>
    <path id="SL" class="country" data-iso2="SL" data-iso3="SLE" data-name="Sierra Leone" d="M463.94,213.20L466.17,210.66L469.74,210.09L471.08,212.21L471.40,214.71L472.15,214.56L468.86,218.97L464.75,216.21L463.94,213.20Z"/>
    <path id="BF" class="country" data-iso2="BF" data-iso3="BFA" data-name="Burkina Faso" d="M485.29,209.21L485.79,205.55L487.95,203.30L488.35,201.43L491.55,200.58L497.10,196.68L501.02,196.80L501.17,199.36L502.79,202.45L505.93,203.07L505.27,205.75L502.45,207.50L492.00,207.60L492.30,211.19L490.44,210.49L488.21,211.28L485.29,209.21Z"/>
    <path id="CF" class="country" data-iso2="CF" data-iso3="CAF" data-name="Central African Rep." d="M574.52,223.19L569.83,223.13L567.52,224.11L566.45,223.53L563.42,224.89L562.18,224.62L560.99,226.47L553.00,223.74L550.48,226.00L550.23,227.90L546.64,227.29L543.59,231.27L543.18,229.24L539.41,224.56L539.36,222.60L539.57,220.49L541.59,217.23L548.90,215.96L551.48,213.94L551.21,212.99L554.61,212.90L557.17,211.64L559.14,208.67L562.24,207.11L564.12,209.97L563.86,213.06L568.37,216.14L572.05,221.25L574.52,223.19Z"/>
    <path id="CG" class="country" data-iso2="CG" data-iso3="COG" data-name="Congo" d="M550.23,227.90L548.02,238.60L544.66,242.18L543.48,244.82L543.57,247.06L539.70,250.97L538.51,249.72L537.02,249.69L536.09,250.73L534.36,249.52L532.44,251.15L530.20,248.27L532.27,246.77L531.25,244.97L534.02,243.95L534.23,242.74L535.69,244.05L538.09,244.17L539.27,241.07L538.97,238.94L537.68,237.33L538.86,234.18L536.16,233.86L535.60,231.27L543.39,232.74L545.02,228.73L546.64,227.29L550.23,227.90Z"/>
    <path id="GA" class="country" data-iso2="GA" data-iso3="GAB" data-name="Gabon" d="M530.70,231.28L535.26,231.12L536.16,233.86L538.86,234.18L537.68,237.33L538.97,238.94L539.27,241.07L538.09,244.17L535.69,244.05L534.23,242.74L534.02,243.95L531.25,244.97L532.27,246.77L530.20,248.27L523.95,240.46L525.84,234.69L530.72,234.56L530.70,231.28Z"/>
    <path id="GQ" class="country" data-iso2="GQ" data-iso3="GNQ" data-name="Eq. Guinea" d="M526.27,231.22L530.70,231.28L530.72,234.56L525.84,234.69L525.33,234.28L526.27,231.22Z"/>
    <path id="ZM" class="country" data-iso2="ZM" data-iso3="ZMB" data-name="Zambia" d="M583.68,260.14L590.46,263.78L591.16,266.09L590.14,269.04L590.67,271.29L588.98,274.77L590.42,275.47L582.16,277.72L582.41,279.65L578.80,281.11L573.62,286.27L568.77,285.72L567.19,284.68L563.20,285.14L559.58,281.21L559.71,272.55L565.38,272.59L565.09,267.18L566.03,267.25L566.19,268.10L569.19,268.28L570.10,269.52L572.28,269.90L573.95,269.04L574.56,270.47L576.64,270.85L578.77,273.51L580.85,273.53L580.62,270.59L579.87,271.09L577.24,269.54L578.06,263.59L577.45,262.39L578.95,260.32L583.68,260.14Z"/>
    <path id="MW" class="country" data-iso2="MW" data-iso3="MWI" data-name="Malawi" d="M589.18,262.57L591.85,263.07L593.32,265.10L594.08,274.41L596.01,275.24L597.15,277.21L597.38,280.71L596.20,281.29L595.37,283.18L593.59,281.49L593.81,277.22L588.98,274.77L590.67,271.29L590.14,269.04L591.16,266.09L589.18,262.57Z"/>
    <path id="MZ" class="country" data-iso2="MZ" data-iso3="MOZ" data-name="Mozambique" d="M594.08,268.80L602.01,268.93L607.58,267.10L609.75,265.52L611.00,277.43L607.40,282.96L601.84,285.31L594.70,291.30L594.47,293.24L596.81,297.57L596.53,303.11L589.87,306.47L588.68,307.47L589.60,308.80L589.37,310.24L587.31,310.21L586.44,306.81L586.92,303.78L584.91,298.01L588.91,292.71L589.42,282.94L584.86,280.62L582.59,280.67L582.16,277.72L590.42,275.47L593.81,277.22L593.59,281.49L595.37,283.18L596.20,281.29L597.38,280.71L597.15,277.21L596.01,275.24L594.08,274.41L593.32,270.87L594.08,268.80Z"/>
    <path id="SZ" class="country" data-iso2="SZ" data-iso3="SWZ" data-name="eSwatini" d="M587.31,310.21L586.75,311.42L585.16,311.72L583.53,310.24L584.51,307.49L586.67,307.79L587.31,310.21Z"/>
    <path id="AO" class="country" data-iso2="AO" data-iso3="AGO" data-name="Angola" d="M535.38,250.45L534.39,251.03L533.16,253.20L532.44,251.15L534.36,249.52L535.38,250.45ZM533.54,254.04L544.44,253.44L547.57,259.40L551.77,259.18L552.86,256.92L554.69,256.34L556.08,256.33L555.85,257.31L559.15,257.29L560.31,267.61L563.85,267.02L565.09,267.18L565.38,268.03L565.38,272.59L559.71,272.55L559.58,281.21L563.20,285.14L558.19,286.25L551.60,285.86L549.72,284.56L538.27,284.87L536.65,283.64L531.94,284.54L533.14,276.77L537.11,270.21L537.40,268.19L535.05,262.39L536.03,260.75L533.54,254.04Z"/>
    <path id="BI" class="country" data-iso2="BI" data-iso3="BDI" data-name="Burundi" d="M582.95,244.01L583.71,246.58L581.00,249.56L579.87,249.69L579.01,245.17L580.67,245.38L581.50,243.83L582.95,244.01Z"/>
    <path id="IL" class="country" data-iso2="IL" data-iso3="ISR" data-name="Israel" d="M597.24,148.40L596.76,149.26L595.78,148.88L595.21,150.69L595.89,151.00L595.08,152.09L596.36,151.72L596.42,152.78L595.07,157.13L593.28,152.45L595.55,147.39L597.51,146.85L597.24,148.40Z"/>
    <path id="LB" class="country" data-iso2="LB" data-iso3="LBN" data-name="Lebanon" d="M597.51,146.85L595.62,147.36L598.00,143.13L599.22,143.27L599.67,144.33L597.51,146.85Z"/>
    <path id="MG" class="country" data-iso2="MG" data-iso3="MDG" data-name="Madagascar" d="M634.87,271.38L636.26,274.34L637.14,280.19L636.66,281.00L635.73,279.40L635.22,280.21L635.50,283.38L628.21,305.34L623.61,307.13L619.89,305.46L618.00,299.44L618.24,295.52L619.49,295.05L621.04,290.35L619.68,284.83L620.99,281.58L626.07,280.40L629.86,277.17L630.68,275.80L630.31,274.64L631.47,274.96L633.92,270.22L634.87,271.38Z"/>
    <path id="PS" class="country" data-iso2="PS" data-iso3="PSE" data-name="Palestine" d="M596.36,151.72L595.08,152.09L595.89,151.00L595.21,150.69L595.78,148.88L596.76,149.26L596.36,151.72Z"/>
    <path id="GM" class="country" data-iso2="GM" data-iso3="GMB" data-name="Gambia" d="M454.50,200.43L458.94,199.66L460.02,200.33L461.76,199.89L462.31,200.68L454.15,201.64L454.50,200.43Z"/>
    <path id="TN" class="country" data-iso2="TN" data-iso3="TUN" data-name="Tunisia" d="M525.81,154.94L524.65,150.05L520.72,146.67L520.48,144.62L522.16,143.10L522.92,136.86L525.89,135.76L527.79,136.09L527.71,137.47L530.02,136.47L528.86,138.32L528.84,139.58L529.78,140.26L529.42,142.61L527.63,143.98L528.15,145.47L529.55,145.51L531.28,147.23L531.12,149.32L527.09,152.03L527.14,154.30L525.81,154.94Z"/>
    <path id="DZ" class="country" data-iso2="DZ" data-iso3="DZA" data-name="Algeria" d="M476.36,162.86L476.39,158.93L485.73,155.77L486.77,154.41L489.95,153.33L490.07,151.32L496.44,149.61L496.94,148.55L494.09,141.70L496.71,140.22L503.99,137.79L514.48,137.49L517.05,136.42L522.92,136.86L522.16,143.10L520.48,144.62L520.72,146.67L524.65,150.05L526.69,157.34L526.45,165.27L525.37,166.40L528.05,171.07L529.32,170.57L532.67,173.54L515.46,184.08L508.60,185.56L508.57,183.83L505.61,182.61L504.96,181.33L476.36,162.86Z"/>
    <path id="JO" class="country" data-iso2="JO" data-iso3="JOR" data-name="Jordan" d="M596.76,149.26L597.24,148.40L600.27,149.48L605.60,146.57L606.70,149.89L600.73,151.67L603.44,154.39L598.19,157.96L595.07,157.13L596.76,149.26Z"/>
    <path id="AE" class="country" data-iso2="AE" data-iso3="ARE" data-name="United Arab Emirates" d="M640.41,171.44L641.00,172.05L647.02,171.77L652.64,166.51L653.16,167.44L653.52,169.59L652.13,169.60L652.39,171.75L651.16,172.29L649.74,176.20L641.56,174.82L640.41,171.44Z"/>
    <path id="QA" class="country" data-iso2="QA" data-iso3="QAT" data-name="Qatar" d="M638.32,170.05L638.14,168.07L639.61,166.35L640.48,168.80L639.89,170.40L638.32,170.05Z"/>
    <path id="KW" class="country" data-iso2="KW" data-iso3="KWT" data-name="Kuwait" d="M630.60,155.84L631.80,159.71L629.87,159.78L629.20,158.49L626.77,158.23L628.77,155.61L630.60,155.84Z"/>
    <path id="IQ" class="country" data-iso2="IQ" data-iso3="IRQ" data-name="Iraq" d="M606.70,149.89L605.60,146.57L611.63,143.74L612.40,138.46L616.45,135.67L620.58,136.71L621.88,136.25L623.65,139.50L625.43,140.32L625.64,141.91L624.27,142.85L623.63,144.97L625.52,147.56L628.86,149.05L630.26,151.12L629.81,153.09L630.68,153.09L630.71,154.54L632.21,155.97L628.77,155.61L626.77,158.23L621.71,158.01L614.03,152.53L606.70,149.89Z"/>
    <path id="OM" class="country" data-iso2="OM" data-iso3="OMN" data-name="Oman" d="M650.29,175.62L651.16,172.29L652.39,171.75L652.13,169.60L653.52,169.59L656.26,172.44L659.87,173.29L662.81,176.70L659.22,181.83L657.42,182.33L657.06,185.87L654.10,186.88L653.22,188.78L651.52,188.75L649.15,191.30L644.57,192.11L641.56,185.72L649.72,182.99L651.54,177.55L650.29,175.62ZM653.16,167.44L652.64,166.51L653.43,165.58L653.77,165.82L653.16,167.44Z"/>
    <path id="VU" class="country" data-iso2="VU" data-iso3="VUT" data-name="Vanuatu" d="M955.20,280.70L956.91,282.26L956.01,282.62L955.20,280.70ZM954.05,280.09L953.66,279.34L953.60,277.26L954.90,278.09L955.35,280.29L954.05,280.09Z"/>
    <path id="KH" class="country" data-iso2="KH" data-iso3="KHM" data-name="Cambodia" d="M779.26,204.26L778.61,200.98L780.36,198.71L783.88,198.19L788.68,199.65L789.91,197.77L792.32,198.78L792.95,200.59L792.62,203.85L788.04,205.95L789.24,207.60L784.02,208.89L781.74,208.49L779.26,204.26Z"/>
    <path id="TH" class="country" data-iso2="TH" data-iso3="THA" data-name="Thailand" d="M786.43,198.58L780.36,198.71L778.61,200.98L779.26,204.26L776.82,203.01L774.49,203.07L774.89,200.93L772.49,200.94L772.27,203.94L769.92,210.32L770.11,212.29L771.88,212.37L773.47,217.21L778.05,220.50L777.16,221.62L775.36,221.95L775.15,220.55L772.93,219.36L772.46,219.84L768.15,214.62L767.70,216.22L767.19,214.71L768.28,210.40L771.10,205.06L769.77,199.80L767.30,196.27L769.24,193.40L765.08,187.23L766.23,186.73L767.47,183.79L769.39,183.67L772.54,181.86L773.72,182.70L773.87,184.33L775.71,184.46L775.11,189.77L777.98,188.14L780.39,188.54L780.93,187.60L782.99,187.78L785.06,189.99L785.23,192.68L787.44,195.05L786.43,198.58Z"/>
    <path id="LA" class="country" data-iso2="LA" data-iso3="LAO" data-name="Laos" d="M792.32,198.78L789.91,197.77L788.68,199.65L786.43,198.58L787.44,195.05L785.23,192.68L785.06,189.99L782.99,187.78L780.93,187.60L780.39,188.54L777.98,188.14L775.11,189.77L775.71,184.46L773.87,184.33L773.72,182.70L772.54,181.86L775.43,179.08L777.13,179.80L776.72,176.68L778.13,176.29L780.94,180.91L784.30,180.93L785.35,183.30L782.83,184.99L786.09,186.62L792.13,194.13L792.81,196.06L792.32,198.78Z"/>
    <path id="MM" class="country" data-iso2="MM" data-iso3="MMR" data-name="Myanmar" d="M772.54,181.86L769.39,183.67L767.47,183.79L766.23,186.73L765.08,187.23L769.24,193.40L767.30,196.27L769.77,199.80L771.10,205.06L768.28,210.40L768.86,206.29L767.94,204.68L768.16,201.72L767.06,200.31L764.50,191.36L759.62,194.66L756.40,193.78L757.34,190.41L756.77,187.86L754.64,184.72L754.97,183.74L753.38,183.39L751.45,181.17L751.27,178.98L752.22,179.39L752.28,177.44L753.62,176.79L754.05,171.89L756.18,172.51L759.03,166.66L758.95,165.10L762.47,163.22L764.42,163.71L764.95,160.50L766.54,160.30L768.64,162.55L768.61,166.88L766.03,169.16L765.70,172.39L768.58,171.93L769.22,174.44L770.95,174.97L770.16,177.23L773.36,178.75L775.35,177.96L775.43,179.08L772.54,181.86Z"/>
    <path id="VN" class="country" data-iso2="VN" data-iso3="VNM" data-name="Vietnam" d="M784.02,208.89L789.24,207.60L788.04,205.95L792.62,203.85L792.81,196.06L792.13,194.13L786.09,186.62L782.83,184.99L785.35,183.30L784.30,180.93L780.94,180.91L778.13,176.29L784.41,175.32L786.73,173.87L790.53,175.39L790.10,176.96L791.40,178.06L794.14,178.77L790.50,181.10L787.64,185.56L792.26,191.98L796.39,195.85L797.63,200.89L797.27,205.68L786.26,214.03L785.28,212.28L786.04,210.44L784.02,208.89Z"/>
    <path id="KP" class="country" data-iso2="KP" data-iso3="PRK" data-name="North Korea" d="M856.01,122.51L856.01,122.51L856.01,122.51L856.01,122.51ZM855.63,122.03L856.01,122.51L854.98,122.34L852.98,124.19L853.09,126.15L847.17,129.21L846.77,130.69L849.40,132.33L849.00,132.99L841.03,134.90L839.49,133.70L841.33,130.22L838.28,128.74L840.50,127.00L845.37,123.61L849.01,124.56L848.59,123.12L852.79,121.95L853.87,120.42L855.63,122.03Z"/>
    <path id="KR" class="country" data-iso2="KR" data-iso3="KOR" data-name="South Korea" d="M843.48,134.68L849.40,132.33L852.42,137.30L852.44,140.44L851.42,141.94L844.32,143.82L844.52,140.30L843.32,137.46L845.34,137.01L843.48,134.68Z"/>
    <path id="MN" class="country" data-iso2="MN" data-iso3="MNG" data-name="Mongolia" d="M738.88,103.24L751.08,99.14L756.29,100.02L758.11,101.29L764.76,102.07L767.41,100.18L766.30,98.58L769.12,95.75L777.84,97.90L778.36,99.94L782.23,101.08L790.98,100.58L795.29,103.28L801.25,103.70L807.33,102.57L811.32,100.65L814.38,101.86L817.63,101.63L814.38,106.40L815.08,107.52L819.30,107.60L821.40,106.59L826.05,109.36L825.75,110.33L819.65,110.39L815.74,112.96L808.87,115.46L804.54,114.66L803.12,116.42L804.42,118.36L800.57,120.73L788.91,122.74L785.74,124.20L774.52,121.30L762.28,121.13L759.45,117.00L754.48,115.01L747.57,114.16L746.59,112.98L747.64,109.80L745.76,107.61L739.59,105.14L738.88,103.24Z"/>
    <path id="IN" class="country" data-iso2="IN" data-iso3="IND" data-name="India" d="M764.95,160.50L764.42,163.71L762.47,163.22L758.95,165.10L759.03,166.66L756.18,172.51L754.05,171.89L753.62,176.79L752.28,177.44L750.84,173.12L750.09,173.13L749.65,174.87L748.15,173.46L751.47,169.45L744.78,168.65L744.54,166.76L741.09,165.45L740.13,167.29L742.09,168.73L739.79,170.74L741.46,171.47L741.00,173.11L742.36,177.40L741.97,178.39L736.77,178.92L736.92,180.97L735.47,182.58L731.55,184.41L723.75,191.12L723.74,192.37L718.66,194.16L717.85,196.23L718.56,202.03L717.40,204.62L717.39,209.24L715.98,209.38L714.74,211.45L715.57,212.35L713.09,213.12L711.08,215.76L708.50,213.21L706.20,206.66L703.80,202.75L702.65,197.65L700.18,193.91L697.72,179.30L693.75,180.93L691.84,180.61L688.28,177.31L689.59,176.32L688.79,175.25L685.59,172.94L687.40,171.13L693.40,171.14L691.02,165.32L689.23,164.10L692.23,161.25L695.39,161.45L702.59,153.11L702.55,151.16L704.87,149.59L702.67,148.25L700.76,144.02L702.10,142.84L709.26,143.10L711.89,140.82L714.82,144.01L714.54,146.23L715.62,147.62L715.54,149.01L713.58,148.65L714.34,151.65L720.80,155.27L719.08,156.51L718.02,159.05L726.77,162.95L730.50,163.30L732.07,164.68L739.72,165.53L739.88,161.55L741.54,160.98L741.83,163.67L744.30,164.70L750.54,164.38L750.73,162.71L749.62,161.84L751.81,161.50L757.43,157.74L759.71,158.41L761.65,157.26L762.93,158.95L762.01,160.10L764.95,160.50Z"/>
    <path id="BD" class="country" data-iso2="BD" data-iso3="BGD" data-name="Bangladesh" d="M752.28,177.44L752.22,179.39L751.27,178.98L751.45,181.17L748.86,175.47L746.35,175.36L745.74,178.00L742.36,177.40L741.00,173.11L741.46,171.47L739.79,170.74L742.09,168.73L740.13,167.29L741.09,165.45L744.54,166.76L744.78,168.65L751.47,169.45L748.15,173.46L749.65,174.87L750.09,173.13L750.84,173.12L752.28,177.44Z"/>
    <path id="BT" class="country" data-iso2="BT" data-iso3="BTN" data-name="Bhutan" d="M749.62,161.84L750.73,162.71L750.54,164.38L744.30,164.70L741.83,163.67L743.57,161.10L745.04,160.41L749.62,161.84Z"/>
    <path id="NP" class="country" data-iso2="NP" data-iso3="NPL" data-name="Nepal" d="M739.88,161.55L739.72,165.53L737.45,165.58L732.07,164.68L730.50,163.30L726.77,162.95L718.02,159.05L719.08,156.51L721.93,154.62L733.63,160.66L739.88,161.55Z"/>
    <path id="PK" class="country" data-iso2="PK" data-iso3="PAK" data-name="Pakistan" d="M711.89,140.82L709.26,143.10L702.10,142.84L700.76,144.02L702.67,148.25L704.87,149.59L702.55,151.16L702.59,153.11L695.39,161.45L692.23,161.25L689.23,164.10L691.02,165.32L693.40,171.14L687.40,171.13L685.59,172.94L683.60,172.26L680.68,168.23L667.41,169.17L668.44,166.01L672.36,164.60L672.14,163.35L670.83,162.91L670.76,160.51L668.16,159.31L665.71,156.24L670.27,157.63L677.07,157.21L680.61,156.08L680.71,153.76L682.22,152.22L688.70,150.60L688.55,148.96L689.70,147.32L691.44,146.63L690.37,144.83L692.96,144.91L694.95,141.74L693.99,139.24L695.58,138.05L704.60,136.35L706.61,137.62L707.41,139.72L711.89,140.82Z"/>
    <path id="AF" class="country" data-iso2="AF" data-iso3="AFG" data-name="Afghanistan" d="M681.08,135.73L685.48,136.65L687.45,135.78L688.37,136.31L689.25,135.06L690.87,135.12L692.75,132.67L694.23,133.29L694.50,136.54L695.58,137.43L699.43,135.37L704.11,135.57L704.60,136.35L695.58,138.05L693.99,139.24L694.95,141.74L692.96,144.91L690.37,144.83L691.44,146.63L689.70,147.32L688.55,148.96L688.70,150.60L682.22,152.22L680.71,153.76L680.61,156.08L677.07,157.21L670.27,157.63L665.71,156.24L668.18,153.77L667.96,152.02L665.90,151.56L664.79,147.66L665.96,146.17L664.77,145.76L666.63,140.39L669.41,141.42L671.46,141.06L672.03,139.83L675.71,138.59L676.25,136.41L678.55,135.89L678.97,134.92L681.08,135.73Z"/>
    <path id="TJ" class="country" data-iso2="TJ" data-iso3="TJK" data-name="Tajikistan" d="M684.65,136.32L686.18,133.57L685.59,131.54L683.59,130.89L684.30,129.69L686.57,129.82L688.73,126.57L692.37,125.94L691.80,127.20L693.32,127.88L692.32,128.73L689.36,128.27L689.10,129.84L700.56,130.10L701.25,132.62L703.80,132.96L704.11,135.57L699.43,135.37L695.58,137.43L694.50,136.54L694.23,133.29L692.75,132.67L690.87,135.12L689.25,135.06L688.37,136.31L684.65,136.32Z"/>
    <path id="KG" class="country" data-iso2="KG" data-iso3="KGZ" data-name="Kyrgyzstan" d="M693.18,122.38L693.78,121.19L695.58,120.80L700.06,121.74L700.48,120.14L702.02,119.57L705.90,120.72L715.44,120.78L718.49,122.15L712.84,125.32L709.35,125.65L708.32,127.39L703.56,127.55L700.96,128.84L701.34,129.48L700.56,130.10L689.10,129.84L689.36,128.27L695.39,128.15L698.87,126.19L695.65,124.76L693.71,125.44L691.70,124.41L693.98,122.65L693.18,122.38Z"/>
    <path id="TM" class="country" data-iso2="TM" data-iso3="TKM" data-name="Turkmenistan" d="M642.92,123.70L647.22,122.22L650.96,125.12L655.43,124.95L654.98,123.58L659.60,121.06L663.27,122.50L663.56,124.67L664.60,125.23L668.46,125.60L669.80,128.40L674.69,131.57L681.15,134.06L681.08,135.73L678.97,134.92L678.55,135.89L676.25,136.41L675.71,138.59L669.41,141.42L666.63,140.39L666.39,138.10L664.36,138.00L661.25,135.59L656.07,133.92L651.11,134.09L649.18,135.65L646.79,136.18L646.68,131.40L644.55,130.48L645.25,128.62L643.44,128.46L644.05,126.16L646.61,126.83L649.01,125.96L646.24,122.77L644.05,123.46L643.77,125.46L642.92,123.70Z"/>
    <path id="IR" class="country" data-iso2="IR" data-iso3="IRN" data-name="Iran" d="M632.21,155.97L630.71,154.54L630.68,153.09L629.81,153.09L630.26,151.12L628.86,149.05L625.52,147.56L623.63,144.97L624.27,142.85L625.64,141.91L625.43,140.32L623.65,139.50L620.39,134.07L620.92,133.23L620.08,130.11L621.94,129.33L623.75,131.62L625.61,131.98L630.83,129.69L631.63,130.49L630.70,131.83L633.07,133.12L633.93,135.13L638.40,137.06L642.27,137.53L646.53,136.81L651.11,134.09L654.13,133.66L661.25,135.59L664.36,138.00L666.39,138.10L666.63,140.39L664.77,145.76L665.96,146.17L664.79,147.66L665.90,151.56L667.96,152.02L668.18,153.77L665.71,156.24L668.16,159.31L670.76,160.51L670.83,162.91L672.14,163.35L672.36,164.60L668.44,166.01L667.41,169.17L656.25,167.37L655.09,164.03L653.78,163.55L648.95,165.35L645.62,164.45L642.87,162.36L640.25,161.58L636.42,155.37L634.96,155.81L633.23,154.91L632.21,155.97Z"/>
    <path id="SY" class="country" data-iso2="SY" data-iso3="SYR" data-name="Syria" d="M597.24,148.40L598.18,145.36L599.67,144.33L599.22,143.27L598.00,143.13L597.74,141.05L599.87,138.73L600.01,137.21L607.59,137.49L615.28,136.09L612.40,138.46L611.63,143.74L600.27,149.48L597.24,148.40Z"/>
    <path id="AM" class="country" data-iso2="AM" data-iso3="ARM" data-name="Armenia" d="M626.60,131.90L625.61,131.98L624.51,129.98L618.84,127.86L618.64,125.58L622.43,125.15L624.03,126.34L623.48,127.02L624.93,127.96L624.16,128.82L626.54,130.01L626.60,131.90Z"/>
    <path id="SE" class="country" data-iso2="SE" data-iso3="SWE" data-name="Sweden" d="M530.02,77.22L533.48,73.78L534.38,70.58L532.65,69.20L532.48,65.59L534.25,63.04L536.95,63.08L537.89,62.00L536.90,61.07L545.65,52.29L548.26,52.30L548.98,50.78L554.11,51.22L554.51,49.43L556.20,49.32L564.08,52.50L564.15,56.69L565.07,57.75L560.39,58.52L557.75,60.42L558.17,62.09L548.59,66.62L546.60,70.45L551.14,73.88L548.64,76.95L545.81,77.59L544.77,82.16L543.23,84.71L539.93,84.45L538.39,86.61L535.23,86.73L530.02,77.22Z"/>
    <path id="BY" class="country" data-iso2="BY" data-iso3="BLR" data-name="Belarus" d="M576.70,84.53L579.96,85.89L584.05,86.22L583.73,88.23L586.38,91.00L589.00,92.20L585.22,92.96L586.53,95.61L584.19,95.77L583.18,97.74L568.95,96.13L564.05,97.03L563.15,94.56L564.79,94.00L563.93,90.68L569.52,89.67L570.15,88.13L572.38,87.26L572.12,86.04L576.70,84.53Z"/>
    <path id="UA" class="country" data-iso2="UA" data-iso3="UKR" data-name="Ukraine" d="M586.53,95.61L591.88,94.97L593.62,96.51L593.17,97.91L595.34,98.04L596.25,99.76L599.70,100.71L601.79,100.28L603.47,101.56L609.08,102.41L608.00,104.64L608.18,107.05L605.54,107.25L604.14,108.01L604.05,109.22L595.18,111.47L595.31,112.93L591.74,111.62L591.02,112.29L586.41,111.31L586.23,110.29L583.70,110.63L580.59,114.14L578.07,114.11L576.86,113.61L578.57,111.02L581.73,111.06L578.05,106.45L574.92,105.50L567.69,107.49L563.00,106.51L561.82,107.09L560.12,105.62L562.00,103.98L561.30,102.75L565.12,100.17L564.05,97.03L568.95,96.13L583.18,97.74L584.19,95.77L586.53,95.61Z"/>
    <path id="PL" class="country" data-iso2="PL" data-iso3="POL" data-name="Poland" d="M563.93,90.68L564.79,94.00L563.15,94.56L565.41,99.41L561.30,102.75L562.00,103.98L558.82,102.77L553.97,103.46L552.60,102.49L551.48,102.86L550.07,101.36L548.05,101.19L547.79,100.34L544.04,100.18L544.21,99.43L540.88,98.32L538.31,93.21L539.07,92.49L538.44,91.10L547.97,88.12L550.69,88.58L550.90,89.24L561.88,89.55L563.93,90.68Z"/>
    <path id="AT" class="country" data-iso2="AT" data-iso3="AUT" data-name="Austria" d="M546.22,106.44L546.02,107.55L544.48,107.55L545.01,108.14L543.59,110.36L539.83,111.04L533.69,110.13L533.08,109.18L530.08,110.17L525.81,109.21L526.94,107.92L528.32,108.67L528.70,107.95L533.05,107.58L535.21,108.22L535.07,105.99L537.01,104.38L539.03,105.26L541.52,103.94L544.91,104.63L546.17,105.15L546.22,106.44Z"/>
    <path id="HU" class="country" data-iso2="HU" data-iso3="HUN" data-name="Hungary" d="M560.12,105.62L561.82,107.09L560.16,107.66L557.23,111.36L550.24,112.87L544.11,109.90L545.01,108.14L544.48,107.55L546.02,107.55L546.22,106.44L548.61,107.43L556.63,105.07L560.12,105.62Z"/>
    <path id="MD" class="country" data-iso2="MD" data-iso3="MDA" data-name="Moldova" d="M572.46,106.17L574.92,105.50L578.05,106.45L581.73,111.06L578.57,111.02L576.86,113.61L576.57,110.01L572.46,106.17Z"/>
    <path id="RO" class="country" data-iso2="RO" data-iso3="ROU" data-name="Romania" d="M576.86,113.61L580.59,114.14L580.65,114.84L578.50,115.17L577.74,118.46L574.16,117.18L569.61,118.51L562.46,118.14L561.18,116.55L561.81,116.09L558.70,115.57L558.48,114.45L555.04,111.87L557.23,111.36L560.16,107.66L563.00,106.51L567.69,107.49L572.46,106.17L576.57,110.01L576.86,113.61Z"/>
    <path id="LT" class="country" data-iso2="LT" data-iso3="LTU" data-name="Lithuania" d="M572.12,86.04L572.38,87.26L570.15,88.13L569.52,89.67L563.93,90.68L561.88,89.55L561.95,88.11L557.90,87.20L557.32,84.91L560.44,84.08L567.68,83.98L572.12,86.04Z"/>
    <path id="LV" class="country" data-iso2="LV" data-iso3="LVA" data-name="Latvia" d="M574.28,80.98L575.60,81.61L576.70,84.53L572.12,86.04L567.68,83.98L560.44,84.08L557.32,84.91L557.41,82.86L558.75,81.15L561.32,80.22L563.48,82.26L565.66,82.20L566.19,80.11L568.50,79.63L574.28,80.98Z"/>
    <path id="EE" class="country" data-iso2="EE" data-iso3="EST" data-name="Estonia" d="M576.17,75.53L576.58,76.01L574.64,77.58L575.45,80.12L574.28,80.98L568.50,79.63L566.19,80.11L566.50,78.51L565.50,78.85L563.77,77.88L563.54,76.32L570.41,75.16L576.17,75.53Z"/>
    <path id="DE" class="country" data-iso2="DE" data-iso3="DEU" data-name="Germany" d="M538.44,91.10L539.07,92.49L538.31,93.21L540.88,98.32L538.95,98.29L533.32,100.60L534.09,102.56L537.01,104.38L535.07,105.99L535.21,108.22L533.05,107.58L528.70,107.95L528.32,108.67L523.20,107.23L520.33,107.81L522.05,104.00L518.13,103.50L516.84,102.79L516.45,100.98L516.30,96.29L517.94,96.29L518.63,95.26L519.33,91.27L522.11,91.72L523.96,90.38L523.21,87.82L527.01,87.76L527.06,88.81L529.81,89.45L529.78,90.42L534.08,89.16L538.44,91.10Z"/>
    <path id="BG" class="country" data-iso2="BG" data-iso3="BGR" data-name="Bulgaria" d="M561.68,117.02L562.46,118.14L569.61,118.51L574.16,117.18L577.74,118.46L575.33,121.53L576.21,123.09L573.87,122.72L571.10,123.58L571.07,124.93L568.59,125.19L566.67,124.24L562.48,124.91L562.29,123.11L560.92,122.23L562.57,119.81L561.25,118.63L561.68,117.02Z"/>
    <path id="GR" class="country" data-iso2="GR" data-iso3="GRC" data-name="Greece" d="M571.57,141.34L571.23,142.15L567.31,142.38L564.01,141.40L564.52,140.24L566.00,141.16L571.57,141.34ZM562.48,124.91L566.67,124.24L568.59,125.19L571.07,124.93L571.10,123.58L572.42,124.30L570.93,126.31L564.56,126.68L566.44,128.21L563.54,128.66L562.10,127.25L561.59,127.85L563.56,130.76L562.54,131.35L565.40,133.40L565.44,134.93L562.92,134.21L563.73,135.60L562.00,135.89L563.03,138.29L561.22,138.32L558.99,137.14L557.49,133.15L554.85,129.57L557.22,126.26L562.48,124.91Z"/>
    <path id="TR" class="country" data-iso2="TR" data-iso3="TUR" data-name="Turkey" d="M621.88,136.25L620.58,136.71L616.45,135.67L607.59,137.49L600.01,137.21L599.87,138.73L598.41,139.92L597.41,138.69L598.44,137.67L594.50,137.27L592.63,138.84L588.50,139.15L586.29,137.69L583.36,137.59L582.73,138.72L580.85,139.05L578.22,137.60L575.25,137.65L571.64,133.43L572.97,131.31L571.24,130.01L574.26,127.41L578.45,127.30L579.60,125.23L584.79,125.59L591.23,123.05L595.73,123.00L604.39,125.97L609.91,125.79L613.12,124.37L616.02,124.24L618.64,125.58L618.84,127.86L621.94,129.33L620.08,130.11L620.92,133.23L620.39,134.07L621.88,136.25ZM571.10,123.58L573.87,122.72L576.21,123.09L576.54,124.13L578.91,125.01L578.42,125.68L575.19,125.83L571.75,128.14L570.93,126.31L572.42,124.30L571.10,123.58Z"/>
    <path id="AL" class="country" data-iso2="AL" data-iso3="ALB" data-name="Albania" d="M557.22,126.26L554.85,129.57L552.83,127.87L553.19,123.87L552.55,122.57L553.73,121.23L555.87,122.51L556.09,125.59L557.22,126.26Z"/>
    <path id="HR" class="country" data-iso2="HR" data-iso3="HRV" data-name="Croatia" d="M545.09,110.85L547.99,112.35L551.26,112.46L552.79,114.30L551.74,115.32L543.44,114.30L542.88,115.43L548.12,120.31L550.52,121.34L550.23,121.80L543.60,119.00L541.31,117.00L541.86,116.80L540.57,114.73L538.82,114.30L537.98,115.48L537.18,114.57L537.34,113.58L541.73,113.71L542.93,111.57L545.09,110.85Z"/>
    <path id="CH" class="country" data-iso2="CH" data-iso3="CHE" data-name="Switzerland" d="M526.12,108.07L525.81,109.21L528.43,109.78L528.21,110.90L525.00,111.02L524.41,112.12L522.64,111.77L519.80,112.82L517.69,111.05L516.39,111.47L516.44,110.24L518.34,108.02L523.20,107.23L526.12,108.07Z"/>
    <path id="LU" class="country" data-iso2="LU" data-iso3="LUX" data-name="Luxembourg" d="M516.45,100.98L516.84,102.79L515.45,102.61L515.74,101.08L516.45,100.98Z"/>
    <path id="BE" class="country" data-iso2="BE" data-iso3="BEL" data-name="Belgium" d="M516.76,99.14L515.45,102.61L513.06,101.37L511.67,101.58L508.50,99.20L507.24,99.16L506.84,98.20L513.54,97.31L516.76,99.14Z"/>
    <path id="NL" class="country" data-iso2="NL" data-iso3="NLD" data-name="Netherlands" d="M518.80,91.85L519.31,92.77L518.63,95.26L517.94,96.29L516.30,96.29L516.76,99.14L513.54,97.31L509.02,97.66L510.43,96.92L512.81,92.91L518.80,91.85Z"/>
    <path id="PT" class="country" data-iso2="PT" data-iso3="PRT" data-name="Portugal" d="M475.41,123.43L477.50,122.34L478.19,123.68L481.85,123.42L482.61,124.79L481.35,125.53L480.76,129.33L479.59,129.56L480.68,131.19L479.93,132.98L480.86,133.79L478.62,137.16L475.78,137.07L475.94,133.27L474.07,131.99L476.13,126.48L475.41,123.43Z"/>
    <path id="ES" class="country" data-iso2="ES" data-iso3="ESP" data-name="Spain" d="M479.71,136.45L479.48,135.55L480.86,133.79L479.93,132.98L480.68,131.19L479.59,129.56L480.76,129.33L481.35,125.53L482.61,124.79L481.85,123.42L478.19,123.68L477.50,122.34L475.41,123.43L475.54,121.49L474.43,120.31L478.28,118.35L494.82,119.23L495.91,120.29L500.92,121.53L501.91,120.94L504.97,122.17L508.13,121.82L508.27,123.40L505.69,125.21L502.21,125.79L499.24,130.43L500.30,131.98L498.73,133.20L498.14,134.97L496.08,135.51L494.16,137.60L488.11,137.59L485.36,139.58L484.03,139.36L482.25,136.87L479.71,136.45Z"/>
    <path id="IE" class="country" data-iso2="IE" data-iso3="IRL" data-name="Ireland" d="M483.13,90.80L483.58,92.74L481.52,95.18L476.69,96.78L472.84,96.37L475.05,93.53L473.63,90.76L479.39,87.36L479.95,88.82L479.39,90.28L483.13,90.80Z"/>
    <path id="NC" class="country" data-iso2="NC" data-iso3="NCL" data-name="New Caledonia" d="M951.29,294.82L954.94,297.76L953.90,298.42L950.46,296.46L946.53,292.17L951.29,294.82Z"/>
    <path id="SB" class="country" data-iso2="SB" data-iso3="SLB" data-name="Solomon Is." d="M941.32,265.98L942.09,266.91L940.18,266.89L939.15,265.22L941.32,265.98ZM940.13,263.57L939.72,264.07L937.13,260.09L938.06,260.09L940.13,263.57ZM937.88,264.32L935.15,264.10L934.75,262.60L936.54,263.03L937.88,264.32ZM934.58,259.27L935.33,260.68L930.69,257.64L931.09,257.37L934.58,259.27ZM927.77,256.55L928.85,257.44L927.12,256.98L926.14,255.40L927.77,256.55Z"/>
    <path id="NZ" class="country" data-iso2="NZ" data-iso3="NZL" data-name="New Zealand" d="M981.52,346.51L979.14,349.84L977.04,350.92L975.44,349.82L977.01,347.58L976.12,346.08L973.19,344.99L973.26,344.00L975.23,343.05L975.56,339.20L969.95,331.43L970.96,331.22L974.56,333.44L977.31,338.73L977.36,336.87L978.59,337.61L979.00,339.67L983.03,340.78L984.58,339.74L985.96,340.05L984.48,344.06L982.40,344.00L981.52,346.51ZM961.87,356.01L965.84,353.17L968.49,348.93L970.40,347.67L971.62,349.95L973.55,348.85L974.34,350.00L974.34,351.15L970.16,355.51L971.16,356.82L966.73,357.88L964.46,362.41L960.96,364.41L953.73,363.26L953.27,362.26L954.74,360.24L958.16,357.55L961.87,356.01Z"/>
    <path id="AU" class="country" data-iso2="AU" data-iso3="AUS" data-name="Australia" d="M902.04,348.53L903.68,348.71L903.87,351.94L902.65,355.07L901.70,354.33L899.81,356.22L897.58,355.99L893.95,349.49L894.02,348.24L898.44,349.43L902.04,348.53ZM843.40,325.14L838.16,327.16L836.63,329.70L826.38,329.93L821.29,332.89L817.48,332.79L813.13,330.53L813.19,328.97L815.00,327.98L815.24,325.11L813.16,317.64L808.53,308.53L809.73,309.71L808.81,307.19L810.97,309.03L808.68,303.82L809.91,300.21L809.62,298.62L810.74,296.66L810.95,298.74L812.10,296.86L817.71,293.79L819.70,293.92L824.63,291.76L829.00,291.02L832.77,286.98L832.96,284.41L834.87,282.10L836.01,284.45L837.17,283.90L836.20,282.62L837.06,281.30L838.26,281.89L838.59,279.82L842.14,276.18L843.34,276.50L843.39,275.81L845.90,275.05L849.42,277.92L852.86,278.19L852.28,276.70L854.81,273.80L854.39,273.12L855.57,271.57L857.22,270.61L860.90,270.42L860.85,269.03L858.86,268.13L860.31,267.73L868.31,270.78L871.56,269.72L872.81,271.06L871.05,273.62L870.12,273.71L870.43,274.80L868.86,278.27L881.70,285.65L883.49,284.72L884.58,282.05L885.74,278.39L885.70,271.22L887.96,266.48L890.70,272.38L891.79,277.04L893.53,276.02L895.74,278.23L896.04,281.77L898.50,289.05L905.20,292.95L904.84,293.61L907.46,298.26L908.54,297.66L909.65,298.84L910.31,298.42L910.78,301.31L916.11,306.22L916.75,311.65L918.05,313.96L916.20,323.57L915.00,326.05L912.99,327.38L909.23,334.55L908.33,339.32L906.77,340.26L903.72,340.36L898.31,343.70L894.39,342.02L894.81,340.60L890.94,343.09L882.85,340.94L881.09,339.26L879.95,335.82L878.61,334.71L876.00,334.38L876.89,333.06L876.23,331.04L874.90,332.93L872.48,333.43L875.37,329.02L875.15,327.00L871.24,330.25L870.19,332.42L868.07,331.30L868.15,329.85L865.01,326.86L865.52,326.23L857.50,323.18L843.40,325.14Z"/>
    <path id="LK" class="country" data-iso2="LK" data-iso3="LKA" data-name="Sri Lanka" d="M722.64,216.96L722.23,219.79L718.73,221.19L717.43,219.03L716.95,215.11L718.18,210.70L720.06,212.21L722.64,216.96Z"/>
    <path id="CN" class="country" data-iso2="CN" data-iso3="CHN" data-name="China" d="M798.02,187.90L795.78,187.06L795.70,184.72L797.05,183.48L801.59,182.78L802.19,183.82L800.37,186.59L798.02,187.90ZM718.49,122.15L718.27,120.60L720.14,119.89L717.69,115.16L724.47,113.47L726.44,108.60L731.84,109.49L733.35,108.26L733.48,105.53L735.74,105.28L738.88,103.24L739.59,105.14L745.76,107.61L747.64,109.80L746.59,112.98L747.57,114.16L754.48,115.01L759.45,117.00L762.28,121.13L774.52,121.30L785.74,124.20L788.91,122.74L797.39,121.69L804.42,118.36L803.12,116.42L804.54,114.66L808.87,115.46L815.74,112.96L819.65,110.39L825.75,110.33L826.05,109.36L821.40,106.59L819.30,107.60L815.08,107.52L814.38,106.40L817.63,101.63L820.89,102.66L824.73,100.94L824.71,99.74L828.68,95.98L828.64,94.48L827.15,93.83L829.40,92.48L832.78,91.99L836.39,91.91L842.85,93.73L847.51,101.98L852.25,102.85L855.47,104.79L856.58,107.34L860.71,107.35L867.57,105.47L862.32,114.55L859.02,114.06L856.68,115.03L857.40,117.36L857.00,120.57L855.61,120.65L855.63,122.03L853.87,120.42L852.79,121.95L848.59,123.12L849.01,124.56L845.37,123.61L838.28,128.74L829.54,131.55L830.98,130.29L830.41,129.23L832.57,127.40L831.13,125.97L825.69,128.83L824.01,130.59L821.34,130.72L819.95,131.99L821.38,133.83L823.61,134.27L823.70,135.50L825.86,136.29L828.91,134.35L833.09,135.48L833.53,136.91L829.67,137.67L824.36,142.41L827.29,143.90L831.86,151.17L831.82,153.19L830.11,153.93L830.76,155.38L832.36,156.23L831.25,160.60L829.73,160.85L823.01,170.62L815.48,175.42L812.41,175.73L810.75,176.94L809.81,176.06L808.27,177.41L801.58,179.19L800.65,182.07L799.14,182.23L798.43,180.25L799.08,179.20L791.40,178.06L790.10,176.96L790.53,175.39L786.73,173.87L784.41,175.32L779.59,175.62L776.72,176.68L777.13,179.80L775.68,179.72L775.35,177.96L773.36,178.75L770.16,177.23L770.95,174.97L769.22,174.44L768.58,171.93L765.70,172.39L766.03,169.16L768.61,166.88L768.64,162.55L766.54,160.30L762.01,160.10L762.93,158.95L761.65,157.26L759.71,158.41L757.43,157.74L751.81,161.50L749.62,161.84L745.04,160.41L741.77,163.12L741.54,160.98L739.88,161.55L733.63,160.66L729.31,158.93L728.39,157.62L724.11,155.46L721.93,154.62L720.80,155.27L714.34,151.65L713.58,148.65L715.54,149.01L715.62,147.62L714.54,146.23L714.82,144.01L711.89,140.82L707.41,139.72L706.61,137.62L704.11,135.57L703.80,132.96L701.25,132.62L700.56,130.10L701.34,129.48L700.96,128.84L703.56,127.55L708.32,127.39L709.35,125.65L712.84,125.32L718.49,122.15Z"/>
    <path id="TW" class="country" data-iso2="TW" data-iso3="TWN" data-name="Taiwan" d="M831.51,171.03L829.87,175.40L828.70,177.63L826.96,173.31L830.74,168.58L831.98,169.39L831.51,171.03Z"/>
    <path id="IT" class="country" data-iso2="IT" data-iso3="ITA" data-name="Italy" d="M528.43,109.78L530.08,110.17L533.08,109.18L533.69,110.13L537.58,110.83L537.94,113.33L535.77,112.93L533.56,113.90L533.38,116.03L534.27,117.41L536.82,118.78L538.19,121.03L541.22,123.23L543.35,123.21L544.02,123.81L543.25,124.36L550.03,127.58L549.80,129.07L548.29,127.79L545.92,127.35L544.78,129.11L546.74,130.12L546.42,131.54L542.70,134.24L543.85,131.37L541.96,128.42L530.47,122.14L528.62,120.57L527.77,117.88L524.20,116.66L520.24,118.49L520.55,117.31L519.08,116.97L518.37,114.86L519.32,114.03L518.63,112.24L519.80,112.82L522.64,111.77L524.41,112.12L525.00,111.02L528.21,110.90L528.43,109.78ZM540.18,133.60L542.25,133.37L541.11,137.75L533.84,135.05L534.22,133.65L540.18,133.60ZM523.71,126.10L525.07,125.26L526.70,127.19L526.32,130.79L523.97,131.53L522.94,130.80L522.21,125.96L523.71,126.10Z"/>
    <path id="DK" class="country" data-iso2="DK" data-iso3="DNK" data-name="Denmark" d="M527.01,87.76L523.21,87.82L522.11,86.31L522.02,83.52L523.26,81.97L528.80,80.29L527.90,82.57L529.71,83.75L526.27,86.44L527.01,87.76ZM533.68,84.69L534.55,86.06L532.91,88.26L530.06,86.72L529.68,85.59L533.68,84.69Z"/>
    <path id="GB" class="country" data-iso2="GB" data-iso3="GBR" data-name="United Kingdom" d="M483.13,90.80L479.39,90.28L479.95,88.82L479.39,87.36L481.67,87.25L484.59,88.93L483.13,90.80ZM491.58,92.06L491.98,90.48L490.12,88.76L486.16,87.55L487.15,86.33L486.26,85.58L484.79,86.87L484.63,84.25L483.26,82.86L484.25,80.04L486.36,77.84L491.82,77.82L488.91,80.77L494.67,80.41L493.96,82.63L491.51,85.07L494.32,85.24L496.96,88.74L498.83,89.17L501.28,93.35L504.58,93.87L504.25,95.61L502.86,96.41L503.95,97.82L501.50,99.24L493.22,99.97L491.95,99.43L490.15,100.71L487.63,100.40L485.72,101.44L484.27,100.89L488.27,98.03L490.70,97.45L486.43,96.99L485.66,95.91L488.51,95.06L487.01,93.60L487.53,91.81L491.58,92.06Z"/>
    <path id="IS" class="country" data-iso2="IS" data-iso3="ISL" data-name="Iceland" d="M460.50,56.53L459.88,58.29L462.95,60.15L459.41,62.23L449.21,64.59L438.03,63.33L440.71,62.12L434.79,60.79L439.61,60.26L439.49,59.46L433.78,58.83L435.62,57.06L439.74,56.66L443.99,58.50L448.12,57.02L451.55,57.79L455.99,56.34L460.50,56.53Z"/>
    <path id="AZ" class="country" data-iso2="AZ" data-iso3="AZE" data-name="Azerbaijan" d="M626.32,123.49L630.16,125.42L632.26,123.63L635.07,126.99L637.18,127.85L634.94,128.07L633.07,133.12L630.70,131.83L631.63,130.49L630.83,129.69L626.60,131.90L626.54,130.01L624.16,128.82L624.93,127.96L622.43,125.15L626.59,125.65L625.62,123.86L626.32,123.49ZM625.61,131.98L623.75,131.62L621.94,129.33L624.51,129.98L625.61,131.98Z"/>
    <path id="GE" class="country" data-iso2="GE" data-iso3="GEO" data-name="Georgia" d="M608.77,119.20L615.41,119.78L619.59,121.60L623.78,121.74L626.32,123.49L625.62,123.86L626.96,125.33L623.09,124.71L618.64,125.58L616.02,124.24L613.12,124.37L612.85,121.35L608.77,119.20Z"/>
    <path id="PH" class="country" data-iso2="PH" data-iso3="PHL" data-name="Philippines" d="M828.94,202.85L827.55,200.78L829.88,200.88L830.82,201.86L830.10,204.21L828.94,202.85ZM833.71,210.27L834.69,207.82L836.19,207.66L835.75,209.49L837.77,206.86L837.51,209.46L834.82,212.88L833.15,211.00L833.71,210.27ZM844.03,214.53L844.46,217.87L843.54,220.36L842.54,217.58L841.27,218.96L842.14,220.97L841.36,222.25L838.15,220.67L837.39,218.70L838.22,217.40L836.49,216.11L832.34,218.66L831.89,217.86L832.96,215.57L836.16,213.77L837.12,215.01L839.19,214.26L839.64,213.05L841.56,212.97L841.40,210.87L843.61,212.16L844.03,214.53ZM822.60,212.08L818.97,214.66L825.34,206.49L825.82,208.71L822.60,212.08ZM833.03,187.83L832.59,188.96L833.51,190.91L832.80,193.17L831.19,194.07L831.37,198.43L834.02,198.41L837.42,199.92L837.77,203.31L834.64,200.55L833.94,201.54L832.21,199.91L828.38,199.72L829.37,197.90L828.55,197.27L828.20,198.25L826.45,195.50L826.35,192.89L827.45,193.79L828.62,187.06L831.94,187.84L832.78,187.14L833.03,187.83ZM832.22,206.36L831.79,205.07L835.16,205.91L835.11,207.04L832.12,209.02L832.22,206.36ZM841.65,204.33L842.41,207.37L840.31,206.65L841.03,209.24L839.74,209.85L839.62,207.94L838.81,207.79L838.38,206.15L839.98,206.36L839.95,205.33L838.28,203.25L840.90,203.31L841.65,204.33Z"/>
    <path id="MY" class="country" data-iso2="MY" data-iso3="MYS" data-name="Malaysia" d="M772.46,219.84L772.93,219.36L775.15,220.55L775.36,221.95L777.16,221.62L778.05,220.50L780.28,222.40L781.43,224.22L781.76,229.84L783.73,233.92L781.80,234.10L776.01,229.92L772.76,222.98L772.46,219.84ZM820.90,226.18L815.41,225.72L812.02,233.54L809.80,234.12L807.23,233.36L804.34,234.98L800.84,235.33L798.98,233.80L798.53,231.98L800.52,232.91L802.63,232.40L803.17,230.10L807.60,228.99L810.89,225.12L812.13,226.53L812.70,225.60L814.00,225.69L814.28,222.61L817.75,218.59L818.85,218.58L820.38,221.14L824.44,222.72L824.25,223.78L822.42,223.92L822.91,225.25L820.90,226.18Z"/>
    <path id="BN" class="country" data-iso2="BN" data-iso3="BRN" data-name="Brunei" d="M814.28,222.61L814.00,225.69L812.70,225.60L812.13,226.53L810.89,225.12L814.28,222.61Z"/>
    <path id="SI" class="country" data-iso2="SI" data-iso3="SVN" data-name="Slovenia" d="M537.58,110.83L544.11,109.90L545.09,110.85L542.93,111.57L541.73,113.71L537.34,113.58L537.94,113.33L537.58,110.83Z"/>
    <path id="FI" class="country" data-iso2="FI" data-iso3="FIN" data-name="Finland" d="M577.83,49.43L577.44,51.34L581.61,53.15L579.09,55.20L582.26,58.30L580.43,60.63L582.88,62.66L581.76,64.43L585.79,66.30L584.77,67.69L576.41,72.74L562.26,74.52L558.04,72.15L558.65,69.46L557.33,67.01L558.63,65.42L569.14,60.19L568.86,59.04L564.15,56.69L564.08,52.50L556.20,49.32L557.83,48.60L560.86,50.04L567.34,50.56L569.93,49.35L571.27,47.36L575.49,46.44L578.99,47.52L577.83,49.43Z"/>
    <path id="SK" class="country" data-iso2="SK" data-iso3="SVK" data-name="Slovakia" d="M561.41,103.82L559.54,105.90L556.63,105.07L548.61,107.43L546.22,106.44L545.95,105.49L550.51,102.70L552.60,102.49L553.97,103.46L558.82,102.77L561.41,103.82Z"/>
    <path id="CZ" class="country" data-iso2="CZ" data-iso3="CZE" data-name="Czechia" d="M540.88,98.32L544.21,99.43L544.04,100.18L545.51,100.74L545.92,100.04L547.79,100.34L548.05,101.19L550.07,101.36L551.32,102.70L546.17,105.15L541.52,103.94L539.03,105.26L534.09,102.56L533.32,100.60L538.95,98.29L540.88,98.32Z"/>
    <path id="ER" class="country" data-iso2="ER" data-iso3="ERI" data-name="Eritrea" d="M599.17,198.18L600.32,191.28L604.56,188.44L606.89,194.09L617.28,202.87L615.29,203.30L611.33,199.01L608.96,197.91L606.44,197.31L604.84,197.95L603.19,196.72L602.34,198.75L599.17,198.18Z"/>
    <path id="JP" class="country" data-iso2="JP" data-iso3="JPN" data-name="Japan" d="M886.24,130.78L883.72,133.52L883.77,136.33L882.74,138.50L883.22,139.87L881.80,141.79L878.32,143.07L873.54,143.23L869.66,146.34L867.83,145.29L867.72,143.26L856.57,145.19L859.33,147.20L857.52,151.82L855.76,152.97L854.44,151.91L855.11,149.46L853.38,148.67L852.28,146.80L854.85,145.96L861.01,140.98L866.43,140.17L869.34,140.73L872.19,135.89L874.01,137.19L879.55,133.41L881.26,130.08L880.79,127.02L881.94,125.30L884.84,124.80L886.32,128.57L886.24,130.78ZM893.67,117.77L895.60,116.61L896.20,119.67L892.16,120.42L889.78,123.12L885.50,121.26L884.02,124.24L880.99,124.28L880.61,121.57L881.96,119.48L884.87,119.33L886.47,113.44L889.67,116.27L893.67,117.77ZM860.34,146.34L861.85,144.72L863.40,145.03L864.52,143.89L866.52,144.48L866.86,145.41L865.33,147.06L864.21,146.18L862.82,146.82L862.10,148.41L860.32,147.63L860.34,146.34Z"/>
    <path id="PY" class="country" data-iso2="PY" data-iso3="PRY" data-name="Paraguay" d="M341.66,292.36L342.46,293.88L342.28,297.57L348.11,298.30L349.19,302.66L352.20,302.83L350.85,309.91L348.38,311.99L346.23,312.43L340.43,311.28L343.11,307.14L342.72,305.94L334.36,302.45L329.36,298.01L331.80,290.89L339.08,290.13L341.61,291.53L341.66,292.36Z"/>
    <path id="YE" class="country" data-iso2="YE" data-iso3="YEM" data-name="Yemen" d="M641.56,185.72L644.57,192.11L642.60,192.84L642.01,194.98L634.95,197.40L632.52,199.32L624.20,201.26L622.47,202.87L618.37,203.04L615.98,196.03L618.09,189.58L619.21,190.29L627.26,190.39L627.94,191.30L629.21,190.84L631.17,187.99L633.71,186.76L641.56,185.72Z"/>
    <path id="SA" class="country" data-iso2="SA" data-iso3="SAU" data-name="Saudi Arabia" d="M595.16,157.52L598.19,157.96L600.02,156.14L602.09,155.76L603.44,154.39L600.73,151.67L606.70,149.89L614.03,152.53L621.71,158.01L629.20,158.49L629.87,159.78L631.80,159.71L632.87,162.06L636.53,164.78L636.76,167.73L638.32,170.05L639.89,170.40L641.56,174.82L649.74,176.20L650.29,175.62L651.54,177.55L649.72,182.99L641.56,185.72L633.71,186.76L631.17,187.99L629.21,190.84L627.94,191.30L627.26,190.39L619.21,190.29L618.09,189.58L617.65,192.07L616.45,192.94L611.45,184.39L608.35,182.07L606.55,179.48L606.35,175.97L604.79,172.95L602.04,171.33L600.54,167.74L595.63,161.04L594.28,161.06L595.16,157.52Z"/>
    <path id="AQ" class="country" data-iso2="AQ" data-iso3="ATA" data-name="Antarctica" d="M367.53,449.90L372.97,449.31L380.44,451.07L382.04,455.29L362.58,458.01L352.55,456.94L353.03,455.82L361.19,454.17L367.53,449.90ZM319.54,455.91L331.54,456.29L335.01,454.21L337.83,455.33L336.23,457.94L324.45,457.73L319.54,455.91ZM298.78,431.45L303.80,431.24L304.70,426.65L306.25,425.37L308.76,424.94L312.91,429.37L313.98,431.82L312.75,433.90L306.52,434.81L302.94,434.76L304.28,433.69L298.04,434.44L295.96,433.64L295.80,432.52L298.78,431.45ZM221.43,433.15L236.52,433.31L238.12,434.86L225.65,434.80L221.43,433.15ZM166.20,437.95L166.78,437.04L173.55,437.95L176.81,437.47L172.70,439.13L166.20,437.95ZM153.51,437.42L155.48,436.83L162.36,438.54L157.24,438.17L153.51,437.42ZM54.34,451.39L55.99,450.38L61.05,450.81L65.85,452.62L66.60,453.85L61.37,454.22L54.34,451.39ZM990.00,468.05L990.00,482.44L10.00,482.44L10.00,468.05L12.56,466.49L17.47,467.34L21.35,466.43L25.29,467.56L29.36,466.27L37.36,465.79L45.33,467.66L69.69,469.85L77.53,469.10L95.66,470.49L110.43,468.94L111.02,467.66L91.50,466.91L89.21,465.85L81.90,465.26L84.41,461.90L83.88,460.78L73.05,458.22L85.96,457.95L89.90,458.86L101.42,456.14L100.46,455.02L92.94,453.47L77.16,452.67L69.75,449.84L68.89,446.75L72.68,447.87L81.48,447.23L83.72,448.40L88.04,448.14L102.27,445.63L101.21,443.60L102.00,442.64L105.52,442.16L107.12,443.07L131.92,439.71L170.41,440.29L180.22,438.96L183.63,439.55L189.82,438.11L194.30,440.83L197.12,440.03L207.20,442.11L214.50,441.47L226.02,442.43L227.46,441.25L224.37,439.39L220.85,439.17L219.30,438.16L217.76,435.12L230.13,435.92L234.07,437.68L237.75,437.84L248.36,436.61L254.76,437.04L257.10,434.96L259.29,436.19L265.85,436.40L268.09,437.47L278.22,438.48L281.42,436.51L292.51,438.80L296.13,438.53L312.34,436.19L316.61,434.75L316.93,432.45L313.41,427.23L316.45,422.96L315.59,420.72L326.79,414.10L342.63,409.68L344.22,410.37L339.27,412.66L335.00,412.50L331.16,413.84L329.46,415.70L330.90,417.62L326.47,418.48L321.67,421.41L321.25,422.42L323.64,424.40L327.96,425.89L331.75,429.95L334.79,436.61L334.41,438.05L331.32,440.08L327.70,440.45L324.82,442.32L310.00,444.94L307.81,446.06L289.73,446.27L290.59,447.34L299.49,449.52L287.87,450.80L287.60,452.99L294.85,455.92L337.51,461.68L341.51,463.98L364.54,459.92L383.47,460.88L389.01,458.91L422.28,456.14L419.19,454.22L419.19,453.20L402.98,453.74L402.23,452.72L402.61,450.70L421.37,446.16L438.86,444.61L452.30,441.95L457.26,440.24L458.06,439.17L455.18,438.53L457.95,436.56L466.53,434.53L471.97,431.44L479.81,432.61L481.30,430.53L488.18,431.97L498.20,431.33L499.38,432.45L517.08,429.25L521.08,427.71L523.10,428.40L525.93,428.03L529.45,430.27L536.54,427.92L540.11,428.08L541.18,429.09L543.42,428.08L552.43,427.71L558.40,428.19L561.44,429.89L573.76,429.25L587.08,427.07L592.20,423.92L598.44,425.95L601.27,425.73L605.21,427.39L614.22,424.18L626.59,421.46L629.15,421.78L633.36,420.08L638.16,419.49L638.70,418.53L640.99,417.78L648.45,416.61L653.41,417.04L659.92,420.61L667.22,422.42L669.83,422.58L674.36,420.93L687.53,422.37L689.67,425.89L689.35,427.12L684.60,428.83L684.97,429.89L688.01,429.84L684.97,433.04L690.20,434.16L693.35,433.68L701.08,427.65L711.37,426.53L715.37,423.44L725.34,420.40L736.16,420.24L738.13,419.49L739.52,417.68L741.81,419.70L744.10,420.24L756.37,420.13L760.74,420.88L771.46,420.50L779.93,415.92L789.05,419.65L800.09,419.01L809.26,416.77L814.70,419.01L826.21,420.56L835.44,418.42L850.63,419.17L866.84,417.68L867.69,415.22L869.40,415.97L871.90,419.22L874.20,419.70L896.06,419.60L897.98,420.45L897.44,421.46L899.20,422.26L905.17,423.60L915.15,424.93L918.24,424.99L920.00,424.08L926.87,426.32L933.33,426.91L939.83,429.57L955.45,430.27L966.06,432.61L960.84,437.95L952.15,439.92L947.08,442.85L945.27,444.99L945.06,447.23L948.47,450.27L953.53,450.64L954.60,451.82L940.36,452.94L934.98,457.79L945.64,461.74L959.77,464.30L961.16,465.63L969.00,466.22L971.55,467.23L979.07,466.54L990.00,468.05Z"/>
    <path id="CY" class="country" data-iso2="CY" data-iso3="CYP" data-name="Cyprus" d="M589.10,141.78L590.88,141.72L592.57,142.22L589.78,143.33L587.81,141.88L589.10,141.78Z"/>
    <path id="MA" class="country" data-iso2="MA" data-iso3="MAR" data-name="Morocco" d="M494.09,141.70L496.94,148.55L496.44,149.61L490.07,151.32L489.95,153.33L486.77,154.41L485.73,155.77L476.39,158.93L476.06,163.61L468.99,164.26L465.97,170.01L462.19,172.95L459.84,178.91L453.67,179.12L456.49,172.86L458.92,170.69L460.69,165.97L462.50,164.98L465.65,161.11L468.18,160.81L473.96,155.95L473.28,152.57L474.68,148.79L476.43,146.95L481.18,144.58L483.86,140.09L485.86,140.11L487.50,141.26L494.09,141.70Z"/>
    <path id="EG" class="country" data-iso2="EG" data-iso3="EGY" data-name="Egypt" d="M600.36,177.55L568.06,177.55L568.06,157.84L567.24,155.65L567.52,152.81L568.50,151.50L572.13,151.46L578.71,153.40L584.33,151.54L586.26,151.88L587.00,153.23L587.64,152.34L591.94,153.14L593.28,152.45L595.07,157.13L592.98,161.70L592.34,162.17L590.21,160.08L587.98,156.42L592.84,166.27L597.16,172.31L596.71,174.55L600.36,177.55Z"/>
    <path id="LY" class="country" data-iso2="LY" data-iso3="LBY" data-name="Libya" d="M568.06,177.55L568.06,182.99L564.93,182.99L564.89,184.14L543.18,173.71L538.50,176.21L536.97,174.72L532.67,173.54L529.32,170.57L528.05,171.07L525.37,166.40L526.45,165.27L526.84,158.60L525.81,154.94L527.14,154.30L527.09,152.03L531.12,149.32L531.28,147.23L541.50,149.61L542.78,152.03L551.96,155.05L554.59,153.09L553.96,151.00L556.77,148.40L562.33,148.59L563.26,149.81L567.84,150.60L568.50,151.50L567.52,152.81L567.24,155.65L568.06,157.84L568.06,177.55Z"/>
    <path id="ET" class="country" data-iso2="ET" data-iso3="ETH" data-name="Ethiopia" d="M630.09,215.65L622.40,223.82L618.85,223.94L613.94,226.77L612.08,226.77L610.98,225.85L607.69,228.12L603.77,227.64L600.33,225.33L598.43,225.33L597.50,224.44L597.50,222.91L596.09,222.45L594.48,219.49L591.38,216.44L589.71,216.25L590.64,214.70L592.08,214.63L593.26,208.50L597.63,203.20L599.17,198.18L602.34,198.75L603.19,196.72L604.84,197.95L606.44,197.31L608.96,197.91L613.24,200.82L615.29,203.30L613.41,205.78L613.67,207.36L616.45,207.69L615.85,208.66L618.90,212.44L627.80,215.67L630.09,215.65Z"/>
    <path id="DJ" class="country" data-iso2="DJ" data-iso3="DJI" data-name="Djibouti" d="M615.29,203.30L617.28,202.87L617.92,203.71L617.84,204.84L616.28,205.49L617.45,206.24L616.45,207.69L613.67,207.36L613.41,205.78L615.29,203.30Z"/>
    <path id="UG" class="country" data-iso2="UG" data-iso3="UGA" data-name="Uganda" d="M592.29,240.03L583.76,240.20L580.52,241.09L581.33,235.81L584.86,231.44L583.77,231.07L583.94,227.89L585.06,227.14L586.79,227.75L590.90,227.12L592.57,225.87L593.86,227.76L595.38,232.25L592.27,237.14L592.29,240.03Z"/>
    <path id="RW" class="country" data-iso2="RW" data-iso3="RWA" data-name="Rwanda" d="M582.81,240.53L583.89,242.06L583.73,243.67L581.50,243.83L580.67,245.38L579.01,245.17L579.74,241.85L582.81,240.53Z"/>
    <path id="BA" class="country" data-iso2="BA" data-iso3="BIH" data-name="Bosnia and Herz." d="M550.52,121.34L544.80,117.55L542.88,115.43L543.44,114.30L552.72,115.31L552.04,116.51L553.35,117.56L552.96,118.84L550.92,119.84L550.52,121.34Z"/>
    <path id="MK" class="country" data-iso2="MK" data-iso3="MKD" data-name="Macedonia" d="M560.92,122.23L562.29,123.11L562.48,124.91L557.22,126.26L556.09,125.59L555.71,124.43L556.52,122.96L560.92,122.23Z"/>
    <path id="RS" class="country" data-iso2="RS" data-iso3="SRB" data-name="Serbia" d="M551.26,112.46L555.04,111.87L558.48,114.45L558.70,115.57L561.81,116.09L561.01,117.64L562.57,119.81L561.37,121.85L558.74,122.44L559.28,121.25L556.66,119.64L555.15,120.89L552.32,118.96L553.35,117.56L552.04,116.51L552.72,115.31L551.74,115.32L552.79,114.30L551.26,112.46Z"/>
    <path id="ME" class="country" data-iso2="ME" data-iso3="MNE" data-name="Montenegro" d="M554.64,121.50L553.73,121.23L552.73,123.44L550.23,121.80L550.92,119.84L552.32,118.96L555.37,120.66L554.64,121.50Z"/>
    <path id="XK" class="country" data-iso2="XK" data-iso3="XKX" data-name="Kosovo" d="M556.05,123.50L554.64,121.50L556.17,119.79L559.28,121.25L558.74,122.44L556.05,123.50Z"/>
    <path id="TT" class="country" data-iso2="TT" data-iso3="TTO" data-name="Trinidad and Tobago" d="M332.09,208.15L334.23,207.89L334.12,209.92L331.36,209.97L332.09,208.15Z"/>
    <path id="SS" class="country" data-iso2="SS" data-iso3="SSD" data-name="S. Sudan" d="M583.94,227.89L580.89,224.91L576.17,225.44L574.08,222.33L572.05,221.25L571.36,219.62L568.39,217.02L568.37,216.14L565.03,213.97L566.80,213.16L568.25,209.47L570.21,209.10L572.82,211.67L578.85,211.86L581.66,209.42L583.95,211.01L585.35,210.73L588.20,207.28L587.31,204.85L590.40,204.28L590.40,208.26L591.80,209.33L592.49,213.80L592.08,214.63L590.64,214.70L589.71,216.25L591.38,216.44L592.76,217.77L596.09,222.45L590.90,227.12L586.79,227.75L585.06,227.14L583.94,227.89Z"/>
  </g>
</svg>
      <div class="map-legend">
        <span><span class="legend-swatch"></span>Selected</span>
        <span><span class="legend-swatch inactive"></span>Not selected</span>
      </div>
    </div>
    <p class="note">Countries light up based on selected countries or zones.</p>
  </section>


  <section class="outputs">
    <h3>Generated URLs</h3>
    <p class="note">
      These URLs can be used in a <code>/tool fetch</code> + <code>/import</code> Mikrotik scheduler.
    </p>
    <p>
      <strong>custom.rsc</strong> (single address-list):
      <input type="text" id="url-custom" readonly placeholder="Click Generate to build the URL" />
      <button id="btn-custom">Generate custom.rsc URL</button>
      <button id="copy-custom">Copy</button>
    </p>
    <p>
      <strong>geoip.rsc</strong> (lists per country/zone):
      <input type="text" id="url-geoip" readonly placeholder="Click Generate to build the URL" />
      <button id="btn-geoip">Generate geoip.rsc URL</button>
      <button id="copy-geoip">Copy</button>
    </p>

    <h2>Quick usage (MikroTik ROS7)</h2>
    <p class="note">
      By default the script uses the last generated URL. Click one of the Generate buttons above
      to update the URL, then copy/paste the script below.
    </p>
    <pre><code id="mikrotik-script"></code></pre>
    <h3>Raw rules examples</h3>
    <p class="note">
      Include both lists (<code>-old</code>) to avoid blocking during updates. Replace names as needed.
    </p>
    <pre><code>/ip firewall raw
# 1) accept selected list(s), then drop all
add chain=prerouting action=accept src-address-list=geoip
add chain=prerouting action=accept src-address-list=geoip-old
add chain=prerouting action=drop

# 2) deny selected list(s)
add chain=prerouting action=drop src-address-list=geoip
add chain=prerouting action=drop src-address-list=geoip-old

# geoip.rsc example (prefix)
add chain=prerouting action=accept src-address-list=geoip-at
add chain=prerouting action=accept src-address-list=geoip-at-old</code></pre>
  </section>
</main>
<footer>
  WIFX SA -
  <a href="https://www.wifx.net" target="_blank" rel="noopener">www.wifx.net</a>
  <span style="color:#6b778c;">&nbsp;|&nbsp; GEOIP service (Made by ChatGPT ^^)</span>
</footer>
<script>
(function() {
  const ZONE_TO_COUNTRIES = {{ZONE_TO_COUNTRIES}};

  function getOrigin() {
    try {
      return window.location.origin || "";
    } catch (e) {
      return "";
    }
  }

  function collectSelection() {
    const ccs = Array.from(document.querySelectorAll("input.cc-checkbox:checked")).map(el => el.value);
    const zones = Array.from(document.querySelectorAll("input.zone-checkbox:checked")).map(el => el.value);
    return { ccs, zones };
  }

  function updateMap() {
    const active = new Set();
    const { ccs, zones } = collectSelection();

    ccs.forEach(cc => {
      if (cc) {
        active.add(cc.toUpperCase());
      }
    });

    zones.forEach(zone => {
      const members = ZONE_TO_COUNTRIES[zone] || [];
      members.forEach(cc => active.add(cc));
    });

    document.querySelectorAll(".country").forEach(el => {
      const code = (el.getAttribute("data-iso2") || el.id || "").toUpperCase();
      if (!code) return;
      if (active.has(code)) {
        el.classList.add("on");
      } else {
        el.classList.remove("on");
      }
    });
  }

  function buildParams(baseParams, ccs, zones, aggregateFlag) {
    const params = [];

    if (baseParams) {
      for (const [k, v] of Object.entries(baseParams)) {
        if (v) {
          params.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
        }
      }
    }

    if (aggregateFlag) {
      params.push("aggregate=1");
    }

    ccs.forEach(cc => params.push("cc=" + encodeURIComponent(cc)));
    zones.forEach(z => params.push("zone=" + encodeURIComponent(z)));

    return params.join("&");
  }

  function escapeMikrotikLine(line) {
    return line
      .replace(/\\\\(?!\\$)/g, "\\\\\\\\")
      .replaceAll('"', '\\\\\"');
  }

  function buildMikrotikScript(url) {
    const safeUrl = url || (getOrigin() + "/custom.rsc");
    const sourceLines = [
      "# name of RAM disk",
      ':local ramdisk "tmpfs1";',
      "",
      "# Check if RAM disk exists",
      ":if ([:len [/disk find slot=\\\\$ramdisk]] = 0) do={",
      '    :log warning "RAM disk <\\\\$ramdisk> missing - created...";',
        "    /disk add type=tmpfs tmpfs-max-size={{TMPFS_MAX_SIZE}} slot=\\\\$ramdisk;",
      "    :delay 1s;",
      "} else={",
      '    :log info "RAM disk <\\\\$ramdisk> already created";',
      "}",
      "",
      "# Download .rsc into RAM disk",
      '/tool fetch url="' + safeUrl + '" dst-path="\\\\$ramdisk/geoip.rsc";',
      ":delay 10",
      "# Import file",
      '/import file-name="\\\\$ramdisk/geoip.rsc" verbose=yes;',
    ];

    const encoded = sourceLines.map(escapeMikrotikLine);
    const bodyLines = encoded.map(function(line, idx) {
      if (idx === 0) return "    \\\"" + line + "\\\\r\\\\";
      if (idx === encoded.length - 1) return "    \\\\n" + line + "\\\"";
      return "    \\\\n" + line + "\\\\r\\\\";
    });

    const lines = [
      "/system script",
      "add dont-require-permissions=yes name=geoip-update policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon source=\\\\",
      ...bodyLines,
      "",
      "/system scheduler",
      "add interval=\\\"1d 00:00:00\\\" name=geoip-update on-event=geoip-update policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-time=startup",
    ];

    return lines.join("\\r\\n");
  }

  function updateMikrotikScript(url) {
    const scriptEl = document.getElementById("mikrotik-script");
    if (!scriptEl) return;
    scriptEl.textContent = buildMikrotikScript(url);
  }

  function generateCustomUrl() {
    const origin = getOrigin();
    const listInput = document.getElementById("list-name");
    const aggregateInput = document.getElementById("aggregate");
    const customInput = document.getElementById("custom-cidr");
    const out = document.getElementById("url-custom");

    const listName = (listInput && listInput.value.trim()) || "";
    const aggregateFlag = !!(aggregateInput && aggregateInput.checked);
    const customRaw = (customInput && customInput.value.trim()) || "";

    const { ccs, zones } = collectSelection();
    if (!ccs.length && !zones.length && !customRaw) {
        alert("Please select at least one country/zone or add custom list.");
      return null;
    }

    const baseParams = {};
    if (listName) baseParams["list"] = listName;
    if (customRaw) baseParams["custom"] = customRaw;

    const qs = buildParams(baseParams, ccs, zones, aggregateFlag);
    const url = (origin || "") + "/custom.rsc" + (qs ? "?" + qs : "");

    if (out) out.value = url;

    updateMikrotikScript(url);

    return url;
  }

  function generateGeoipUrl() {
    const origin = getOrigin();
    const prefixInput = document.getElementById("prefix");
    const aggregateInput = document.getElementById("aggregate");
    const customInput = document.getElementById("custom-cidr");
    const out = document.getElementById("url-geoip");

    let prefix = (prefixInput && prefixInput.value.trim()) || "";
    if (!prefix) {
      prefix = "geoip";
    }
    const aggregateFlag = !!(aggregateInput && aggregateInput.checked);
    const customRaw = (customInput && customInput.value.trim()) || "";

    const { ccs, zones } = collectSelection();
    if (!ccs.length && !zones.length && !customRaw) {
        alert("Please select at least one country/zone or add custom list.");
      return null;
    }

    const baseParams = {};
    if (prefix) baseParams["prefix"] = prefix;
    if (customRaw) baseParams["custom"] = customRaw;

    const qs = buildParams(baseParams, ccs, zones, aggregateFlag);
    const url = (origin || "") + "/geoip.rsc" + (qs ? "?" + qs : "");

    if (out) out.value = url;
    updateMikrotikScript(url);
    return url;
  }

  function setupButtons() {
    const countriesSelectAll = document.getElementById("countries-select-all");
    const zonesSelectAll = document.getElementById("zones-select-all");
    const countriesSearch = document.getElementById("countries-search");
    const countriesList = document.getElementById("countries-list");

    function syncSelectAll(selectAllEl, selector) {
      if (!selectAllEl) return;
      const boxes = Array.from(document.querySelectorAll(selector));
      if (!boxes.length) return;
      const allChecked = boxes.every(box => box.checked);
      const anyChecked = boxes.some(box => box.checked);
      selectAllEl.checked = allChecked;
      selectAllEl.indeterminate = !allChecked && anyChecked;
    }

    function toggleAll(selectAllEl, selector) {
      if (!selectAllEl) return;
      const boxes = Array.from(document.querySelectorAll(selector));
      boxes.forEach(box => { box.checked = selectAllEl.checked; });
      updateMap();
    }

    const btnCustom = document.getElementById("btn-custom");
    const btnGeoip = document.getElementById("btn-geoip");
    const copyCustom = document.getElementById("copy-custom");
    const copyGeoip = document.getElementById("copy-geoip");
    const outCustom = document.getElementById("url-custom");
    const outGeoip = document.getElementById("url-geoip");

    if (countriesSelectAll) {
      countriesSelectAll.addEventListener("change", function() {
        toggleAll(countriesSelectAll, "input.cc-checkbox");
      });
    }
    if (zonesSelectAll) {
      zonesSelectAll.addEventListener("change", function() {
        toggleAll(zonesSelectAll, "input.zone-checkbox");
      });
    }

    if (countriesSearch && countriesList) {
      const items = Array.from(countriesList.querySelectorAll("li"));
      countriesSearch.addEventListener("input", function() {
        const needle = (countriesSearch.value || "").trim().toLowerCase();
        items.forEach(function(item) {
          const text = (item.textContent || "").toLowerCase();
          const visible = !needle || text.includes(needle);
          item.classList.toggle("is-hidden", !visible);
        });
      });
    }

    if (btnCustom) {
      btnCustom.addEventListener("click", function() {
        generateCustomUrl();
        updateMap();
      });
    }
    if (btnGeoip) {
      btnGeoip.addEventListener("click", function() {
        generateGeoipUrl();
        updateMap();
      });
    }

    function copyField(input) {
      if (!input || !input.value) return;
      input.select();
      input.setSelectionRange(0, 99999);
      try { document.execCommand("copy"); } catch (e) {}
    }

    if (copyCustom && outCustom) {
      copyCustom.addEventListener("click", function() { copyField(outCustom); });
    }
    if (copyGeoip && outGeoip) {
      copyGeoip.addEventListener("click", function() { copyField(outGeoip); });
    }

    const checks = document.querySelectorAll("input.cc-checkbox, input.zone-checkbox");
    checks.forEach(function(el) {
      el.addEventListener("change", function() {
        updateMap();
        syncSelectAll(countriesSelectAll, "input.cc-checkbox");
        syncSelectAll(zonesSelectAll, "input.zone-checkbox");
      });
    });

    updateMap();
    updateMikrotikScript("");
    syncSelectAll(countriesSelectAll, "input.cc-checkbox");
    syncSelectAll(zonesSelectAll, "input.zone-checkbox");
  }

  document.addEventListener("DOMContentLoaded", setupButtons);
})();
</script>
</body>
</html>
"""

def render_index_html() -> str:
    # Known countries list (countries.yaml preferred, fallback to loaded data)
    country_items: List[str] = []
    if _country_catalog:
        country_codes = sorted(_country_catalog.keys())
    else:
        country_codes = sorted(_country_nets.keys())

    for code in country_codes:
        label = code.upper()
        if _country_catalog.get(code):
            label = f"{code.upper()} - {_country_catalog[code]}"
        country_items.append(
            f'<li><label><input type="checkbox" class="cc-checkbox" value="{code}" /> {label}</label></li>'
        )
    if not country_items:
        country_items.append("<li><em>No GEOIP data loaded yet...</em></li>")

    zone_items: List[str] = []
    for zone in sorted(ZONE_DEFS.keys()):
        label = zone
        if _zone_catalog.get(zone):
            label = f"{zone} - {_zone_catalog[zone]}"
        zone_items.append(
            f'<li><label><input type="checkbox" class="zone-checkbox" value="{zone}" /> {label}</label></li>'
        )
    if not zone_items:
        zone_items.append("<li><em>No zones defined.</em></li>")

    # Map data (zone to country list)
    zone_to_countries: Dict[str, List[str]] = {}
    for zone_name, members in ZONE_DEFS.items():
        zone_to_countries[zone_name] = [c.upper() for c in members]

    html = INDEX_HTML.replace("{{COUNTRIES}}", "\n".join(country_items))
    html = html.replace("{{ZONES}}", "\n".join(zone_items))
    html = html.replace("{{ZONE_TO_COUNTRIES}}", json.dumps(zone_to_countries))
    html = html.replace("{{TMPFS_MAX_SIZE}}", str(GEOIP_TMPFS_MAX_SIZE))
    return html


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(content=render_index_html())


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    if FAVICON_PATH.is_file():
        return FileResponse(FAVICON_PATH, media_type="image/svg+xml")
    return PlainTextResponse("", status_code=404)


@app.get("/health", response_class=PlainTextResponse)
def health():
    ts = _last_refresh_ts or 0
    age = int(time.time() - ts) if ts else -1
    return f"ok (last_refresh_age={age}s, countries={len(_country_nets)}, zones={len(ZONE_DEFS)})\n"


@app.get("/custom.rsc", response_class=PlainTextResponse)
def custom_rsc(
    cc: List[str] = Query([], alias="cc"),
    zone: List[str] = Query([], alias="zone"),
    list_name_param: Optional[str] = Query(None, alias="list"),
    aggregate_param: int = Query(0, alias="aggregate"),
    custom_param: Optional[str] = Query(None, alias="custom"),
):
    """Combine all selected countries/zones into a single address-list.

    - Default list name: geoip
    - Comment: country code or zone name for each entry
    - Option aggregate=1 to aggregate subnets per source
    """
    try:
        list_name = normalize_list_name(list_name_param)
        aggregate = bool(aggregate_param)
        custom_nets = parse_custom_cidrs(custom_param)

        selected_countries: List[str] = []
        selected_zones: List[str] = []

        for c_raw in cc:
            c = c_raw.strip().lower()
            if c and c in _country_nets and c not in selected_countries:
                selected_countries.append(c)

        for z_raw in zone:
            zkey = z_raw.strip().upper()
            if zkey and zkey in ZONE_DEFS and zkey not in selected_zones:
                selected_zones.append(zkey)

        if not selected_countries and not selected_zones and not custom_nets:
            raise ValueError("No valid countries or zones selected")

        lines: List[str] = []
        lines.append("/ip firewall address-list")

        any_entries = False
        old_list = list_old_name(list_name)
        lines.append(
            f':do {{ set [find list={list_name}] list={old_list} timeout=00:05:00 }} on-error={{}}'
        )
        seen: Set[str] = set()

        for c in sorted(selected_countries):
            nets = _country_nets.get(c, [])
            if not nets:
                continue
            nets_final = maybe_collapse_networks(nets, aggregate)
            for net in nets_final:
                key = net.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f'add list={list_name} address={key} dynamic=yes comment="{c.upper()}"'
                )
                any_entries = True

        for z in sorted(selected_zones):
            nets_zone: Set[ipaddress.IPv4Network] = set()
            for c in ZONE_DEFS[z]:
                if c in _country_nets:
                    nets_zone.update(_country_nets[c])
            if not nets_zone:
                continue
            nets_final = maybe_collapse_networks(nets_zone, aggregate)
            for net in nets_final:
                key = net.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f'add list={list_name} address={key} dynamic=yes comment="{z}"'
                )
                any_entries = True

        if custom_nets:
            nets_final = maybe_collapse_networks(custom_nets, aggregate)
            for net in nets_final:
                key = net.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f'add list={list_name} address={key} dynamic=yes comment="Custom"'
                )
                any_entries = True

        if not any_entries:
            raise ValueError("No networks resolved for selected countries/zones")

        script = "\n".join(lines) + "\n"
        return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")

    except Exception as e:
        print(f"[custom.rsc] error: {e}")
        err = ':log error "GEOIP custom link is wrong, please check online !"\n'
        return PlainTextResponse(content=err, media_type="text/plain; charset=utf-8")


@app.get("/geoip.rsc", response_class=PlainTextResponse)
def geoip_rsc(
    cc: List[str] = Query([], alias="cc"),
    zone: List[str] = Query([], alias="zone"),
    prefix_param: Optional[str] = Query(None, alias="prefix"),
    aggregate_param: int = Query(0, alias="aggregate"),
    custom_param: Optional[str] = Query(None, alias="custom"),
):
    """Generate separate lists for each country and each zone.

    - List name per country: <prefix>-<code> (default: geoip-ch, geoip-fr, ...)
    - List name per zone: <prefix>-<ZONE> (geoip-EU, geoip-US, ...)
    - No comment is added to entries.
    - Option aggregate=1 to aggregate subnets per list.
    """
    try:
        prefix = normalize_prefix(prefix_param, GEOIP_COUNTRY_PREFIX)
        aggregate = bool(aggregate_param)
        custom_nets = parse_custom_cidrs(custom_param)

        selected_countries: Set[str] = set()
        selected_zones: Set[str] = set()

        for c_raw in cc:
            c = c_raw.strip().lower()
            if c and c in _country_nets:
                selected_countries.add(c)

        for z_raw in zone:
            zkey = z_raw.strip().upper()
            if not zkey:
                continue
            if zkey in ZONE_DEFS:
                selected_zones.add(zkey)
                for c in ZONE_DEFS[zkey]:
                    if c in _country_nets:
                        selected_countries.add(c)

        if not selected_countries and not selected_zones and not custom_nets:
            raise ValueError("No valid countries or zones selected")

        list_names: Set[str] = set()

        for c in selected_countries:
            list_names.add(f"{prefix}-{c.lower()}")

        for z in selected_zones:
            list_names.add(f"{prefix}-{z}")

        if custom_nets:
            list_names.add(f"{prefix}-custom")

        lines: List[str] = []
        lines.append("/ip firewall address-list")

        # Entries per country
        for c in sorted(selected_countries):
            nets = _country_nets.get(c, [])
            if not nets:
                continue
            list_name = f"{prefix}-{c.lower()}"
            old_list = list_old_name(list_name)
            lines.append(
                f':do {{ set [find list={list_name}] list={old_list} timeout=00:05:00 }} on-error={{}}'
            )
            seen: Set[str] = set()
            nets_final = maybe_collapse_networks(nets, aggregate)
            for net in nets_final:
                key = net.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"add list={list_name} address={key} dynamic=yes"
                )

        # Entries per zone (union of zone countries)
        for z in sorted(selected_zones):
            list_name = f"{prefix}-{z}"
            nets_zone: Set[ipaddress.IPv4Network] = set()
            for c in ZONE_DEFS[z]:
                if c in selected_countries:
                    for net in _country_nets.get(c, []):
                        nets_zone.add(net)
            nets_final = maybe_collapse_networks(nets_zone, aggregate)
            old_list = list_old_name(list_name)
            lines.append(
                f':do {{ set [find list={list_name}] list={old_list} timeout=00:05:00 }} on-error={{}}'
            )
            seen: Set[str] = set()
            for net in nets_final:
                key = net.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"add list={list_name} address={key} dynamic=yes"
                )

        if custom_nets:
            list_name = f"{prefix}-custom"
            nets_final = maybe_collapse_networks(custom_nets, aggregate)
            old_list = list_old_name(list_name)
            lines.append(
                f':do {{ set [find list={list_name}] list={old_list} timeout=00:05:00 }} on-error={{}}'
            )
            seen: Set[str] = set()
            for net in nets_final:
                key = net.with_prefixlen
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"add list={list_name} address={key} dynamic=yes"
                )

        script = "\n".join(lines) + "\n"
        return PlainTextResponse(content=script, media_type="text/plain; charset=utf-8")

    except Exception as e:
        print(f"[geoip.rsc] error: {e}")
        err = ':log error "GEOIP geoip.rsc link is wrong, please check online !"\n'
        return PlainTextResponse(content=err, media_type="text/plain; charset=utf-8")


