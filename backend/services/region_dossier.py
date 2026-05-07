import logging
import time
import concurrent.futures
from urllib.parse import quote
import requests as _requests
from cachetools import TTLCache
from services.network_utils import fetch_with_curl

logger = logging.getLogger(__name__)

# Cache dossier results for 24 hours — country data barely changes
# Key: rounded lat/lng grid (0.1 degree ≈ 11km)
dossier_cache = TTLCache(maxsize=500, ttl=86400)

# Nominatim requires max 1 req/sec — track last call time
_nominatim_last_call = 0.0


def _reverse_geocode_offline(lat: float, lng: float) -> dict:
    """Offline fallback via reverse_geocoder when external reverse geocoding is blocked."""
    try:
        import reverse_geocoder as rg

        hit = rg.search((lat, lng), mode=1)[0]
        country_code = (hit.get("cc") or "").upper()
        city = hit.get("name") or ""
        state = hit.get("admin1") or ""
        display = ", ".join(part for part in [city, state, country_code] if part)
        return {
            "city": city,
            "state": state,
            "country": country_code or "Unknown",
            "country_code": country_code,
            "display_name": display,
            "offline_fallback": True,
        }
    except Exception as e:
        logger.warning(f"Offline reverse geocode failed: {e}")
        return {}


def _reverse_geocode(lat: float, lng: float) -> dict:
    global _nominatim_last_call
    url = (
        f"https://nominatim.openstreetmap.org/reverse?"
        f"lat={lat}&lon={lng}&format=json&zoom=10&addressdetails=1&accept-language=en"
    )
    headers = {
        "User-Agent": "ShadowBroker-OSINT/1.0 (live-risk-dashboard; contact@shadowbroker.app)"
    }

    for attempt in range(2):
        # Enforce Nominatim's 1 req/sec policy
        elapsed = time.time() - _nominatim_last_call
        if elapsed < 1.1:
            time.sleep(1.1 - elapsed)
        _nominatim_last_call = time.time()

        try:
            # Use requests directly — fetch_with_curl raises on non-200 which breaks 429 handling
            res = _requests.get(url, timeout=4, headers=headers)
            if res.status_code == 200:
                data = res.json()
                addr = data.get("address", {})
                return {
                    "city": addr.get("city")
                    or addr.get("town")
                    or addr.get("village")
                    or addr.get("county")
                    or "",
                    "state": addr.get("state") or addr.get("region") or "",
                    "country": addr.get("country") or "",
                    "country_code": (addr.get("country_code") or "").upper(),
                    "display_name": data.get("display_name", ""),
                }
            elif res.status_code == 429:
                logger.warning(
                    f"Nominatim 429 rate-limited, retrying after 1s (attempt {attempt+1})"
                )
                time.sleep(1)
                continue
            else:
                logger.warning(f"Nominatim returned {res.status_code}")
        except (_requests.RequestException, ConnectionError, TimeoutError, OSError) as e:
            logger.warning(f"Reverse geocode failed: {e}")
    return _reverse_geocode_offline(lat, lng)


def _fetch_country_data(country_code: str) -> dict:
    if not country_code:
        return {}
    url = (
        f"https://restcountries.com/v3.1/alpha/{country_code}"
        f"?fields=name,population,capital,languages,region,subregion,area,currencies,borders,flag"
    )
    try:
        res = fetch_with_curl(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, list):
                return data[0] if data and isinstance(data[0], dict) else {}
            return data if isinstance(data, dict) else {}
    except (ConnectionError, TimeoutError, ValueError, KeyError, OSError) as e:
        logger.warning(f"RestCountries failed for {country_code}: {e}")
    return {}


def _fetch_wikidata_leader(country_name: str) -> dict:
    if not country_name:
        return {"leader": "Unknown", "government_type": "Unknown"}
    # SPARQL: get head of state (P35) and form of government (P122) for a sovereign state
    safe_name = country_name.replace('"', '\\"').replace("'", "\\'")
    sparql = f"""
    SELECT ?leaderLabel ?govTypeLabel WHERE {{
      ?country wdt:P31 wd:Q6256 ;
               rdfs:label "{safe_name}"@en .
      OPTIONAL {{ ?country wdt:P35 ?leader . }}
      OPTIONAL {{ ?country wdt:P122 ?govType . }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }} LIMIT 1
    """
    url = f"https://query.wikidata.org/sparql?query={quote(sparql)}&format=json"
    try:
        res = fetch_with_curl(url, timeout=6)
        if res.status_code == 200:
            results = res.json().get("results", {}).get("bindings", [])
            if results:
                r = results[0]
                return {
                    "leader": r.get("leaderLabel", {}).get("value", "Unknown"),
                    "government_type": r.get("govTypeLabel", {}).get("value", "Unknown"),
                }
    except (ConnectionError, TimeoutError, ValueError, KeyError, OSError) as e:
        logger.warning(f"Wikidata SPARQL failed for {country_name}: {e}")
    return {"leader": "Unknown", "government_type": "Unknown"}


def _fetch_local_wiki_summary(place_name: str, country_name: str = "") -> dict:
    if not place_name:
        return {}
    # Try exact match first, then with country qualifier
    candidates = [place_name]
    if country_name:
        candidates.append(f"{place_name}, {country_name}")

    for name in candidates:
        slug = quote(name.replace(" ", "_"))
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{slug}"
        try:
            res = fetch_with_curl(url, timeout=5)
            if res.status_code == 200:
                data = res.json()
                if data.get("type") != "disambiguation":
                    return {
                        "description": data.get("description", ""),
                        "extract": data.get("extract", ""),
                        "thumbnail": data.get("thumbnail", {}).get("source", ""),
                    }
        except (
            ConnectionError,
            TimeoutError,
            ValueError,
            KeyError,
            OSError,
        ):  # Intentional: optional enrichment
            continue
    return {}


def get_region_dossier(lat: float, lng: float) -> dict:
    cache_key = f"{round(lat, 1)}_{round(lng, 1)}"
    if cache_key in dossier_cache:
        return dossier_cache[cache_key]

    # Step 1: Reverse geocode
    geo = _reverse_geocode(lat, lng)
    if not geo or not geo.get("country"):
        return {
            "coordinates": {"lat": lat, "lng": lng},
            "location": geo or {},
            "country": None,
            "local": None,
            "error": "No country data — possibly international waters or uninhabited area",
        }

    country_code = geo.get("country_code", "")
    country_name = geo.get("country", "")
    city_name = geo.get("city", "")
    state_name = geo.get("state", "")

    # Step 2: Parallel fetch with real timeouts that do not block on executor shutdown
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    try:
        country_fut = pool.submit(_fetch_country_data, country_code)
        leader_fut = pool.submit(_fetch_wikidata_leader, country_name)
        local_fut = pool.submit(
            _fetch_local_wiki_summary, city_name or state_name, country_name
        )
        country_wiki_fut = pool.submit(_fetch_local_wiki_summary, country_name, "")

        try:
            country_data = country_fut.result(timeout=6)
        except Exception:  # Intentional: optional enrichment
            logger.warning("Country data fetch timed out or failed")
            country_data = {}
        try:
            leader_data = leader_fut.result(timeout=6)
        except Exception:  # Intentional: optional enrichment
            logger.warning("Leader data fetch timed out or failed")
            leader_data = {"leader": "Unknown", "government_type": "Unknown"}
        try:
            local_data = local_fut.result(timeout=5)
        except Exception:  # Intentional: optional enrichment
            logger.warning("Local wiki fetch timed out or failed")
            local_data = {}
        try:
            country_wiki_data = country_wiki_fut.result(timeout=5)
        except Exception:  # Intentional: optional enrichment
            country_wiki_data = {}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # If no local data but we have country wiki summary, use that
    if not local_data.get("extract") and country_wiki_data.get("extract"):
        local_data = country_wiki_data

    # Build languages list
    languages = country_data.get("languages", {})
    lang_list = list(languages.values()) if isinstance(languages, dict) else []

    # Build currencies
    currencies = country_data.get("currencies", {})
    currency_list = []
    if isinstance(currencies, dict):
        for v in currencies.values():
            if isinstance(v, dict):
                symbol = v.get("symbol", "")
                name = v.get("name", "")
                currency_list.append(f"{name} ({symbol})" if symbol else name)

    result = {
        "coordinates": {"lat": lat, "lng": lng},
        "location": geo,
        "country": {
            "name": country_data.get("name", {}).get("common", country_name),
            "official_name": country_data.get("name", {}).get("official", ""),
            "leader": leader_data.get("leader", "Unknown"),
            "government_type": leader_data.get("government_type", "Unknown"),
            "population": country_data.get("population", 0),
            "capital": (
                (country_data.get("capital") or ["Unknown"])[0]
                if isinstance(country_data.get("capital"), list)
                else "Unknown"
            ),
            "languages": lang_list,
            "currencies": currency_list,
            "region": country_data.get("region", ""),
            "subregion": country_data.get("subregion", ""),
            "area_km2": country_data.get("area", 0),
            "flag_emoji": country_data.get("flag", ""),
        },
        "local": {
            "name": city_name,
            "state": state_name,
            "description": local_data.get("description", ""),
            "summary": local_data.get("extract", ""),
            "thumbnail": local_data.get("thumbnail", ""),
        },
    }

    dossier_cache[cache_key] = result
    return result


def lookup_for_recon_bridge(target: str) -> dict:
    """Recon-bridge GeoIP lookup. Returns at most {country, asn, org}.

    Resolves hostname/URL targets to an IP via DNS, then queries ip-api.com
    (free, no key, 45 req/min/IP). Returns {} on any failure — enrichment
    is opportunistic per spec §9, so misses are non-fatal.

    The aggregator already caches results for 60s, so call volume to
    ip-api.com stays bounded under normal use.
    """
    if not target:
        return {}

    ip = _resolve_target_to_ip(target)
    if not ip:
        return {}

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,org,as,query"
        res = _requests.get(url, timeout=5)
        if res.status_code != 200:
            return {}
        data = res.json()
    except (_requests.RequestException, ValueError, OSError) as exc:
        logger.warning("region_dossier ip-api lookup failed: %s", exc)
        return {}

    if data.get("status") != "success":
        return {}

    asn = _extract_asn_token(data.get("as") or "")
    fields = {
        "country": data.get("country"),
        "asn": asn,
        "org": data.get("org") or data.get("as"),
    }
    return {k: v for k, v in fields.items() if v}


def _resolve_target_to_ip(target: str) -> str | None:
    """URL/hostname/IP → IP. None on resolution failure.

    Handles IPv6 literals correctly — splitting on ':' as the original
    implementation did corrupted addresses like '2001:db8::1' into '2001'
    (which socket.gethostbyname then treated as an integer-form IPv4).
    Order matters here:
      1. Try parsing as a literal IP first (catches bare IPv4 + IPv6).
      2. urlparse for URL forms (it correctly handles bracketed IPv6).
      3. Fall back to hostname:port stripping for the hostname-with-port
         form, but ONLY if the leading segment is plausibly a hostname
         (not a colon-laden IPv6 fragment).
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    target = target.strip()

    # 1) Bare literal IP (v4 or v6) — return as-is.
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # 2) Bracketed IPv6 with optional port: '[2001:db8::1]:8080' or '[::1]'.
    if target.startswith("["):
        end = target.find("]")
        if end > 0:
            inner = target[1:end]
            try:
                ipaddress.ip_address(inner)
                return inner
            except ValueError:
                return None

    # 3) URL form — let urlparse extract the host.
    if "://" in target:
        host = (urlparse(target).hostname or "").strip()
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        return _resolve_dualstack(host)

    # 4) hostname[:port] form. We only strip a single trailing ':port'
    #    (and only if there's exactly one ':') so we don't shred IPv6.
    host = target.split("/", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]

    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    return _resolve_dualstack(host)


def _resolve_dualstack(host: str) -> str | None:
    """Resolve a hostname to an IPv4 or IPv6 address.

    Codex R2 P2: socket.gethostbyname() only handles A records (IPv4),
    so AAAA-only domains used to return None and silently drop enrichment.
    getaddrinfo handles both families in one call.
    """
    import socket

    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return None
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET and sockaddr:
            return sockaddr[0]
        if family == socket.AF_INET6 and sockaddr:
            return sockaddr[0]
    return None


def _extract_asn_token(as_field: str) -> str | None:
    """'AS15169 Google LLC' → 'AS15169'. None if no AS-prefixed token."""
    if not as_field or not as_field.strip():
        return None
    first = as_field.strip().split()[0]
    return first if first.startswith("AS") else None
