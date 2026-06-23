"""
Geo-IP enrichment service.
Converts an IP address to a LocationInfo dict using ipapi.co.
"""
import hashlib
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.event import LocationInfo

logger = get_logger(__name__)
settings = get_settings()

_PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.", "::1", "fc", "fd")

MOCK_LOCATIONS = [
    {"city": "Beijing", "country": "China", "country_code": "CN", "flag": "🇨🇳", "region": "Beijing", "isp": "China Telecom", "latitude": 39.9042, "longitude": 116.4074},
    {"city": "Moscow", "country": "Russia", "country_code": "RU", "flag": "🇷🇺", "region": "Moscow", "isp": "Rostelecom", "latitude": 55.7558, "longitude": 37.6173},
    {"city": "New York", "country": "United States", "country_code": "US", "flag": "🇺🇸", "region": "New York", "isp": "Verizon", "latitude": 40.7128, "longitude": -74.0060},
    {"city": "Amsterdam", "country": "Netherlands", "country_code": "NL", "flag": "🇳🇱", "region": "North Holland", "isp": "KPN", "latitude": 52.3676, "longitude": 4.9041},
    {"city": "Frankfurt", "country": "Germany", "country_code": "DE", "flag": "🇩🇪", "region": "Hesse", "isp": "Deutsche Telekom", "latitude": 50.1109, "longitude": 8.6821},
    {"city": "São Paulo", "country": "Brazil", "country_code": "BR", "flag": "🇧🇷", "region": "São Paulo", "isp": "Telefonica Brasil", "latitude": -23.5505, "longitude": -46.6333},
    {"city": "Tokyo", "country": "Japan", "country_code": "JP", "flag": "🇯🇵", "region": "Tokyo", "isp": "NTT Communications", "latitude": 35.6762, "longitude": 139.6503},
    {"city": "London", "country": "United Kingdom", "country_code": "GB", "flag": "🇬🇧", "region": "England", "isp": "British Telecom", "latitude": 51.5074, "longitude": -0.1278},
    {"city": "Seoul", "country": "South Korea", "country_code": "KR", "flag": "🇰🇷", "region": "Seoul", "isp": "SK Broadband", "latitude": 37.5665, "longitude": 126.9780},
    {"city": "Sydney", "country": "Australia", "country_code": "AU", "flag": "🇦🇺", "region": "New South Wales", "isp": "Telstra", "latitude": -33.8688, "longitude": 151.2093},
]


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def get_mock_location(ip: str) -> dict:
    """Deterministically select a mock location for local/demo runs."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    idx = h % len(MOCK_LOCATIONS)
    loc = MOCK_LOCATIONS[idx].copy()
    # Add deterministic jitter (-0.4 to 0.4 degrees)
    jitter_lat = ((h % 100) / 125.0) - 0.4
    jitter_lng = (((h // 100) % 100) / 125.0) - 0.4
    loc["latitude"] = round(loc["latitude"] + jitter_lat, 4)
    loc["longitude"] = round(loc["longitude"] + jitter_lng, 4)
    return loc


async def _get_public_ip() -> str:
    """Fallback: resolve the machine's public IP."""
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get("https://api.ipify.org?format=json",
                             timeout=settings.GEOIP_TIMEOUT_SECONDS)
            r.raise_for_status()
            return r.json()["ip"]
    except Exception as exc:
        logger.warning("Could not resolve public IP: %s", exc)
        return "0.0.0.0"


def resolve_ip(ip: str | None) -> str:
    """Return the provided IP as-is, with a safe default for missing values."""
    if not ip or ip in ("", "unknown"):
        return "0.0.0.0"
    return ip


def get_country_flag(country_code: str) -> str:
    if not country_code or country_code == "XX":
        return "🌍"
    try:
        return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        return "🌍"


async def _check_abuse_ipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    if not settings.ABUSEIPDB_API_KEY:
        return {}
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        headers = {
            "Accept": "application/json",
            "Key": settings.ABUSEIPDB_API_KEY
        }
        async with httpx.AsyncClient() as client:
            r = await client.get(url, params=params, headers=headers, timeout=settings.GEOIP_TIMEOUT_SECONDS)
            r.raise_for_status()
            return r.json().get("data", {})
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return {}


async def lookup_location(ip: str) -> LocationInfo:
    """
    Resolve geographic info and threat intelligence for the given IP.
    Returns a LocationInfo with defaults/mock values on any failure.
    """
    # Start with a deterministic mock location so we ALWAYS have coordinates
    mock_data = get_mock_location(ip)
    
    loc = LocationInfo(
        city=mock_data["city"],
        country=mock_data["country"],
        country_code=mock_data["country_code"],
        flag=mock_data["flag"],
        region=mock_data["region"],
        isp=mock_data["isp"],
        latitude=mock_data["latitude"],
        longitude=mock_data["longitude"],
    )

    # 1. Private network check (return mock values directly so local testing looks great)
    if _is_private(ip):
        return loc

    # 2. Enrich with Threat Intelligence (AbuseIPDB)
    abuse_data = await _check_abuse_ipdb(ip)
    if abuse_data:
        loc.abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        loc.total_reports = abuse_data.get("totalReports", 0)
        loc.is_whitelisted = abuse_data.get("isWhitelisted", False)
        loc.usage_type = abuse_data.get("usageType", "Unknown")

    # 3. Resolve geographic info (ipapi.co)
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=settings.GEOIP_TIMEOUT_SECONDS,
            )
            r.raise_for_status()
            geo_data = r.json()
        
        if "error" not in geo_data and geo_data.get("city"):
            loc.city = geo_data.get("city", loc.city)
            loc.country = geo_data.get("country_name", loc.country)
            loc.country_code = geo_data.get("country_code", loc.country_code)
            loc.flag = get_country_flag(loc.country_code)
            loc.region = geo_data.get("region", loc.region)
            loc.isp = geo_data.get("org", loc.isp)
            if geo_data.get("latitude") and geo_data.get("longitude"):
                loc.latitude = float(geo_data["latitude"])
                loc.longitude = float(geo_data["longitude"])
    except Exception as exc:
        logger.debug("Geo-IP lookup failed for %s: %s", ip, exc)

    return loc
