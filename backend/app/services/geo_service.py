"""
Geo-IP enrichment service.
Converts an IP address to a LocationInfo dict using ipapi.co.
"""
import requests

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.event import LocationInfo

logger = get_logger(__name__)
settings = get_settings()

_PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.", "::1", "fc", "fd")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _get_public_ip() -> str:
    """Fallback: resolve the machine's public IP."""
    try:
        r = requests.get("https://api.ipify.org?format=json",
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


def _check_abuse_ipdb(ip: str) -> dict:
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
        r = requests.get(url, params=params, headers=headers, timeout=settings.GEOIP_TIMEOUT_SECONDS)
        r.raise_for_status()
        return r.json().get("data", {})
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return {}


def lookup_location(ip: str) -> LocationInfo:
    """
    Resolve geographic info and threat intelligence for the given IP.
    Returns a LocationInfo with defaults on any failure.
    """
    # 1. Start with private network check
    if _is_private(ip):
        return LocationInfo(
            city="Local Network",
            country="LAN",
            country_code="LN",
            flag="🏠",
            region="Private",
            isp="Local ISP",
        )

    # 2. Enrich with Threat Intelligence (AbuseIPDB)
    abuse_data = _check_abuse_ipdb(ip)

    # 3. Resolve geographic info (ipapi.co)
    try:
        r = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=settings.GEOIP_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        geo_data = r.json()
        
        if "error" in geo_data or not geo_data.get("city"):
            # If geo lookup fails, try to use data from AbuseIPDB if available
            country_code = abuse_data.get("countryCode", "XX")
            return LocationInfo(
                city=abuse_data.get("city", "Unknown"),
                country=abuse_data.get("countryName", "Unknown"),
                country_code=country_code,
                flag=get_country_flag(country_code),
                isp=abuse_data.get("isp", "Unknown ISP"),
                abuse_score=abuse_data.get("abuseConfidenceScore", 0),
                total_reports=abuse_data.get("totalReports", 0),
                is_whitelisted=abuse_data.get("isWhitelisted", False),
                usage_type=abuse_data.get("usageType", "Unknown"),
            )

        country_code = geo_data.get("country_code", "XX")
        return LocationInfo(
            city=geo_data.get("city", "Unknown"),
            country=geo_data.get("country_name", "Unknown"),
            country_code=country_code,
            flag=get_country_flag(country_code),
            region=geo_data.get("region", ""),
            isp=geo_data.get("org", "Unknown ISP"),
            abuse_score=abuse_data.get("abuseConfidenceScore", 0) if abuse_data else 0,
            total_reports=abuse_data.get("totalReports", 0) if abuse_data else 0,
            is_whitelisted=abuse_data.get("isWhitelisted", False) if abuse_data else False,
            usage_type=abuse_data.get("usageType", "Unknown") if abuse_data else "Unknown",
        )
    except Exception as exc:
        logger.debug("Geo-IP lookup failed for %s: %s", ip, exc)
        # Return what we have from AbuseIPDB even if ipapi fails
        if abuse_data:
            cc = abuse_data.get("countryCode", "XX")
            return LocationInfo(
                country_code=cc,
                flag=get_country_flag(cc),
                isp=abuse_data.get("isp", "Unknown ISP"),
                abuse_score=abuse_data.get("abuseConfidenceScore", 0),
                total_reports=abuse_data.get("totalReports", 0),
                is_whitelisted=abuse_data.get("isWhitelisted", False),
                usage_type=abuse_data.get("usageType", "Unknown"),
            )
        return LocationInfo()
