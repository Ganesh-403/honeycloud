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


def lookup_location(ip: str) -> LocationInfo:
    """
    Resolve geographic info for the given IP.
    Returns a LocationInfo with defaults on any failure.
    """
    if _is_private(ip):
        return LocationInfo(
            city="Local Network",
            country="LAN",
            country_code="LN",
            flag="🏠",
            region="Private",
            isp="Local ISP",
        )

    try:
        r = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=settings.GEOIP_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        data = r.json()
        if "error" in data or not data.get("city"):
            raise ValueError("No city in response")

        country_code = data.get("country_code", "XX")
        return LocationInfo(
            city=data.get("city", "Unknown"),
            country=data.get("country_name", "Unknown"),
            country_code=country_code,
            flag=get_country_flag(country_code),
            region=data.get("region", ""),
            isp=data.get("org", "Unknown ISP"),
        )
    except Exception as exc:
        logger.debug("Geo-IP lookup failed for %s: %s", ip, exc)
        return LocationInfo()
