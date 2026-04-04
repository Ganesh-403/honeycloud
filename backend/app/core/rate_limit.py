"""
Rate limiter singleton – lives here so routes can import it
without pulling in app.main (which would be a circular import).
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings

_settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{_settings.RATE_LIMIT_PER_MINUTE}/minute"],
)
