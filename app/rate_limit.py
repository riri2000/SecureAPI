"""Global rate limiting via slowapi.

In-memory storage by default (fine for dev / a single instance). Set
RATE_LIMIT_STORAGE_URI=redis://... in production so the limit is shared
across instances behind a load balancer.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

storage_uri = settings.rate_limit_storage_uri or "memory://"

limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri)
