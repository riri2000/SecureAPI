"""
Rate limiting global via slowapi (basé sur la librairie `limits`).

Stockage en mémoire par défaut (suffisant en dev / une seule instance) ;
passer RATE_LIMIT_STORAGE_URI=redis://... en production pour que la
limite soit partagée entre plusieurs instances de l'API derrière un
load balancer.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

storage_uri = settings.rate_limit_storage_uri or "memory://"

limiter = Limiter(key_func=get_remote_address, storage_uri=storage_uri)
