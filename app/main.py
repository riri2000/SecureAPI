"""
Point d'entrée de l'application. Rassemble :
- les headers de sécurité HTTP (défense en profondeur, OWASP A05) ;
- une politique CORS explicite plutôt qu'un wildcard "*" ;
- le rate limiter global ;
- les routers auth et notes.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import Base, engine
from app.rate_limit import limiter
from app.routers import auth, notes

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecureAPI",
    description=(
        "API REST démontrant des mitigations concrètes contre les "
        "vulnérabilités les plus courantes de l'OWASP Top 10."
    ),
    version="1.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Défense en profondeur : même si une couche applicative a une faille,
    # ces headers limitent ce qu'un navigateur laissera se produire.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


app.include_router(auth.router)
app.include_router(notes.router)


@app.get("/health")
def health_check():
    return JSONResponse({"status": "ok"})
