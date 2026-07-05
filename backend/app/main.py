from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .config import get_settings
from .database import init_db
from .rate_limit import limiter
from .routers import history, inspect

settings = get_settings()

app = FastAPI(title="URL Inspector API", version="2.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


app.include_router(inspect.router)
app.include_router(history.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# Serve the static frontend. Defaults to ../../frontend for local runs;
# override with FRONTEND_DIR env var (docker-compose points this at /frontend).
FRONTEND_DIR = Path(settings.FRONTEND_DIR) if settings.FRONTEND_DIR else (
    Path(__file__).resolve().parent.parent.parent / "frontend"
)
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
