# URL Inspector

A full-stack link-safety scanner. Paste a URL and it runs a real background
analysis pipeline — DNS resolution, WHOIS domain-age lookup, TLS certificate
inspection, and reputation scoring (blacklist + keyword heuristics, with
optional Google Safe Browsing integration) — and returns a transparent 0–100
risk score with a safe / suspicious / malicious verdict.

This started as a static HTML/JS page with a hardcoded keyword list and
`localStorage`. It's now a real client-server app with an async job queue,
a cache layer, rate limiting, and a database-backed history.

## Architecture

```
 Browser (vanilla JS)
      │  POST /api/inspect  →  202 { job_id }
      │  GET  /api/jobs/:id (polled)
      ▼
 FastAPI (Uvicorn)
      │  checks Redis cache by domain → instant result if hit
      │  else creates a ScanJob row (status=pending) and enqueues a Celery task
      ▼
 Redis  ⇄  Celery worker
      │  runs dns_check / whois_check / ssl_check / reputation_check
      │  writes verdict + risk_score back to the DB
      │  caches the result by domain (TTL) for future requests
      ▼
 SQLite (dev) / Postgres (prod) — scan_jobs table = persistent history
```

Rate limiting (via `slowapi`, Redis-backed) protects `/api/inspect` from
abuse independent of the job queue itself.

## Why it's structured this way

- **Async job queue (Celery + Redis)** — network calls (DNS, WHOIS, TLS,
  Safe Browsing) are slow and unpredictable. Offloading them to a worker
  keeps the API responsive and makes the system horizontally scalable
  (add more workers, not more API replicas).
- **Caching by domain** — repeat scans of the same domain skip the full
  pipeline for `CACHE_TTL_SECONDS` (default 1h), which is both a
  performance win and a courtesy to WHOIS/Safe Browsing rate limits.
- **DB-backed history** instead of `localStorage` — history now survives
  across devices/browsers and can be queried, paginated, and exported.
- **Transparent scoring** — `services/scoring.py` is a small, readable
  function, not a black box, so the "why" behind a verdict is inspectable.

## Project layout

```
backend/
  app/
    main.py            FastAPI app, CORS, static frontend mount
    config.py           env-driven settings
    database.py / models.py / schemas.py
    celery_app.py / tasks.py    async pipeline
    cache.py             Redis cache helpers
    rate_limit.py         slowapi limiter
    routers/
      inspect.py         POST /api/inspect, GET /api/jobs/:id
      history.py         GET/DELETE /api/history, GET /api/history/export
    services/
      dns_check.py / whois_check.py / ssl_check.py / reputation_check.py
      scoring.py
  requirements.txt
  Dockerfile
frontend/
  index.html / style.css / app.js     (static, no build step)
docker-compose.yml   redis + api + worker
```

## Running locally with Docker (recommended)

```bash
cp backend/.env.example backend/.env   # tweak if you want a Safe Browsing API key
docker compose up --build
```

Then open **http://localhost:8000**.

## Running without Docker

You'll need Redis running locally (`redis-server`, or `docker run -p 6379:6379 redis:7-alpine`).

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# terminal 1: API
uvicorn app.main:app --reload

# terminal 2: worker
celery -A app.celery_app worker --loglevel=info
```

Open **http://localhost:8000** (FastAPI serves the `frontend/` folder as static files).

## Deploying

- **API + worker + Redis**: Render or Railway both support multi-service
  docker-compose-style deployments (a web service for `api`, a background
  worker service for `worker`, and a managed Redis add-on).
- **Database**: swap `DATABASE_URL` to a managed Postgres instance
  (`postgresql+psycopg2://...`) — no code changes needed, SQLAlchemy
  handles both.
- **Frontend**: it's static, so it can also be deployed separately on
  Vercel/Netlify — just point `window.API_BASE` in `index.html` at your
  API's public URL and drop the `StaticFiles` mount in `main.py`.

## Configuration

All settings are environment variables (see `backend/.env.example`):

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLite by default; swap for Postgres in prod |
| `REDIS_URL` / `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Redis connection(s) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional — enables real threat-list lookups |
| `CACHE_TTL_SECONDS` | How long a domain's result is cached |
| `RATE_LIMIT_INSPECT` | e.g. `5/minute` per IP on the scan endpoint |

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/inspect` | Body `{ "url": "..." }` → `202 { job_id, status, from_cache }` |
| GET | `/api/jobs/{job_id}` | Poll for status/result |
| GET | `/api/history?limit=&offset=` | Paginated scan history |
| GET | `/api/history/export` | Full history as JSON |
| DELETE | `/api/history` | Clear history |
| GET | `/api/health` | Liveness check |

## Notes for your resume

This project now demonstrates: REST API design, async task queues,
caching strategy, rate limiting, ORM/database modeling, third-party API
integration (DNS/WHOIS/TLS/Safe Browsing), and containerized multi-service
deployment (Docker Compose) — not just a frontend form. A reasonable
resume bullet:

> Built a full-stack link-safety scanner (FastAPI, Celery, Redis,
> SQLAlchemy) performing DNS/WHOIS/TLS/reputation analysis via an async
> job queue, with per-domain caching and rate-limited API access;
> containerized with Docker Compose.
