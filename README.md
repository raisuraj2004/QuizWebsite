# QuizPlatform

Production-grade Flask quiz platform with PostgreSQL + Redis support.

## Local Development

1. Create venv and install dependencies:
   - `python -m venv venv`
   - `venv\\Scripts\\python -m pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and set values for your environment.
3. Run migrations:
   - `python migrate.py`
4. Start app:
   - `python app.py`

## Database Migrations

- Migration files are in:
  - `migrations/sqlite`
  - `migrations/postgres`
- Apply migrations:
  - `python migrate.py`

## Running Tests

- `python -m pytest -q`

## Production Deployment

### Option A: Docker Compose

1. Configure `.env` with production values.
2. Start stack:
   - `docker compose up --build -d`
3. Services:
   - App (Gunicorn)
   - PostgreSQL
   - Redis
   - Nginx reverse proxy

### Option B: Bare Metal / VM

1. Set environment variables (`FLASK_ENV=production`, `FLASK_SECRET_KEY`, `DATABASE_URL`, `REDIS_URL`).
2. Run migrations:
   - `python migrate.py`
3. Serve with Gunicorn:
   - `gunicorn -c gunicorn.conf.py app:app`
4. Put behind HTTPS reverse proxy (Nginx/Caddy).

## Health Check

- Endpoint: `GET /healthz`
- Returns:
  - `200 {"status": "ok"}` when DB is reachable
  - `500 {"status": "error"}` otherwise

## Backup and Restore (PostgreSQL)

- Backup:
  - `DATABASE_URL=... sh scripts/backup_postgres.sh`
- Restore:
  - `DATABASE_URL=... BACKUP_FILE=backup.sql.gz sh scripts/restore_postgres.sh`

## Security Notes

- CSRF protection on all state-changing forms.
- Redis-backed rate limiting.
- Strict production env validation.
- CSP / HSTS / secure cookie headers.
- POST-based logout with CSRF.
