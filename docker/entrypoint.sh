#!/usr/bin/env bash
set -euo pipefail

APP_ENV="${APP_ENV:-production}"
PORT="${PORT:-5001}"

# Tunables (override via -e on docker run)
GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"
GUNICORN_THREADS="${GUNICORN_THREADS:-8}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-120}"
GUNICORN_GRACEFUL_TIMEOUT="${GUNICORN_GRACEFUL_TIMEOUT:-30}"

echo "Starting QSE Demos"
echo "APP_ENV=$APP_ENV"
echo "PORT=$PORT"

if [[ "$APP_ENV" == "production" ]]; then
  exec gunicorn \
    -w "$GUNICORN_WORKERS" \
    -k gthread \
    --threads "$GUNICORN_THREADS" \
    --timeout "$GUNICORN_TIMEOUT" \
    --graceful-timeout "$GUNICORN_GRACEFUL_TIMEOUT" \
    --access-logfile - \
    --error-logfile - \
    -b "0.0.0.0:${PORT}" \
    web_demo_app:app
else
  # staging/dev mode
  exec python3 web_demo_app.py
fi