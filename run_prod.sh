#!/bin/bash
# run_prod.sh - Start the OmniLog API Server using Gunicorn for production

# Load API_PORT from .env if present, otherwise default to 5000
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
fi

PORT=${API_PORT:-5000}
WORKERS=${GUNICORN_WORKERS:-4}

echo "Starting OmniLog API Server (Production) on 0.0.0.0:$PORT with $WORKERS workers..."
exec gunicorn --workers $WORKERS --bind 0.0.0.0:$PORT api_server:app
