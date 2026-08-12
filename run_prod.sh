#!/bin/bash
# run_prod.sh - Start the OmniLog API Server using Gunicorn for production

# Load API_PORT from .env if present, otherwise default to 5000
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | xargs)
fi

# Use PORT if provided by the platform (like Render), otherwise check API_PORT, then fallback to 5000
SERVER_PORT=${PORT:-${API_PORT:-5000}}
WORKERS=${GUNICORN_WORKERS:-4}

echo "Starting OmniLog API Server (Production) on 0.0.0.0:$SERVER_PORT with $WORKERS workers..."
exec gunicorn --workers $WORKERS --bind 0.0.0.0:$SERVER_PORT api_server:app
