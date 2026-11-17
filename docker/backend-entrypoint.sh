#!/bin/sh
# Backend start-up: wait for PostgreSQL, apply Alembic migrations, wait (bounded) for the
# smart contract deployment, then start the API.
set -e

echo "[backend] waiting for the database..."
python - <<'EOF'
import os, sys, time
from sqlalchemy import create_engine, text
url = os.environ["DATABASE_URL"]
for attempt in range(60):
    try:
        with create_engine(url).connect() as c:
            c.execute(text("SELECT 1"))
        print("[backend] database ready")
        sys.exit(0)
    except Exception as exc:
        time.sleep(2)
print("[backend] database not reachable", file=sys.stderr)
sys.exit(1)
EOF

echo "[backend] applying migrations (alembic upgrade head)"
alembic upgrade head

DEPLOYMENT="${ETH_DEPLOYMENT_FILE:-/deployments/localhost.json}"
i=0
while [ ! -f "$DEPLOYMENT" ] && [ $i -lt 60 ]; do
  echo "[backend] waiting for smart contract deployment ($DEPLOYMENT)..."
  sleep 2; i=$((i+1))
done
[ -f "$DEPLOYMENT" ] || echo "[backend] WARNING: no deployment file, blockchain features unavailable until deployed"

exec "$@"
