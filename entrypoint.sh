#!/bin/sh
set -e

echo "=== Tabletop Nights starting ==="
echo "DATABASE_PATH: ${DATABASE_PATH}"
echo "ADMIN_USERNAME: ${ADMIN_USERNAME:-admin}"

# Ensure /data is writable
mkdir -p /data
touch /data/.write_test && rm /data/.write_test || { echo "ERROR: /data is not writable"; exit 1; }

echo "Starting gunicorn..."
exec gunicorn \
  --bind 0.0.0.0:5000 \
  --workers ${WORKERS:-2} \
  --timeout 60 \
  --access-logfile - \
  --error-logfile - \
  --log-level info \
  app:app
