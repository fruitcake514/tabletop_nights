FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY templates/ templates/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create data directory with correct permissions
RUN mkdir -p /data && chmod 755 /data

EXPOSE 5000

# Defaults (override in docker-compose.yml)
ENV DATABASE_PATH=/data/tabletop.db \
    SECRET_KEY=change-me-in-production \
    ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=changeme \
    WORKERS=2 \
    FLASK_DEBUG=0

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
