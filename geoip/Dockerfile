FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GEOIP_CONFIG_PATH=/data/geoip/config.yaml

WORKDIR /app

# Minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
COPY html ./html
COPY data ./defaults
RUN mkdir -p /etc/conf

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 80

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app_geoip:app", "--host", "0.0.0.0", "--port", "8001"]
