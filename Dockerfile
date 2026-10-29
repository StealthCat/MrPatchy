FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.licenses="LicenseRef-MrPatchy-Personal-Commercial-1.0"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data TLS_DIR=/tls
RUN apt-get update && apt-get install -y --no-install-recommends apt gnupg ca-certificates gosu tzdata python3 python3-dnf python3-rpm rpm && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home mrpatchy
WORKDIR /app
COPY requirements.txt .
COPY LICENSE COMMERCIAL.md ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY target ./target
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","1","--no-access-log"]

