FROM python:3.15-slim-bookworm@sha256:4e03260adeeebafccd084f3584e6b84823aba5651cfb53ef8a078ed441ddf9cd AS runtime-base

FROM runtime-base AS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt requirements.lock ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

FROM runtime-base
LABEL org.opencontainers.image.licenses="LicenseRef-MrPatchy-Personal-Commercial-1.1"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data TLS_DIR=/tls
ENV PATH="/opt/venv/bin:$PATH"
COPY --from=dependencies /opt/venv /opt/venv
RUN apt-get update && apt-get install -y --no-install-recommends apt gnupg ca-certificates gosu tzdata python3 python3-dnf python3-rpm rpm && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home mrpatchy
WORKDIR /app
COPY requirements.txt requirements.lock ./
COPY LICENSE COMMERCIAL.md ./
COPY app ./app
COPY target ./target
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","1","--no-access-log"]

