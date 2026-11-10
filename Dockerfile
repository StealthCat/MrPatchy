FROM python:3.15-slim-bookworm@sha256:4e03260adeeebafccd084f3584e6b84823aba5651cfb53ef8a078ed441ddf9cd AS runtime-base

FROM runtime-base AS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt requirements.lock requirements-build.lock ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Build inputs for sdist-only runtime packages come from their own hash-pinned lock.
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-build.lock
# Online steps fetch bytes only, so no PEP 517 build hook runs while networking is enabled:
# every other runtime package as a hash-checked wheel, and the sdist-only zstandard archive
# as raw bytes checked against its requirements.lock hashes. The offline install below then
# builds and installs with networking disabled so nothing outside the two locks can be resolved.
RUN python -c "import pathlib,re; lock=pathlib.Path('requirements.lock').read_text(); pathlib.Path('requirements-wheels.lock').write_text(re.sub(r'(?ms)^zstandard==.*?(?=^\S|\Z)','',lock))"
RUN pip download --no-cache-dir --require-hashes --no-deps --only-binary=:all: -d /wheelhouse -r requirements-wheels.lock
RUN python -c "import hashlib,pathlib,re,urllib.request; version,block=re.search(r'(?ms)^zstandard==(\S+)(.*?)(?=^\S|\Z)',pathlib.Path('requirements.lock').read_text()).groups(); data=urllib.request.urlopen(f'https://files.pythonhosted.org/packages/source/z/zstandard/zstandard-{version}.tar.gz').read(); assert hashlib.sha256(data).hexdigest() in re.findall(r'[0-9a-f]{64}',block), 'zstandard sdist hash is not in requirements.lock'; pathlib.Path(f'/wheelhouse/zstandard-{version}.tar.gz').write_bytes(data)"
RUN --network=none pip install --no-cache-dir --no-index --find-links /wheelhouse --no-build-isolation --require-hashes -r requirements.lock
# Build-only packages must not reach the runtime image.
RUN pip uninstall --yes setuptools packaging && ! pip show setuptools packaging

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

