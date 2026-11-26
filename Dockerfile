FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl libgomp1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 cybertriage \
    && useradd --uid 10001 --gid 10001 --create-home cybertriage
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir '.[graph]'
COPY config ./config
COPY docker ./docker
RUN mkdir -p /app/data && chown 10001:10001 /app/data
USER 10001:10001
ENTRYPOINT ["python", "/app/docker/entrypoint.py"]
