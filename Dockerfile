# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS frontend
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
WORKDIR /app/backend
COPY backend/pyproject.toml ./
COPY backend/app/__init__.py ./app/__init__.py
RUN pip install --no-cache-dir '.[cloud]' && pip check
COPY --from=frontend /web/dist /app/frontend/dist
COPY LICENSE /app/LICENSE
RUN useradd --uid 10001 --create-home audit && mkdir -p /app/.audit-work && chown -R audit:audit /app/.audit-work
USER 10001
EXPOSE 8080
CMD ["sh", "-c", "exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS:-127.0.0.1}"]

FROM runtime AS api
COPY backend/app ./app
COPY backend/scripts ./scripts

FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks
FROM aquasec/trivy:0.75.0 AS trivy
FROM runtime AS scanner-runtime
USER root
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.180.0 && /opt/semgrep/bin/pip check && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep && mkdir -p /app/notices
COPY docs/dependencies.md /app/notices/dependencies.md
COPY third_party /app/notices/third_party
USER 10001

FROM scanner-runtime AS local
COPY backend/app ./app
COPY backend/scripts ./scripts

FROM local AS worker
CMD ["python", "-m", "app.worker"]
