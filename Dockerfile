# Playwright 1.54 supports Debian 12, but not Debian 13. Keep the distro pinned
# so a moving python:3.13-slim tag cannot break browser dependency installation.
FROM python:3.13-slim-bookworm

WORKDIR /app

# Install system deps for Playwright/Chromium PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry==2.2.1

# Copy full project so Poetry can validate all included files (e.g. README.md)
COPY . .

# Install dependencies into an application-only environment. Poetry and its
# own dependencies remain in the system environment, which prevents a Poetry
# dependency upgrade/downgrade from leaving mixed binary and Python modules in
# the runtime environment (notably charset-normalizer).
RUN poetry config virtualenvs.create true \
    && poetry config virtualenvs.in-project true \
    && poetry install --no-interaction --no-ansi --extras web --without dev

ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Playwright Chromium for PDF generation
RUN pip install --no-cache-dir playwright==1.54.0 \
    && playwright install --with-deps chromium \
    && python -c "import nltk; from charset_normalizer import from_bytes; assert from_bytes(b'container-smoke-test')"

# The web server runs scans locally (no Docker-in-Docker sandbox), so we
# need standalone mode so that ALL tools — including create_vulnerability_report
# and finish_scan — are registered and execute in-process.
ENV STRIX_SANDBOX_MODE=true
ENV STRIX_STANDALONE=true

# Default port; Railway overrides this with its own PORT env var
ENV PORT=8080
EXPOSE 8080

CMD python -m strix.web --host 0.0.0.0 --port $PORT
