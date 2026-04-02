FROM python:3.13-slim

WORKDIR /app

# Install system deps for Playwright/Chromium PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy full project so Poetry can validate all included files (e.g. README.md)
COPY . .

# Install dependencies (no dev deps, web extra only)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --extras web --without dev

# Install Playwright Chromium for PDF generation
RUN pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium

# Default port; Railway overrides this with its own PORT env var
ENV PORT=8080
EXPOSE 8080

CMD python -m strix.web --host 0.0.0.0 --port $PORT
