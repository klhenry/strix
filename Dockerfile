FROM python:3.13-slim

WORKDIR /app

# Install system deps for Playwright/Chromium PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy dependency files first for layer caching
COPY pyproject.toml poetry.lock* ./

# Regenerate lock if out of sync, then install deps
RUN poetry config virtualenvs.create false \
    && poetry lock --no-update 2>/dev/null; \
    poetry install --no-interaction --no-ansi --extras web --without dev
# Install dependencies (no dev deps, web extra only)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --extras web --without dev

# Install Playwright Chromium for PDF generation
RUN pip install --no-cache-dir playwright \
    && playwright install --with-deps chromium

# Copy application code
COPY . .

# Railway sets PORT env var
ENV PORT=8420
EXPOSE 8420

CMD ["python", "-m", "strix.web", "--host", "0.0.0.0"]
