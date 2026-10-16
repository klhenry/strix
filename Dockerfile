FROM node:22-bookworm-slim AS node
FROM python:3.13-slim-bookworm
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates openssl bash git ripgrep jq nmap dnsutils netcat-openbsd procps \
    chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app/certs && openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key \
    && openssl req -x509 -new -key /app/certs/ca.key -out /app/certs/ca.crt -days 3650 \
    -subj "/CN=Accountable Scan Proxy" -addext "basicConstraints=critical,CA:TRUE" \
    && openssl pkcs12 -export -out /app/certs/ca.p12 -inkey /app/certs/ca.key \
       -in /app/certs/ca.crt -passout pass: \
    && cp /app/certs/ca.crt /usr/local/share/ca-certificates/scan-proxy.crt \
    && update-ca-certificates
RUN pip install --no-cache-dir uv==0.13.1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --extra web --no-dev --no-install-project
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN case "$(uname -m)" in x86_64) CAIDO_ARCH=x86_64 ;; aarch64|arm64) CAIDO_ARCH=aarch64 ;; *) exit 1 ;; esac \
    && curl -fsSL "https://caido.download/releases/v0.56.0/caido-cli-v0.56.0-linux-${CAIDO_ARCH}.tar.gz" -o /tmp/caido.tar.gz \
    && tar -xzf /tmp/caido.tar.gz -C /usr/local/bin ./caido-cli \
    && chmod +x /usr/local/bin/caido-cli && rm /tmp/caido.tar.gz
RUN npm install -g agent-browser@0.26.0 && npm cache clean --force \
    && python -m playwright install --with-deps chromium
COPY . .
COPY strix/tools/proxy/caido_api.py /opt/strix-python/caido_api.py
ENV PYTHONPATH=/app:/opt/strix-python
ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_ARGS="--no-sandbox,--disable-dev-shm-usage,--no-first-run"
ENV STRIX_PROXY_CA_P12=/app/certs/ca.p12
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV STRIX_RUNTIME_BACKEND=railway
ENV STRIX_TELEMETRY=0
ENV OPENAI_AGENTS_DISABLE_TRACING=1
RUN python -m strix.web.services.runtime_check
ENV PORT=8080
EXPOSE 8080
CMD python -m strix.web --host 0.0.0.0 --port $PORT
