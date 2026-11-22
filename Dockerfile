FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_login ./mcp_login
# Who may sign in to which server (copy clients.example.json). Baked into the image,
# so a grant or removal is a reviewed commit and a deploy.
COPY clients.json ./clients.json

# Non-root. The data volume (signing key, sessions, refresh-token hashes, audit
# log) is created here, owned by appuser, so Docker seeds the named volume with
# that ownership; without it the volume arrives root-owned and nothing writes.
RUN useradd --create-home --uid 10001 appuser \
 && mkdir -p /var/lib/mcp-login \
 && chown -R appuser:appuser /app /var/lib/mcp-login

USER appuser
EXPOSE 8000
CMD ["python", "-m", "mcp_login"]
