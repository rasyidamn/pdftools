# Image API gateway merge PDF. Dibangun dari folder api/ (docker compose melakukannya otomatis).
# Sematkan versi uv (mis. ghcr.io/astral-sh/uv:0.9.5) lewat --build-arg UV_IMAGE=... untuk build yang bisa diulang.
ARG UV_IMAGE=ghcr.io/astral-sh/uv:latest
ARG PYTHON_IMAGE=python:3.13-slim

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------- build: pasang dependensi
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMP_DIR=/tmp/pdftool
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY app ./app
USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]

# --no-proxy-headers: IP klien diambil sendiri dari X-Forwarded-For (entri terkanan) di app.util.
CMD ["uvicorn", "app.main:factory", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--no-proxy-headers", "--no-server-header", "--timeout-keep-alive", "10"]
