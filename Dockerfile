FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RED_WOLF_SERVICE_DB=/var/lib/red-wolf/service.db

WORKDIR /app
COPY pyproject.toml requirements.txt README.md ./
COPY red_wolf ./red_wolf
COPY assets ./assets

RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 redwolf \
    && mkdir -p /var/lib/red-wolf \
    && chown -R redwolf:redwolf /app /var/lib/red-wolf
USER redwolf

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
CMD ["uvicorn", "red_wolf.service:app", "--host", "0.0.0.0", "--port", "8000"]
