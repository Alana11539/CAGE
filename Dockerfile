# CAGE: Composition-Aware Guard Evaluation for Agentic AI
# A single image serves the guard library, the evaluation harness and the
# Console. The agent model and the benchmark are NOT bundled: they are
# integrated per the configuration gate and run outside this image.
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first, so a source change does not invalidate the layer.
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY pyproject.toml README.md LICENSE NOTICE CITATION.cff ./
COPY cage_guard/ ./cage_guard/
COPY cage_eval/ ./cage_eval/
COPY cage_console/ ./cage_console/
COPY config/ ./config/
COPY policies/ ./policies/
COPY cases/ ./cases/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
RUN pip install --no-cache-dir -e .

# Run as an unprivileged user; the guard needs no privileges and no network.
RUN useradd --create-home --uid 10001 cage \
    && mkdir -p /app/runs /app/results \
    && chown -R cage:cage /app
USER cage

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')"

CMD ["python", "-m", "cage_console.server", "--host", "0.0.0.0", "--port", "8000", \
     "--logs", "runs", "--results", "results"]
