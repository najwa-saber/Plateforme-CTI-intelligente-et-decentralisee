# FastAPI backend (NLP, ML, MITRE, MISP, Web3)
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
RUN useradd --create-home --uid 10001 cti

COPY backend/requirements.txt backend/requirements.lock /app/
RUN pip install -r /app/requirements.txt -c /app/requirements.lock

# Application code, trained model and official MITRE catalogue
COPY backend/ /app/
# Annotated corpus (needed to retrain / evaluate inside the container): PROJECT_DIR=/ -> /data
COPY data/ /data/
COPY docker/backend-entrypoint.sh /usr/local/bin/backend-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/backend-entrypoint.sh && chmod +x /usr/local/bin/backend-entrypoint.sh \
    && mkdir -p /deployments && chown -R cti:cti /app /data

USER cti
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
ENTRYPOINT ["/usr/local/bin/backend-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
