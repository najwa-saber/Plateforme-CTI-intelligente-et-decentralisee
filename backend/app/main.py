"""FastAPI application: orchestration of NLP, ML, MITRE ATT&CK, MISP and Ethereum modules."""
from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import organizations, reports, system
from app.blockchain.client import get_chain_client
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.database.seed import seed_organizations
from app.database.session import SessionLocal, create_all
from app.mitre.enricher import get_enricher
from app.ml.classifier import get_classifier

logger = logging.getLogger("cti.app")

DESCRIPTION = """
Plateforme collaborative de **Cyber Threat Intelligence** (prototype academique).

Pipeline : rapport -> extraction NLP des IOC -> normalisation / doublons / incoherences ->
classification ML (TF-IDF + regression logistique) -> enrichissement MITRE ATT&CK -> MISP ->
empreinte SHA-256 sur Ethereum -> validation collaborative (smart contract) -> score de fiabilite ->
reputation dynamique -> correlation.

**Authentification** : en-tete `X-API-Key` (une cle par organisation A, B, C).

Avertissements : un IOC syntaxiquement valide n'est pas forcement malveillant ; une correspondance ATT&CK
par mots-cles est une proposition ; le score de fiabilite n'est pas une probabilite de veracite ;
une correlation n'est pas une preuve d'appartenance a une meme campagne.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    if settings.is_sqlite:
        create_all()  # PostgreSQL schema is managed by Alembic (docker/backend-entrypoint.sh)
    chain = get_chain_client()
    with SessionLocal() as db:
        seed_organizations(db, chain if chain.is_ready() else None)
    get_classifier().load()
    get_enricher()
    logger.info("%s v%s started (env=%s)", settings.app_name, settings.app_version, settings.environment)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="CTI Platform API", version=settings.app_version, description=DESCRIPTION,
                  lifespan=lifespan, docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=False,
                       allow_methods=["GET", "POST"], allow_headers=["X-API-Key", "Content-Type"])

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        rid = request.headers.get("X-Request-ID", "")[:64] or uuid.uuid4().hex[:16]
        request.state.request_id = rid
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        logging.getLogger("cti.access").info("%s %s -> %s (%.0f ms)", request.method, request.url.path,
                                             response.status_code, elapsed, extra={"request_id": rid})
        return response

    register_exception_handlers(app)
    app.include_router(system.router)
    app.include_router(reports.router)
    app.include_router(organizations.router)
    return app


app = create_app()
