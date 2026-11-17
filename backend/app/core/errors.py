"""Domain exceptions and their mapping to HTTP responses.

Error payloads never contain stack traces, SQL, keys or internal hostnames.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("cti.errors")


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class BadRequestError(AppError):
    status_code, code = 400, "bad_request"


class AuthenticationError(AppError):
    status_code, code = 401, "unauthenticated"


class ForbiddenError(AppError):
    status_code, code = 403, "forbidden"


class NotFoundError(AppError):
    status_code, code = 404, "not_found"


class ConflictError(AppError):
    status_code, code = 409, "conflict"


class UnprocessableError(AppError):
    status_code, code = 422, "unprocessable"


class PayloadTooLargeError(AppError):
    status_code, code = 413, "payload_too_large"


class ExternalServiceError(AppError):
    """MISP / Ethereum failures: the platform keeps working, the operation is reported as failed."""

    status_code, code = 503, "external_service_unavailable"


class BlockchainError(ExternalServiceError):
    code = "blockchain_error"


class ContractRevertError(ConflictError):
    """The smart contract rejected the transaction (business rule)."""

    code = "contract_revert"


class MispError(ExternalServiceError):
    code = "misp_error"


def _payload(code: str, message: str, details: dict | None, request_id: str | None) -> dict:
    return {"error": {"code": code, "message": message, "details": details or {}, "request_id": request_id}}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        rid = getattr(request.state, "request_id", None)
        log = logger.warning if exc.status_code < 500 else logger.error
        log("%s %s -> %s %s: %s", request.method, request.url.path, exc.status_code, exc.code, exc.message)
        return JSONResponse(status_code=exc.status_code, content=_payload(exc.code, exc.message, exc.details, rid))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        rid = getattr(request.state, "request_id", None)
        errors = [
            {"loc": [str(p) for p in e.get("loc", [])], "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content=_payload("validation_error", "Invalid request", {"errors": errors}, rid))

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        rid = getattr(request.state, "request_id", None)
        code = {401: "unauthenticated", 403: "forbidden", 404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error"
        )
        return JSONResponse(status_code=exc.status_code, content=_payload(code, str(exc.detail), None, rid))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", None) or uuid.uuid4().hex
        logger.exception("Unhandled error on %s %s (request_id=%s)", request.method, request.url.path, rid)
        return JSONResponse(
            status_code=500,
            content=_payload("internal_error", "Internal server error", {"hint": "see server logs with request_id"}, rid),
        )
