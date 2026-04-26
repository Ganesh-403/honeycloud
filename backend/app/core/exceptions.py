"""
Centralized exception handling.
Register all handlers via register_exception_handlers(app).
"""
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Custom exception hierarchy
# ---------------------------------------------------------------------------

class HoneyCloudError(Exception):
    """Base application exception."""
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail: str = "An internal error occurred."

    def __init__(self, detail: str | None = None):
        if detail:
            self.detail = detail
        super().__init__(self.detail)


class NotFoundError(HoneyCloudError):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Resource not found."


class BadRequestError(HoneyCloudError):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Bad request."


class UnauthorizedError(HoneyCloudError):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Authentication required."


class ForbiddenError(HoneyCloudError):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Access forbidden."


class IngestError(HoneyCloudError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    detail = "Failed to ingest event."


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _error_response(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "error": detail},
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(HoneyCloudError)
    async def honecloud_error_handler(request: Request, exc: HoneyCloudError):
        logger.warning("%s – %s %s", type(exc).__name__, request.method, request.url)
        return _error_response(exc.status_code, exc.detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        logger.debug("Validation error on %s: %s", request.url, exc.errors())
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Invalid input: {exc.errors()}",
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception on %s %s", request.method, request.url)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "An unexpected error occurred.",
        )
