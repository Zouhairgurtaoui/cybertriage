import asyncio
import hmac
import json

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from cybertriage.application.use_cases.ingest_alert import IngestAlert
from cybertriage.domain.alert import (
    AlertConflictError,
    AlertStorageError,
    InvalidAlertError,
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys.")

        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Nonstandard JSON numeric constant.")


async def _read_payload(
    request: Request,
    max_body_bytes: int,
) -> dict[str, object]:
    media_type = request.headers.get("content-type", "")
    media_type = media_type.split(";", 1)[0].strip().lower()

    if media_type != "application/json":
        raise HTTPException(415, "Content-Type must be application/json.")

    lengths = request.headers.getlist("content-length")

    if len(lengths) > 1:
        raise HTTPException(400, "Multiple Content-Length headers.")

    if lengths:
        if not lengths[0].isascii() or not lengths[0].isdecimal():
            raise HTTPException(400, "Invalid Content-Length.")

        if int(lengths[0]) > max_body_bytes:
            raise HTTPException(413, "Alert payload exceeds the size limit.")

    body = bytearray()

    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(body) + len(chunk) > max_body_bytes:
                    raise HTTPException(
                        413,
                        "Alert payload exceeds the size limit.",
                    )

                body.extend(chunk)

    except TimeoutError as error:
        raise HTTPException(408, "Request body timed out.") from error

    except ClientDisconnect as error:
        raise HTTPException(400, "Request body was interrupted.") from error

    try:
        payload = json.loads(
            body.decode("utf-8-sig"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )

    except (ValueError, UnicodeError, RecursionError) as error:
        raise HTTPException(400, "Invalid JSON payload.") from error

    if not isinstance(payload, dict):
        raise HTTPException(400, "The alert payload must be a JSON object.")

    return payload


def create_app(
    ingestion: IngestAlert,
    token: str,
    max_body_bytes: int = 262144,
) -> FastAPI:
    if (
        not isinstance(token, str)
        or not 32 <= len(token) <= 512
        or not token.isascii()
        or any(character.isspace() for character in token)
    ):
        raise ValueError(
            "The ingestion token must contain 32-512 ASCII characters "
            "without whitespace."
        )

    if type(max_body_bytes) is not int or max_body_bytes <= 0:
        raise ValueError("max_body_bytes must be a positive integer.")

    expected_token = token.encode("ascii")
    bearer = HTTPBearer(auto_error=False)

    async def require_token(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> None:
        if (
            len(request.headers.getlist("authorization")) != 1
            or credentials is None
            or len(credentials.credentials) > 512
            or not hmac.compare_digest(
                credentials.credentials.encode("utf-8"),
                expected_token,
            )
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing ingestion token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    app = FastAPI(
        title="CyberTriage ingestion API",
        debug=False,
    )

    @app.post(
        "/api/v1/alerts/wazuh",
        dependencies=[Depends(require_token)],
    )
    async def receive_wazuh_alert(request: Request) -> JSONResponse:
        payload = await _read_payload(request, max_body_bytes)

        try:
            receipt = await run_in_threadpool(
                ingestion.execute,
                payload,
            )

        except InvalidAlertError as error:
            raise HTTPException(400, str(error)) from error

        except AlertConflictError as error:
            raise HTTPException(
                409,
                "This alert identity already has different content.",
            ) from error

        except AlertStorageError as error:
            raise HTTPException(
                503,
                "Alert storage is unavailable.",
            ) from error

        return JSONResponse(
            status_code=201 if receipt.created else 200,
            content={
                "record_id": receipt.record_id,
                "created": receipt.created,
            },
        )

    return app