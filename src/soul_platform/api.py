"""FastAPI shell for SOUL Core. Agentic APIs are opt-in library integrations."""

from __future__ import annotations

import os
import base64
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field
from soul_framework import Soul
from soul_platform.auth import AuthenticationDenied, PrincipalTokenVerifier
from soul_platform.coordination import ChannelService, CoordinatorStore
from soul_platform.receipts import ReceiptCheckpointStore, ReceiptSigner


def _data_dir() -> Path:
    return Path(os.environ.get("SOUL_PLATFORM_DATA", Path.home() / ".soul-platform" / "souls"))


def _db_for(name: str) -> Path:
    if not name or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in name):
        raise HTTPException(status_code=422, detail="invalid soul name")
    return _data_dir() / f"{name}.db"


class CreateSoulRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    ocean: dict[str, float] = Field(
        default_factory=lambda: {"O": 0.5, "C": 0.5, "E": 0.5, "A": 0.5, "N": 0.5}
    )


class RememberRequest(BaseModel):
    content: str = Field(min_length=1)
    importance: int = Field(default=5, ge=1, le=10)


class SendMessageRequest(BaseModel):
    content: str = Field(min_length=1, max_length=65_536)
    idempotency_key: str = Field(min_length=1, max_length=256)


async def _authenticated_channels(authorization: str) -> tuple[ChannelService, Any]:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="bearer token required")
    required = (
        "SOUL_PLATFORM_COORDINATOR_DB", "SOUL_PLATFORM_CHECKPOINT_DB",
        "SOUL_PLATFORM_RECEIPT_KEY", "SOUL_PLATFORM_AUTH_KEYS",
    )
    if any(not os.environ.get(name) for name in required):
        raise HTTPException(status_code=503, detail="multi-agent API is not configured")
    try:
        auth_keys = json.loads(os.environ["SOUL_PLATFORM_AUTH_KEYS"])
        verifier = PrincipalTokenVerifier({
            key_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
            for key_id, value in auth_keys.items()
        })
        principal = verifier.verify(authorization[7:])
        signer = ReceiptSigner.from_private_bytes(
            base64.b64decode(os.environ["SOUL_PLATFORM_RECEIPT_KEY"], validate=True),
            os.environ.get("SOUL_PLATFORM_RECEIPT_KEY_ID", "coordinator"),
        )
        store = CoordinatorStore(
            os.environ["SOUL_PLATFORM_COORDINATOR_DB"], signer,
            ReceiptCheckpointStore(os.environ["SOUL_PLATFORM_CHECKPOINT_DB"]),
        )
        await store.initialize()
    except AuthenticationDenied as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=503, detail="multi-agent security configuration is invalid") from None
    return ChannelService(store), principal


@asynccontextmanager
async def lifespan(app: FastAPI):
    _data_dir().mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="SOUL Platform", version="0.1.0", lifespan=lifespan)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "core": "soul-framework", "agency_default": "disabled"}


@app.get("/api/souls")
async def list_souls() -> dict[str, Any]:
    return {"souls": sorted(path.stem for path in _data_dir().glob("*.db"))}


@app.post("/api/souls")
async def create_soul(request: CreateSoulRequest) -> dict[str, Any]:
    database = _db_for(request.name)
    async with Soul.create(
        request.name, backend="sqlite", backend_url=str(database), ocean=request.ocean
    ) as soul:
        boot = await soul.boot()
    return {"created": request.name, "boot_context_preview": boot[:200]}


@app.post("/api/souls/{name}/remember")
async def remember(name: str, request: RememberRequest) -> dict[str, Any]:
    database = _db_for(name)
    if not database.exists():
        raise HTTPException(status_code=404, detail="soul does not exist")
    async with Soul.create(name, backend="sqlite", backend_url=str(database)) as soul:
        memory_id = await soul.memory.store(request.content, importance=request.importance)
    return {"soul": name, "memory_id": memory_id}


@app.get("/api/souls/{name}/boot")
async def boot(name: str) -> dict[str, Any]:
    database = _db_for(name)
    if not database.exists():
        raise HTTPException(status_code=404, detail="soul does not exist")
    async with Soul.create(name, backend="sqlite", backend_url=str(database)) as soul:
        context = await soul.boot()
    return {"soul": name, "boot_context": context}


@app.get("/api/channels/{channel}/messages")
async def channel_messages(
    channel: str, authorization: str = Header(default="")
) -> dict[str, Any]:
    service, principal = await _authenticated_channels(authorization)
    try:
        messages = await service.read(principal.tenant, channel, principal.actor)
    except Exception as exc:
        raise HTTPException(status_code=403, detail=type(exc).__name__) from None
    return {"messages": [message.__dict__ for message in messages]}


@app.post("/api/channels/{channel}/messages")
async def send_channel_message(
    channel: str, request: SendMessageRequest,
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    service, principal = await _authenticated_channels(authorization)
    try:
        message = await service.send(
            principal.tenant, channel, principal.actor,
            request.content, request.idempotency_key,
        )
    except Exception as exc:
        raise HTTPException(status_code=403, detail=type(exc).__name__) from None
    return message.__dict__
