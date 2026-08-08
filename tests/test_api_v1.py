import httpx
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from soul_platform.api import app
from soul_platform.auth import PrincipalTokenIssuer
from soul_platform.coordination import ChannelService, CoordinatorStore
from soul_platform.receipts import ReceiptCheckpointStore, ReceiptSigner


async def test_api_core_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SOUL_PLATFORM_DATA", str(tmp_path))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/api/health")).json()["agency_default"] == "disabled"
        created = await client.post("/api/souls", json={"name": "Maya"})
        assert created.status_code == 200
        stored = await client.post(
            "/api/souls/Maya/remember", json={"content": "likes astronomy", "importance": 8}
        )
        assert stored.status_code == 200
        boot = await client.get("/api/souls/Maya/boot")
        assert boot.status_code == 200 and "Maya" in boot.json()["boot_context"]


async def test_api_rejects_path_like_names(tmp_path, monkeypatch):
    monkeypatch.setenv("SOUL_PLATFORM_DATA", str(tmp_path))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.post("/api/souls", json={"name": "../escape"})).status_code == 422


async def test_dm_api_derives_actor_and_tenant_from_signed_token(tmp_path, monkeypatch):
    db, heads = tmp_path / "coord.db", tmp_path / "heads.db"
    receipt = ReceiptSigner.generate("coordinator")
    auth_private = Ed25519PrivateKey.generate()
    auth_public = auth_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv("SOUL_PLATFORM_COORDINATOR_DB", str(db))
    monkeypatch.setenv("SOUL_PLATFORM_CHECKPOINT_DB", str(heads))
    monkeypatch.setenv("SOUL_PLATFORM_RECEIPT_KEY", base64.b64encode(receipt.private_bytes()).decode())
    monkeypatch.setenv("SOUL_PLATFORM_RECEIPT_KEY_ID", "coordinator")
    monkeypatch.setenv(
        "SOUL_PLATFORM_AUTH_KEYS", json.dumps({"auth-1": base64.b64encode(auth_public).decode()}),
    )
    store = CoordinatorStore(db, receipt, ReceiptCheckpointStore(str(heads)))
    await store.initialize()
    for actor, role in (("ada", "lead"), ("alice", "worker"), ("nexus", "worker")):
        await store.add_member("team", actor, role)
    await ChannelService(store).create_channel(
        "team", "ada", "dm:ada:alice", kind="dm", participants={"alice"}
    )
    issuer = PrincipalTokenIssuer(auth_private, "auth-1")
    alice = issuer.issue("team", "alice")
    nexus = issuer.issue("team", "nexus")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/api/channels/dm:ada:alice/messages")).status_code == 401
        sent = await client.post(
            "/api/channels/dm:ada:alice/messages",
            headers={"Authorization": f"Bearer {alice}"},
            json={"content": "secret", "idempotency_key": "m1"},
        )
        assert sent.status_code == 200 and sent.json()["sender"] == "alice"
        read = await client.get(
            "/api/channels/dm:ada:alice/messages",
            headers={"Authorization": f"Bearer {alice}"},
        )
        assert read.status_code == 200 and read.json()["messages"][0]["content"] == "secret"
        denied = await client.get(
            "/api/channels/dm:ada:alice/messages",
            headers={"Authorization": f"Bearer {nexus}"},
        )
        assert denied.status_code == 403
