"""Redis-backed storage for session-scoped token <-> PII mappings."""

from __future__ import annotations

import logging
import uuid

import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger("dlp_proxy.redis")


class RedisMappingStore:
    """
    Stores PII token mappings as Redis hashes:

        key:   dlp:session:{session_id}
        field: token  (e.g. "[DLP_PERSON_a1b2c3d4e5]")
        value: original PII string

    Each session hash has a TTL refreshed on every write so active sessions
    don't expire mid-conversation, while idle sessions are cleaned up
    automatically.
    """

    def __init__(self, url: str) -> None:
        self._redis = redis.from_url(url, decode_responses=True)

    @staticmethod
    def _key(session_id: str) -> str:
        return f"dlp:session:{session_id}"

    @staticmethod
    def new_session_id() -> str:
        return uuid.uuid4().hex

    async def store_mapping(self, session_id: str, mapping: dict[str, str], ttl: int | None = None) -> None:
        if not mapping:
            return
        key = self._key(session_id)
        ttl = ttl or settings.token_ttl_seconds
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=mapping)
            pipe.expire(key, ttl)
            await pipe.execute()

    async def get_mapping(self, session_id: str) -> dict[str, str]:
        key = self._key(session_id)
        return await self._redis.hgetall(key)

    async def delete_session(self, session_id: str) -> None:
        await self._redis.delete(self._key(session_id))

    async def ping(self) -> None:
        await self._redis.ping()
        logger.info("Connected to Redis.")

    async def healthcheck(self) -> bool:
        try:
            await self._redis.ping()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Redis healthcheck failed: %s", exc)
            return False

    async def close(self) -> None:
        await self._redis.aclose()


redis_client = RedisMappingStore(settings.redis_url)
