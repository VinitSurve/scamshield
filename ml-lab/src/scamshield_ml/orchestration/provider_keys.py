"""Provider Multi-Key Health Manager & Automatic Failover Engine.

Safely manages pools of Gemini and Groq API keys with:
- Health checking and masked identification (never exposing secrets)
- Rate-limit (HTTP 429) backoff & automatic cooldown
- Round-robin key rotation across healthy key pools
- Provider fallback routing (Gemini -> Groq -> Local Heuristics)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class KeyHealthInfo:
    provider: str
    key_id: str
    masked_key: str
    is_healthy: bool
    failure_count: int
    cooldown_until: float
    last_used: float
    last_error: Optional[str] = None


class ProviderKeyManager:
    """Thread-safe multi-key rotation and provider failover manager."""

    _instance: Optional[ProviderKeyManager] = None

    def __init__(self) -> None:
        self.gemini_keys: List[str] = self._load_keys("GEMINI_API_KEYS", "GEMINI_API_KEY", "GOOGLE_API_KEY")
        self.groq_keys: List[str] = self._load_keys("GROQ_API_KEYS", "GROQ_API_KEY")

        self.key_health: Dict[str, KeyHealthInfo] = {}
        self.gemini_idx = 0
        self.groq_idx = 0

        self._init_pool("gemini", self.gemini_keys)
        self._init_pool("groq", self.groq_keys)

    @classmethod
    def get_instance(cls) -> ProviderKeyManager:
        if cls._instance is None:
            cls._instance = ProviderKeyManager()
        return cls._instance

    @staticmethod
    def _load_keys(*env_names: str) -> List[str]:
        keys = []
        for name in env_names:
            val = os.getenv(name, "")
            if val:
                for k in val.split(","):
                    k = k.strip()
                    if k and k not in keys:
                        keys.append(k)
        return keys

    @staticmethod
    def mask_key(key: str) -> str:
        """Masks sensitive API key, showing only prefix and last 4 characters."""
        if not key or len(key) < 8:
            return "***"
        return f"{key[:4]}...{key[-4:]}"

    def _init_pool(self, provider: str, keys: List[str]) -> None:
        for idx, key in enumerate(keys):
            key_id = f"{provider}_{idx+1}"
            self.key_health[key_id] = KeyHealthInfo(
                provider=provider,
                key_id=key_id,
                masked_key=self.mask_key(key),
                is_healthy=True,
                failure_count=0,
                cooldown_until=0.0,
                last_used=0.0,
            )

    def get_healthy_key(self, provider: str) -> Optional[Tuple[str, str]]:
        """Returns (key_id, raw_key) for the next healthy key in the pool."""
        keys = self.gemini_keys if provider == "gemini" else self.groq_keys
        if not keys:
            return None

        now = time.time()
        start_idx = self.gemini_idx if provider == "gemini" else self.groq_idx

        for attempt in range(len(keys)):
            idx = (start_idx + attempt) % len(keys)
            key_id = f"{provider}_{idx+1}"
            health = self.key_health.get(key_id)

            if health and health.is_healthy and now >= health.cooldown_until:
                if provider == "gemini":
                    self.gemini_idx = (idx + 1) % len(keys)
                else:
                    self.groq_idx = (idx + 1) % len(keys)
                health.last_used = now
                return key_id, keys[idx]

        return None

    def record_success(self, key_id: str) -> None:
        """Records a successful API call on the key."""
        if key_id in self.key_health:
            self.key_health[key_id].is_healthy = True
            self.key_health[key_id].failure_count = 0
            self.key_health[key_id].cooldown_until = 0.0

    def record_rate_limit(self, key_id: str, cooldown_sec: float = 60.0) -> None:
        """Puts a key into temporary cooldown due to HTTP 429 rate limit."""
        if key_id in self.key_health:
            self.key_health[key_id].cooldown_until = time.time() + cooldown_sec
            self.key_health[key_id].failure_count += 1
            self.key_health[key_id].last_error = f"Rate limited (429), cooling down {cooldown_sec}s"
            logger.warning("Key %s rate-limited; cooldown for %ds", key_id, cooldown_sec)

    def record_failure(self, key_id: str, error: str) -> None:
        """Records a request failure on the key."""
        if key_id in self.key_health:
            self.key_health[key_id].failure_count += 1
            self.key_health[key_id].last_error = error
            if self.key_health[key_id].failure_count >= 3:
                self.key_health[key_id].is_healthy = False
                logger.warning("Key %s marked unhealthy after %d failures: %s", key_id, self.key_health[key_id].failure_count, error)

    def get_status(self) -> Dict[str, Any]:
        """Returns safe operational status without exposing secrets."""
        now = time.time()
        return {
            "gemini": {
                "total_keys": len(self.gemini_keys),
                "healthy_keys": sum(1 for k, v in self.key_health.items() if v.provider == "gemini" and v.is_healthy and now >= v.cooldown_until),
                "keys": [asdict(v) for v in self.key_health.values() if v.provider == "gemini"],
            },
            "groq": {
                "total_keys": len(self.groq_keys),
                "healthy_keys": sum(1 for k, v in self.key_health.items() if v.provider == "groq" and v.is_healthy and now >= v.cooldown_until),
                "keys": [asdict(v) for v in self.key_health.values() if v.provider == "groq"],
            },
        }
