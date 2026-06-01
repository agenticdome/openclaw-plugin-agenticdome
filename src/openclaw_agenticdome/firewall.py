from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Dict, Optional, Tuple

from agentguard_sdk.client import AgentGuardClient, AgentGuardError, AgentGuardHTTPError

logger = logging.getLogger("AgenticDome.openclaw")
logger.addHandler(logging.NullHandler())


# ============================================================================
# AgenticDome x OpenClaw Production Firewall
#
# Provides:
# - inbound prompt screening
# - direct tool/skill authorization
# - manager -> specialist delegated authorization
# - specialist-side single-use decision-token verification
# - output sanitization
# - safe output serialization
# ============================================================================


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _nonempty_text(value: Optional[str], fallback: str) -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _ensure_dict(name: str, value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"'{name}' must be a dict")
    return value


@dataclass(frozen=True)
class OpenClawFirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str

    platform: str = "openclaw"
    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = True

    default_tool_platform: str = "python"

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:openclaw:handoff"

    # SDK already has retries. Keep firewall retries disabled by default to avoid retry multiplication.
    sdk_max_retries: int = 3
    retry_max_attempts: int = 1
    retry_initial_delay_s: float = 0.25
    retry_max_delay_s: float = 2.0

    output_serialization_max_chars: int = 200_000


DEFAULT_CONFIG = OpenClawFirewallConfig(
    api_base=os.getenv("AgenticDome_API_BASE", "").rstrip("/"),
    api_key=os.getenv("AgenticDome_API_KEY", ""),
    tenant_id=os.getenv("AgenticDome_TENANT_ID", ""),
    platform=os.getenv("AgenticDome_PLATFORM", "openclaw"),
    timeout_s=_env_int("AgenticDome_TIMEOUT_S", 20),
    fail_closed=_env_bool("AgenticDome_FAIL_CLOSED", True),
    require_explicit_session_id=_env_bool("AgenticDome_REQUIRE_SESSION_ID", True),
    default_tool_platform=os.getenv("AgenticDome_DEFAULT_TOOL_PLATFORM", "python"),
    redact_pii=_env_bool("AgenticDome_REDACT_PII", True),
    redact_secrets=_env_bool("AgenticDome_REDACT_SECRETS", True),
    block_on_sensitive_output=_env_bool("AgenticDome_BLOCK_ON_SENSITIVE_OUTPUT", False),
    handoff_token_ttl_s=_env_int("AgenticDome_HANDOFF_TOKEN_TTL_S", 900),
    redis_url=os.getenv("AgenticDome_REDIS_URL", "").strip(),
    redis_key_prefix=os.getenv("AgenticDome_REDIS_KEY_PREFIX", "AgenticDome:openclaw:handoff"),
    sdk_max_retries=_env_int("AgenticDome_SDK_MAX_RETRIES", 3),
    retry_max_attempts=_env_int("AgenticDome_RETRY_MAX_ATTEMPTS", 1),
    retry_initial_delay_s=_env_float("AgenticDome_RETRY_INITIAL_DELAY_S", 0.25),
    retry_max_delay_s=_env_float("AgenticDome_RETRY_MAX_DELAY_S", 2.0),
    output_serialization_max_chars=_env_int("AgenticDome_OUTPUT_SERIALIZATION_MAX_CHARS", 200_000),
)


class OpenClawFirewallError(RuntimeError):
    """Base OpenClaw integration error."""


class OpenClawExecutionDenied(OpenClawFirewallError):
    """Raised when AgenticDome blocks or fails-closed execution."""


@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float


def _stable_type_name(value: Any) -> str:
    typ = type(value)
    return f"{typ.__module__}.{typ.__qualname__}"


def _obfuscated_object_identifier(value: Any) -> str:
    raw = f"{_stable_type_name(value)}:{id(value)}".encode("utf-8", errors="ignore")
    ref = hashlib.sha256(raw).hexdigest()[:16]
    return f"<non_serializable_object type={_stable_type_name(value)} ref={ref}>"


def _safe_jsonable(value: Any, *, depth: int = 0, max_depth: int = 20, max_items: int = 1000) -> Any:
    """
    Convert data to JSON-safe form without calling unsafe custom __str__ / __repr__.

    Unsupported objects become opaque identifiers, not debug dumps.
    """
    if depth > max_depth:
        return "<max_depth_exceeded>"

    if value is None or type(value) in {bool, int, float, str}:
        return value

    if isinstance(value, bytes):
        return {
            "__type__": "bytes",
            "length": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }

    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for idx, item in enumerate(value.items()):
            if idx >= max_items:
                out["<truncated>"] = f"exceeded max_items={max_items}"
                break

            key, val = item

            if type(key) is str:
                safe_key = key
            elif type(key) in {int, float, bool} or key is None:
                safe_key = json.dumps(key, sort_keys=True)
            else:
                safe_key = f"<non_string_key type={_stable_type_name(key)}>"

            out[safe_key] = _safe_jsonable(
                val,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
            )

        return out

    if isinstance(value, (list, tuple)):
        out = []
        for idx, item in enumerate(value):
            if idx >= max_items:
                out.append(f"<truncated: exceeded max_items={max_items}>")
                break
            out.append(
                _safe_jsonable(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                )
            )
        return out

    if isinstance(value, set):
        safe_items = []
        for idx, item in enumerate(value):
            if idx >= max_items:
                safe_items.append(f"<truncated: exceeded max_items={max_items}>")
                break
            safe_items.append(
                _safe_jsonable(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                )
            )

        try:
            return sorted(safe_items, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
        except Exception:
            return safe_items

    return _obfuscated_object_identifier(value)


def _canonical_json(value: Any) -> str:
    """
    Stable JSON for fingerprints.

    Does not use default=str because that can leak internals from custom objects.
    """
    safe_value = _safe_jsonable(value)
    return json.dumps(safe_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {
        "tool_name": tool_name or "",
        "tool_args": tool_args or {},
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def safe_result_to_text(raw_result: Any, *, max_chars: int) -> str:
    """
    Safe output serialization.

    Security goals:
    - Never blindly call str(custom_object).
    - Never use json.dumps(..., default=str).
    - If serialization fails, return an opaque identifier.
    - If output is too large, return a digest summary instead of leaking a prefix.
    """
    try:
        if type(raw_result) is str:
            text = raw_result
        elif raw_result is None or type(raw_result) in {bool, int, float}:
            text = json.dumps(raw_result, ensure_ascii=False)
        elif isinstance(raw_result, bytes):
            text = json.dumps(
                {
                    "__type__": "bytes",
                    "length": len(raw_result),
                    "sha256": hashlib.sha256(raw_result).hexdigest(),
                },
                ensure_ascii=False,
            )
        elif isinstance(raw_result, (dict, list, tuple, set)):
            safe_value = _safe_jsonable(raw_result)
            text = json.dumps(safe_value, indent=2, ensure_ascii=False)
        else:
            text = _obfuscated_object_identifier(raw_result)
    except Exception:
        try:
            text = _obfuscated_object_identifier(raw_result)
        except Exception:
            text = "<non_serializable_object ref=unavailable>"

    if max_chars > 0 and len(text) > max_chars:
        digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        return (
            "[OUTPUT OMITTED BY AgenticDome OPENCLAW ADAPTER: "
            f"serialized output exceeded max_chars={max_chars}; "
            f"length={len(text)}; sha256={digest}]"
        )

    return text


class DecisionTokenStore:
    def put(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        record: DecisionTokenRecord,
        ttl_s: int,
    ) -> None:
        raise NotImplementedError

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        raise NotImplementedError

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        raise NotImplementedError

    def pop(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        """Atomically consume a single-use token."""
        raise NotImplementedError


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
        self._lock = Lock()
        self._data: Dict[str, Tuple[float, DecisionTokenRecord]] = {}

    def _key(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

    def _cleanup_locked(self) -> None:
        now = time.time()
        expired = [k for k, (expires_at, _) in self._data.items() if expires_at <= now]
        for key in expired:
            self._data.pop(key, None)

    def put(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        record: DecisionTokenRecord,
        ttl_s: int,
    ) -> None:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        with self._lock:
            self._cleanup_locked()
            self._data[key] = (time.time() + ttl_s, record)

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        with self._lock:
            self._cleanup_locked()
            entry = self._data.get(key)
            return entry[1] if entry else None

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        with self._lock:
            self._data.pop(key, None)

    def pop(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        with self._lock:
            self._cleanup_locked()
            entry = self._data.pop(key, None)
            return entry[1] if entry else None


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, redis_url: str, key_prefix: str, tenant_id: str) -> None:
        import redis

        self._tenant_id = tenant_id
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix.rstrip(":")
        self._getdel_script = """
        local value = redis.call('GET', KEYS[1])
        if value then
          redis.call('DEL', KEYS[1])
        end
        return value
        """

    def _key(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        return f"{self._prefix}:{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

    @staticmethod
    def _decode_record(raw: Optional[str]) -> Optional[DecisionTokenRecord]:
        if not raw:
            return None
        try:
            payload = json.loads(raw)
            return DecisionTokenRecord(
                decision_token=str(payload["decision_token"]),
                source_agent_id=str(payload["source_agent_id"]),
                created_at=float(payload["created_at"]),
            )
        except Exception:
            return None

    def put(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        record: DecisionTokenRecord,
        ttl_s: int,
    ) -> None:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        payload = {
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
        }
        self._client.setex(key, ttl_s, _canonical_json(payload))

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        raw = self._client.get(key)
        record = self._decode_record(raw)
        if raw and record is None:
            self._client.delete(key)
        return record

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        self._client.delete(key)

    def pop(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )

        try:
            raw = self._client.getdel(key)
        except AttributeError:
            raw = self._client.eval(self._getdel_script, 1, key)

        return self._decode_record(raw)


def _build_token_store(config: OpenClawFirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            logger.info("AgenticDome OpenClaw firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)

    return InMemoryDecisionTokenStore(config.tenant_id)


class OpenClawFirewall:
    _RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(self, *, config: OpenClawFirewallConfig = DEFAULT_CONFIG):
        if not config.api_base or not config.api_key or not config.tenant_id:
            raise ValueError(
                "AgenticDome firewall misconfigured. "
                "Set AgenticDome_API_BASE, AgenticDome_API_KEY, AgenticDome_TENANT_ID."
            )

        self.config = config
        self.client = AgentGuardClient(
            api_base=config.api_base,
            api_key=config.api_key,
            tenant_id=config.tenant_id,
            timeout=config.timeout_s,
            max_retries=config.sdk_max_retries,
        )
        self.token_store = _build_token_store(config)

    def _require_session_id(self, session_id: str) -> None:
        if self.config.require_explicit_session_id and not str(session_id or "").strip():
            raise OpenClawExecutionDenied("Missing required explicit session_id.")

    def _fail_or_raise(self, message: str, exc: Optional[Exception] = None) -> None:
        if self.config.fail_closed:
            if exc:
                raise OpenClawExecutionDenied(message) from exc
            raise OpenClawExecutionDenied(message)

        logger.warning("AgenticDome FAIL-OPEN: %s", message)

    @staticmethod
    def _http_status(exc: Exception) -> Optional[int]:
        for attr in ("status_code", "status", "code"):
            value = getattr(exc, attr, None)
            if value is not None:
                try:
                    return int(value)
                except Exception:
                    pass

        response = getattr(exc, "response", None)
        if response is not None:
            for attr in ("status_code", "status", "code"):
                value = getattr(response, attr, None)
                if value is not None:
                    try:
                        return int(value)
                    except Exception:
                        pass

        return None

    def _is_retryable_exception(self, exc: Exception) -> bool:
        if isinstance(exc, AgentGuardHTTPError):
            return self._http_status(exc) in self._RETRYABLE_STATUS_CODES

        name = exc.__class__.__name__.lower()
        module = exc.__class__.__module__.lower()
        transient_markers = (
            "timeout",
            "connectionerror",
            "connecterror",
            "readtimeout",
            "networkerror",
            "temporarilyunavailable",
            "serviceunavailable",
        )
        return any(marker in name or marker in module for marker in transient_markers)

    def _agentguard_call(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """
        Optional outer retry loop.

        The official SDK already retries HTTP transport failures. Keep
        AgenticDome_RETRY_MAX_ATTEMPTS=1 unless you intentionally want a second layer.
        """
        max_attempts = max(1, int(self.config.retry_max_attempts))
        base_delay = max(0.0, float(self.config.retry_initial_delay_s))
        max_delay = max(base_delay, float(self.config.retry_max_delay_s))

        method = getattr(self.client, method_name)

        for attempt in range(1, max_attempts + 1):
            try:
                return method(*args, **kwargs)
            except Exception as exc:
                retryable = self._is_retryable_exception(exc)
                last_attempt = attempt >= max_attempts

                if not retryable or last_attempt:
                    raise

                delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                jitter = random.uniform(0, delay * 0.25) if delay > 0 else 0.0

                logger.warning(
                    "AgenticDome transient client error; retrying method=%s attempt=%s/%s delay=%.3fs error=%s",
                    method_name,
                    attempt,
                    max_attempts,
                    delay + jitter,
                    exc,
                )

                time.sleep(delay + jitter)

        raise RuntimeError("unreachable")

    def _tool_platform(self, tool_platform: Optional[str], tool_args: Dict[str, Any]) -> str:
        return str(
            tool_platform
            or tool_args.get("tool_platform")
            or tool_args.get("platform")
            or self.config.default_tool_platform
        )

    def _extract_result(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}

        if payload.get("error"):
            err = payload.get("error")
            raise OpenClawExecutionDenied(f"AgenticDome JSON-RPC error: {err}")

        result = payload.get("result")
        return result if isinstance(result, dict) else payload

    def _verdict(self, payload: Dict[str, Any]) -> str:
        env = self._extract_result(payload)
        return str(env.get("verdict") or env.get("decision") or "").upper()

    def _reason(self, payload: Dict[str, Any]) -> str:
        env = self._extract_result(payload)
        return str(env.get("reason") or env.get("message") or payload)

    def _merged_policy_context(
        self,
        *,
        agent_id: str,
        request_purpose: str,
        policy_context: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = dict(policy_context or {})
        ctx.setdefault("source_agent_id", agent_id)
        ctx.setdefault("request_purpose", request_purpose)
        ctx.setdefault("platform", self.config.platform)
        if extra:
            ctx.update(extra)
        return ctx

    def screen_prompt(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_session_id(session_id)
        text = _nonempty_text(text, "[empty prompt]")

        try:
            response = self._agentguard_call(
                "guardrail_validate",
                session_id=session_id,
                direction="input",
                text=text,
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                policy_context=self._merged_policy_context(
                    agent_id=agent_id,
                    request_purpose="prompt_input",
                    policy_context=policy_context,
                ),
            )

            if self._verdict(response) == "BLOCKED":
                raise OpenClawExecutionDenied(f"AgenticDome blocked prompt: {self._reason(response)}")

            return response

        except OpenClawExecutionDenied:
            raise
        except ValueError as exc:
            raise OpenClawFirewallError(f"AgenticDome SDK contract error during input screening: {exc}") from exc
        except (AgentGuardError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome input screening error: {exc}", exc=exc)
            return {}

    def authorize_direct_skill(
        self,
        *,
        text: str,
        agent_id: str,
        skill_name: str,
        skill_args: Dict[str, Any],
        session_id: str,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_session_id(session_id)

        skill_args = _ensure_dict("skill_args", skill_args)
        text = _nonempty_text(text, f"[OpenClaw] Agent {agent_id} executing {skill_name}")
        effective_tool_platform = self._tool_platform(tool_platform, skill_args)

        try:
            response = self._agentguard_call(
                "guardrail_validate",
                session_id=session_id,
                direction="outbound",
                text=text,
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=effective_tool_platform,
                tool_name=skill_name,
                tool_args=skill_args,
                policy_context=self._merged_policy_context(
                    agent_id=agent_id,
                    request_purpose="skill_execution",
                    policy_context=policy_context,
                    extra={"tool_platform": effective_tool_platform},
                ),
            )

            if self._verdict(response) == "BLOCKED":
                raise OpenClawExecutionDenied(f"AgenticDome blocked skill execution: {self._reason(response)}")

            return response

        except OpenClawExecutionDenied:
            raise
        except ValueError as exc:
            raise OpenClawFirewallError(f"AgenticDome SDK contract error during direct authorization: {exc}") from exc
        except (AgentGuardError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome direct authorization error: {exc}", exc=exc)
            return {}

    def authorize_manager_handoff(
        self,
        *,
        text: str,
        manager_agent_id: str,
        specialist_agent_id: str,
        skill_name: str,
        skill_args: Dict[str, Any],
        session_id: str,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_session_id(session_id)

        skill_args = _ensure_dict("skill_args", skill_args)
        text = _nonempty_text(
            text,
            f"[OpenClaw] Manager {manager_agent_id} delegates {skill_name} to {specialist_agent_id}",
        )
        effective_tool_platform = self._tool_platform(tool_platform, skill_args)

        try:
            response = self._agentguard_call(
                "a2a_authorize_tool",
                text=text,
                agent_id=specialist_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=effective_tool_platform,
                tool_name=skill_name,
                tool_args=skill_args,
                session_id=session_id,
                direction="outbound",
                source_agent_id=manager_agent_id,
                policy_context=self._merged_policy_context(
                    agent_id=manager_agent_id,
                    request_purpose="delegated_task",
                    policy_context=policy_context,
                    extra={
                        "source_agent_id": manager_agent_id,
                        "delegation_chain": [manager_agent_id, specialist_agent_id],
                        "tool_platform": effective_tool_platform,
                    },
                ),
            )

            envelope = self._extract_result(response)

            if self._verdict(envelope) != "ALLOWED":
                raise OpenClawExecutionDenied(f"AgenticDome blocked delegation: {self._reason(envelope)}")

            decision_token = str(envelope.get("decision_token") or "")
            if decision_token:
                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=specialist_agent_id,
                    tool_name=skill_name,
                    tool_args=skill_args,
                    record=DecisionTokenRecord(
                        decision_token=decision_token,
                        source_agent_id=manager_agent_id,
                        created_at=time.time(),
                    ),
                    ttl_s=self.config.handoff_token_ttl_s,
                )

            return envelope

        except OpenClawExecutionDenied:
            raise
        except ValueError as exc:
            raise OpenClawFirewallError(f"AgenticDome SDK contract error during delegation authorization: {exc}") from exc
        except (AgentGuardError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome delegation authorization error: {exc}", exc=exc)
            return {}

    def verify_specialist_execution(
        self,
        *,
        specialist_agent_id: str,
        skill_name: str,
        skill_args: Dict[str, Any],
        session_id: str,
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._require_session_id(session_id)

        skill_args = _ensure_dict("skill_args", skill_args)
        token = decision_token
        source = source_agent_id

        # Strict single-use nonce behavior: consume local pending token before remote verdict.
        if not token:
            pending = self.token_store.pop(
                session_id=session_id,
                target_agent_id=specialist_agent_id,
                tool_name=skill_name,
                tool_args=skill_args,
            )

            if pending:
                token = pending.decision_token
                source = pending.source_agent_id

        if not token or not source:
            raise OpenClawExecutionDenied(
                "Missing AgenticDome delegation token or source agent id for specialist execution."
            )

        try:
            if hasattr(self.client, "a2a_verify_decision_token_rpc"):
                response = self._agentguard_call(
                    "a2a_verify_decision_token_rpc",
                    token=token,
                    tool_name=skill_name,
                    tool_args=skill_args,
                    agent_id=specialist_agent_id,
                    source_agent_id=source,
                    platform=self.config.platform,
                    require_allowed=True,
                )
            else:
                response = self._agentguard_call(
                    "a2a_action_call",
                    "security.decision.verify",
                    {
                        "token": token,
                        "tool_name": skill_name,
                        "tool_args": skill_args,
                        "agent_id": specialist_agent_id,
                        "source_agent_id": source,
                        "platform": self.config.platform,
                        "require_allowed": True,
                    },
                )

            result = self._extract_result(response)

            if not bool(result.get("valid")):
                raise OpenClawExecutionDenied(
                    f"AgenticDome blocked delegated execution: {result.get('reason') or result}"
                )

            return result

        except OpenClawExecutionDenied:
            raise
        except ValueError as exc:
            raise OpenClawFirewallError(f"AgenticDome SDK contract error during token verification: {exc}") from exc
        except (AgentGuardError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome token verification error: {exc}", exc=exc)
            return {}

    def sanitize_output(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        self._require_session_id(session_id)

        safe_text = _nonempty_text(text, "[empty output]")

        try:
            response = self._agentguard_call(
                "mesh_validate",
                agent_id=agent_id,
                session_id=session_id,
                direction="output",
                text=safe_text,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._merged_policy_context(
                    agent_id=agent_id,
                    request_purpose="output_review",
                    policy_context=policy_context,
                    extra={
                        "redact_pii": self.config.redact_pii,
                        "redact_secrets": self.config.redact_secrets,
                        "block_on_sensitive_output": self.config.block_on_sensitive_output,
                    },
                ),
            )

            envelope = self._extract_result(response)
            verdict = self._verdict(envelope)

            sanitized_text = (
                envelope.get("text")
                or envelope.get("sanitized_text")
                or response.get("text")
                or response.get("sanitized_text")
            )

            if verdict == "BLOCKED":
                logger.warning(
                    "AgenticDome blocked output for agent=%s reason=%s",
                    agent_id,
                    self._reason(envelope),
                )
                return "[OUTPUT BLOCKED BY AgenticDome]"

            if sanitized_text is not None:
                return str(sanitized_text)

            return safe_text

        except OpenClawExecutionDenied:
            raise
        except ValueError as exc:
            raise OpenClawFirewallError(f"AgenticDome SDK contract error during mesh sanitization: {exc}") from exc
        except (AgentGuardError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome mesh sanitization error: {exc}", exc=exc)
            return safe_text

    def protected_execute(
        self,
        *,
        agent_id: str,
        skill_name: str,
        skill_func: Callable[..., Any],
        skill_args: Dict[str, Any],
        session_id: str,
        text: str,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        delegated: bool = False,
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Any:
        """
        Use inside your OpenClaw dispatcher / SkillManager wrapper.
        """
        self._require_session_id(session_id)

        skill_args = _ensure_dict("skill_args", skill_args)

        if delegated:
            self.verify_specialist_execution(
                specialist_agent_id=agent_id,
                skill_name=skill_name,
                skill_args=skill_args,
                session_id=session_id,
                decision_token=decision_token,
                source_agent_id=source_agent_id,
            )
        else:
            self.authorize_direct_skill(
                text=text,
                agent_id=agent_id,
                skill_name=skill_name,
                skill_args=skill_args,
                session_id=session_id,
                tool_platform=tool_platform,
                policy_context=policy_context,
            )

        raw_result = skill_func(**skill_args)

        result_text = safe_result_to_text(
            raw_result,
            max_chars=self.config.output_serialization_max_chars,
        )

        return self.sanitize_output(
            text=result_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context=policy_context,
        )

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            logger.debug("AgenticDome client close failed", exc_info=True)