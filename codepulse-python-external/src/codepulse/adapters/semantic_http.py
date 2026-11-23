"""OpenAI-compatible chat-completions backend over stdlib HTTP (spec 002 FR-202).

Works with internal gateways, vLLM, and local Ollama (``http://localhost:11434/v1``).
Egress policy (allow-list, retention/training declarations) is enforced when the config
loads; this adapter refuses to be built from an unvalidated config as a second line.
"""

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from codepulse.core.config import SemanticConfig
from codepulse.core.errors import ConfigError
from codepulse.core.semantic import BackendError, SemanticRequest, SemanticResponse

_RETRYABLE = frozenset({429, 500, 502, 503, 504})
_BACKOFF_S = 2.0


class OpenAICompatibleBackend:
    name = "openai_compatible"

    def __init__(self, cfg: SemanticConfig) -> None:
        if cfg.backend != self.name or not cfg.base_url or not cfg.model:
            raise ConfigError("semantic backend is not configured as openai_compatible")
        host = urlsplit(cfg.base_url).hostname or ""
        if host not in cfg.allowed_hosts or cfg.retention != "none" or cfg.training != "prohibited":
            raise ConfigError("semantic backend failed egress policy checks")
        self.model_id = cfg.model
        self._url = cfg.base_url.rstrip("/") + "/chat/completions"
        self._cfg = cfg
        key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
        if cfg.api_key_env and not key:
            raise ConfigError(
                f"semantic.api_key_env: environment variable {cfg.api_key_env} is not set"
            )
        self._headers = {"Content-Type": "application/json"}
        if key:
            self._headers["Authorization"] = f"Bearer {key}"

    def _body(self, request: SemanticRequest) -> bytes:
        body: dict[str, Any] = {
            "model": self.model_id,
            "temperature": 0,
            "max_tokens": request.max_tokens,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
        }
        if self._cfg.json_mode:
            body["response_format"] = {"type": "json_object"}
        return json.dumps(body).encode("utf-8")

    def evaluate(self, request: SemanticRequest) -> SemanticResponse:
        data = self._body(request)
        # One authoritative retry layer with a single bounded retry (our own E04 standard).
        for attempt in (1, 2):
            req = urllib.request.Request(self._url, data=data, headers=self._headers, method="POST")  # noqa: S310 — https enforced at config load
            try:
                with urllib.request.urlopen(req, timeout=self._cfg.timeout_s) as resp:  # noqa: S310 — https enforced at config load
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code in _RETRYABLE and attempt == 1:
                    time.sleep(_BACKOFF_S)
                    continue
                raise BackendError("backend_error", f"HTTP {exc.code}") from exc
            except TimeoutError as exc:
                raise BackendError("timeout", f"no response within {self._cfg.timeout_s}s") from exc
            except (urllib.error.URLError, OSError, ValueError) as exc:
                raise BackendError("backend_error", f"{type(exc).__name__}: {exc}") from exc
        try:
            text = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage") or {}
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError("backend_error", "response is not chat-completions shaped") from exc
        return SemanticResponse(
            str(text), int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
        )
