"""NIM streaming transport for qualification, matching the frozen Run D envelope.

This carries no owner-authorization coupling: qualification is synthetic and
non-claim-bearing, so there is no experiment authorization to consume. The
request envelope, streaming SSE reconstruction and [DONE] acquisition mirror
the Run B / Run D transport so candidates are measured under the same
conditions. The credential is read from the environment and used only as a
Bearer header; it is never printed or persisted.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from oat.qualification.runner import ProviderFailure

ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
CREDENTIAL_ENV = "NVIDIA_API_KEY"
TIMEOUT_SECONDS = 120


def _data_payloads(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderFailure("MALFORMED_SSE") from exc
    payloads: list[str] = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        lines = [line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")]
        if lines:
            payloads.append("\n".join(lines))
    return payloads


def _reconstruct(raw: bytes) -> tuple[str, bool]:
    content: list[str] = []
    done = False
    for data in _data_payloads(raw):
        if data == "[DONE]":
            done = True
            continue
        try:
            event = json.loads(data)
            for choice in event.get("choices", []):
                value = choice.get("delta", {}).get("content")
                if isinstance(value, str):
                    content.append(value)
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise ProviderFailure("MALFORMED_SSE") from exc
    return "".join(content), done


class NimTransport:
    """Frozen Run-D-compatible NIM transport. Raises ProviderFailure on any fault."""

    def __init__(
        self, *, seed: int = 20260915, temperature: float = 0.0, max_tokens: int = 4096
    ) -> None:
        self.seed = seed
        self.temperature = temperature
        self.max_tokens = max_tokens

    def __call__(self, messages: list[dict[str, str]]) -> str:
        api_key = os.environ.get(CREDENTIAL_ENV, "")
        if not api_key:
            raise ProviderFailure("credential absent")
        body: dict[str, Any] = {
            "max_tokens": self.max_tokens,
            "messages": messages,
            "model": MODEL,
            "seed": self.seed,
            "stream": True,
            "temperature": self.temperature,
            "top_p": 1.0,
        }
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        request = urllib.request.Request(
            ENDPOINT,
            data=data,
            method="POST",
            headers={
                "Accept": "text/event-stream",
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        raw = bytearray()
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                raw.extend(response.read())
        except (urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise ProviderFailure(f"transport failure: {type(exc).__name__}") from None
        content, done = _reconstruct(bytes(raw))
        if not done:
            raise ProviderFailure("stream incomplete")
        return content
