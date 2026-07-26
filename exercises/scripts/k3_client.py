#!/usr/bin/env python3
"""
k3_client.py: minimal shared client for Kimi K3 via Fireworks AI or Moonshot AI.

Both providers expose an OpenAI-compatible Chat Completions API, so one small
client covers both. All exercise scripts in this pack import from here.

Usage as a connectivity check (Lab 0):

    python3 scripts/k3_client.py --check

Environment variables:
    K3_PROVIDER        "fireworks" (default) or "moonshot"
    FIREWORKS_API_KEY  API key from https://fireworks.ai  (Settings -> API Keys)
    MOONSHOT_API_KEY   API key from https://platform.moonshot.ai
    K3_MODEL           Override the model id if the listing differs at launch.

Notes on K3 behavior that matter for these scripts (per the Moonshot K3 docs,
July 2026; verify against the provider you actually use):
  * K3 ALWAYS reasons; the effort is configurable via the top-level
    `reasoning_effort` request field: "low" | "high" | "max" (default "max").
    Your max_tokens budget must cover BOTH the reasoning trace and the visible
    answer. When in doubt, give it headroom (we default to 16k).
  * Sampling parameters are fixed server-side (temperature=1.0, top_p=0.95);
    omit them from requests.
  * Strict JSON Schema output is supported via
    response_format={"type": "json_schema", ...}; parse message.content only,
    never the reasoning fields. The scripts try strict schema first and fall
    back to tolerant parsing if a provider rejects it.
  * If you build multi-turn tool loops, send the complete assistant message
    back on the next request, including reasoning fields. The scripts in this
    pack use stateless single turns, which sidesteps this.
  * Moonshot's hosted web-search tool is being updated and is not recommended
    for near-term production use; do your own retrieval (as these scripts do).

Data-policy gate: these scripts send file contents, scan output, or logs to a
hosted inference endpoint. Every script requires explicit consent before the
first model call: pass --allow-cloud-upload or set K3_ALLOW_UPLOAD=1 after
confirming your data policy (BAA/DPA where applicable). --dry-run never sends
anything.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import requests

PROVIDERS = {
    "fireworks": {
        "base_url": "https://api.fireworks.ai/inference/v1",
        "model": "accounts/fireworks/models/kimi-k3",
        "key_env": "FIREWORKS_API_KEY",
    },
    "moonshot": {
        "base_url": "https://api.moonshot.ai/v1",
        "model": "kimi-k3",
        "key_env": "MOONSHOT_API_KEY",
    },
}

DEFAULT_MAX_TOKENS = 16384
CONSENT_ENV = "K3_ALLOW_UPLOAD"

# USD per 1M tokens. Override either provider with K3_PRICE_JSON:
#   export K3_PRICE_JSON='{"input": 3.0, "cached_input": 0.3, "output": 15.0}'
PRICE_BOOK = {
    "moonshot": {"input": 3.00, "cached_input": 0.30, "output": 15.00},
    "fireworks": {"input": 3.00, "cached_input": 0.30, "output": 15.00},
}


class K3Error(RuntimeError):
    pass


def require_upload_consent(allowed: bool, provider: str, what: str) -> None:
    """Refuse to send data to a hosted API without an explicit opt-in.

    `allowed` is the script's --allow-cloud-upload flag; the K3_ALLOW_UPLOAD=1
    environment variable is the session-level equivalent. --dry-run paths in
    the scripts never call this because they never send anything.
    """
    if allowed or os.environ.get(CONSENT_ENV) == "1":
        return
    raise K3Error(
        f"Data-policy gate: {what} would be sent to the hosted "
        f"'{provider}' inference endpoint. Confirm your data policy permits "
        f"this (BAA/DPA where regulated data is in scope), then either:\n"
        f"  - pass --allow-cloud-upload, or\n"
        f"  - export {CONSENT_ENV}=1\n"
        f"To exercise the pipeline offline with zero upload, use --dry-run."
    )


class K3Client:
    """Stateless Chat Completions client with retries and clear errors."""

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        timeout: int = 300,
        max_retries: int = 4,
    ) -> None:
        self.provider = (provider or os.environ.get("K3_PROVIDER") or "fireworks").lower()
        if self.provider not in PROVIDERS:
            raise K3Error(f"Unknown provider {self.provider!r}. Choose from: {list(PROVIDERS)}")
        cfg = PROVIDERS[self.provider]
        self.base_url = cfg["base_url"].rstrip("/")
        self.model = model or os.environ.get("K3_MODEL") or cfg["model"]
        self.api_key = os.environ.get(cfg["key_env"], "").strip()
        self.timeout = timeout
        self.max_retries = max_retries
        # Token accounting for the whole client lifetime (see estimate_cost).
        self.usage_totals: dict[str, int] = {}
        self.last_usage: dict = {}

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    # ------------------------------------------------------------------
    # Low-level request plumbing
    # ------------------------------------------------------------------

    def _post(self, payload: dict) -> dict:
        """POST one chat-completions request with retries; return raw JSON."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"
        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(url, headers=headers, json=payload,
                                     timeout=self.timeout)
                if resp.status_code == 400 and "reasoning_effort" in payload:
                    # Provider does not know this field; drop it once and
                    # continue with the server default ("max" on Moonshot).
                    payload.pop("reasoning_effort")
                    continue
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise K3Error(f"HTTP {resp.status_code}: {resp.text[:300]}")
                resp.raise_for_status()
                data = resp.json()
                self._record_usage(data.get("usage") or {})
                return data
            except (requests.RequestException, K3Error, KeyError, ValueError) as exc:
                last_err = exc
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 20))
        raise K3Error(f"K3 request failed after {self.max_retries} attempts: {last_err}")

    def _record_usage(self, usage: dict) -> None:
        if not isinstance(usage, dict):
            return
        self.last_usage = usage
        for key in ("prompt_tokens", "completion_tokens", "total_tokens",
                    "cached_tokens", "prompt_cache_hit_tokens",
                    "prompt_cache_miss_tokens"):
            value = usage.get(key)
            if isinstance(value, int):
                self.usage_totals[key] = self.usage_totals.get(key, 0) + value

    def estimate_cost(self) -> dict:
        """Rough USD estimate for accumulated usage (empty dict if pricing
        unknown for the provider; set K3_PRICE_JSON to override)."""
        prices = dict(PRICE_BOOK.get(self.provider, {}))
        override = os.environ.get("K3_PRICE_JSON")
        if override:
            try:
                prices.update(json.loads(override))
            except ValueError:
                pass
        if not prices:
            return {}
        cached = self.usage_totals.get("cached_tokens", 0)
        prompt = self.usage_totals.get("prompt_tokens", 0)
        output = self.usage_totals.get("completion_tokens", 0)
        fresh = max(prompt - cached, 0)
        usd = (cached * prices.get("cached_input", prices.get("input", 0))
               + fresh * prices.get("input", 0)
               + output * prices.get("output", 0)) / 1_000_000
        return {"usd": round(usd, 4), "cached_input_tokens": cached,
                "fresh_input_tokens": fresh, "output_tokens": output}

    # ------------------------------------------------------------------
    # Public call shapes
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict],
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float | None = None,
        response_format: dict | None = None,
        reasoning_effort: str | None = None,
    ) -> str:
        """Single-turn chat call. Returns the assistant message content."""
        if not self.configured:
            raise K3Error(
                f"No API key found for provider '{self.provider}'. "
                f"Set {PROVIDERS[self.provider]['key_env']} and retry, "
                f"or use --dry-run to exercise the pipeline offline."
            )
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": False,
        }
        # K3 fixes sampling server-side; only send temperature if explicitly
        # asked for (some providers reject it entirely).
        if temperature is not None:
            payload["temperature"] = temperature
        if response_format is not None:
            payload["response_format"] = response_format
        if reasoning_effort is not None:
            if reasoning_effort not in ("low", "high", "max"):
                raise K3Error("reasoning_effort must be 'low', 'high', or 'max'")
            payload["reasoning_effort"] = reasoning_effort

        data = self._post(payload)
        content = data["choices"][0]["message"].get("content") or ""
        if not content.strip():
            # Common cause with always-on reasoning: the token budget was
            # consumed by the reasoning trace before any visible answer.
            raise K3Error(
                "Empty completion. K3 reasons on every call; increase "
                "max_tokens so the budget covers reasoning + answer."
            )
        return content

    def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        handlers: dict,
        max_rounds: int = 8,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        reasoning_effort: str | None = None,
        tool_choice: str = "auto",
    ) -> dict:
        """Bounded tool loop that preserves complete assistant messages.

        `handlers` maps tool names to callables taking a dict of arguments and
        returning a string result. The COMPLETE assistant message (including
        reasoning fields, per the K3 docs) is appended verbatim each round;
        trimming it destabilizes multi-turn behavior.

        Returns {"content": str, "rounds": int, "messages": full_history}.
        On round exhaustion, content is "" and the dict gains an "error" key.
        `tool_choice="required"` is available for single-shot forced calls;
        avoid it in loops (the model must be allowed to stop).
        """
        if not self.configured:
            raise K3Error(f"No API key for provider '{self.provider}'.")
        history = list(messages)
        for round_no in range(1, max_rounds + 1):
            payload: dict = {
                "model": self.model,
                "messages": history,
                "max_tokens": max_tokens,
                "stream": False,
                "tools": tools,
                "tool_choice": tool_choice,
            }
            if reasoning_effort is not None:
                payload["reasoning_effort"] = reasoning_effort
            data = self._post(payload)
            msg = data["choices"][0]["message"]
            history.append(msg)  # complete message, reasoning fields included
            calls = msg.get("tool_calls") or []
            if not calls:
                return {"content": msg.get("content") or "",
                        "rounds": round_no, "messages": history}
            for call in calls:
                fn_meta = call.get("function", {})
                name = fn_meta.get("name", "")
                try:
                    args = json.loads(fn_meta.get("arguments") or "{}")
                except ValueError:
                    args = {}
                fn = handlers.get(name)
                try:
                    result = fn(args) if fn else f"error: unknown tool '{name}'"
                except Exception as exc:  # a tool failure must not kill the loop
                    result = f"error: tool '{name}' failed: {exc}"
                history.append({
                    "role": "tool",
                    "tool_call_id": call.get("id", ""),
                    "name": name,
                    "content": str(result)[:8000],
                })
        return {"content": "", "rounds": max_rounds, "messages": history,
                "error": f"max_rounds ({max_rounds}) reached without a final answer"}


def _check() -> int:
    client = K3Client()
    print(f"Provider : {client.provider}")
    print(f"Model    : {client.model}")
    print(f"Endpoint : {client.base_url}")
    if not client.configured:
        print(f"API key  : MISSING (set {PROVIDERS[client.provider]['key_env']})")
        return 1
    t0 = time.time()
    try:
        out = client.chat(
            [
                {"role": "system", "content": "You are a concise assistant."},
                {"role": "user", "content": "Reply with exactly: K3 connection OK"},
            ],
            max_tokens=4096,
        )
    except K3Error as exc:
        print(f"API key  : present, but the call failed: {exc}")
        return 1
    dt = time.time() - t0
    print(f"API key  : present")
    print(f"Latency  : {dt:.1f}s")
    print(f"Response : {out.strip()[:200]}")
    print("\nConnection OK. You are ready for the labs.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kimi K3 connectivity check")
    parser.add_argument("--check", action="store_true", help="verify API access and exit")
    args = parser.parse_args()
    if args.check:
        sys.exit(_check())
    parser.print_help()
