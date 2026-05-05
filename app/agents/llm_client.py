from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


class BudgetExceededError(Exception):
    """Raised when token budget is exceeded."""
    pass


class LLMTimeoutError(Exception):
    """Raised when an LLM call times out."""
    pass


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass
class LLMResponse:
    content: str = ""
    tool_use: dict[str, Any] | None = None
    tool_name: str = ""
    usage: TokenUsage = field(default_factory=TokenUsage)
    stop_reason: str = ""


class LLMClient:
    # Per-call timeout (seconds) — hard limit for a single API request
    _CALL_TIMEOUT = 90

    def __init__(self, model: str | None = None):
        self._model = model or settings.anthropic_model
        self._total_usage = TokenUsage()
        self._api_format = settings.api_format

        _timeout = httpx.Timeout(connect=10.0, read=self._CALL_TIMEOUT, write=30.0, pool=10.0)

        if self._api_format == "openai":
            import openai
            self._openai_client = openai.AsyncOpenAI(
                api_key=settings.anthropic_api_key,
                base_url=settings.anthropic_base_url or None,
                timeout=_timeout,
            )
        else:
            import anthropic
            client_kwargs = {"api_key": settings.anthropic_api_key, "timeout": _timeout}
            if settings.anthropic_base_url:
                client_kwargs["base_url"] = settings.anthropic_base_url
            self._anthropic_client = anthropic.AsyncAnthropic(**client_kwargs)

    @property
    def total_usage(self) -> TokenUsage:
        return self._total_usage

    def check_budget(self) -> None:
        """Check if per-task token budget is exceeded."""
        total_tokens = self._total_usage.input_tokens + self._total_usage.output_tokens
        if total_tokens >= settings.single_task_token_limit:
            raise BudgetExceededError(
                f"Per-task token limit reached: {total_tokens}/{settings.single_task_token_limit}"
            )

    async def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        timeout: float | None = None,
    ) -> LLMResponse:
        self.check_budget()
        call_timeout = timeout or self._CALL_TIMEOUT

        try:
            return await asyncio.wait_for(
                self._do_complete(system, messages, tools, max_tokens),
                timeout=call_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("llm_call_timeout", timeout=call_timeout)
            raise LLMTimeoutError(f"LLM call timed out after {call_timeout}s")

    async def _do_complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        max_tokens: int,
    ) -> LLMResponse:
        if self._api_format == "openai":
            return await self._complete_openai(system, messages, tools, max_tokens)
        else:
            return await self._complete_anthropic(system, messages, tools, max_tokens)

    async def _complete_anthropic(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        max_tokens: int,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = self._convert_tools_to_anthropic(tools)

        resp = await self._anthropic_client.messages.create(**kwargs)

        usage = TokenUsage(
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            cost_usd=_calc_cost(resp.usage.input_tokens, resp.usage.output_tokens, self._model),
        )
        self._total_usage.input_tokens += usage.input_tokens
        self._total_usage.output_tokens += usage.output_tokens
        self._total_usage.cost_usd += usage.cost_usd

        content = ""
        tool_use = None
        tool_name = ""

        for block in resp.content:
            if block.type == "text":
                content += block.text
            elif block.type == "tool_use":
                tool_use = block.input
                tool_name = block.name

        return LLMResponse(
            content=content,
            tool_use=tool_use,
            tool_name=tool_name,
            usage=usage,
            stop_reason=resp.stop_reason,
        )

    async def _complete_openai(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        max_tokens: int,
    ) -> LLMResponse:
        # Convert messages to OpenAI format
        openai_messages = [{"role": "system", "content": system}]
        for msg in messages:
            openai_messages.append(msg)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": openai_messages,
            "max_tokens": max_tokens,
        }
        if tools:
            kwargs["tools"] = self._convert_tools_to_openai(tools)

        resp = await self._openai_client.chat.completions.create(**kwargs)

        choice = resp.choices[0]
        content = choice.message.content or ""
        tool_use = None
        tool_name = ""

        # Handle tool calls
        if choice.message.tool_calls:
            tool_call = choice.message.tool_calls[0]
            tool_name = tool_call.function.name
            import json
            tool_use = json.loads(tool_call.function.arguments)

        usage = TokenUsage(
            input_tokens=resp.usage.prompt_tokens if resp.usage else 0,
            output_tokens=resp.usage.completion_tokens if resp.usage else 0,
            cost_usd=_calc_cost(
                resp.usage.prompt_tokens if resp.usage else 0,
                resp.usage.completion_tokens if resp.usage else 0,
                self._model,
            ),
        )
        self._total_usage.input_tokens += usage.input_tokens
        self._total_usage.output_tokens += usage.output_tokens
        self._total_usage.cost_usd += usage.cost_usd

        return LLMResponse(
            content=content,
            tool_use=tool_use,
            tool_name=tool_name,
            usage=usage,
            stop_reason=choice.finish_reason or "",
        )

    def _convert_tools_to_anthropic(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for tool in tools:
            result.append({
                "name": tool["name"],
                "description": tool.get("description", ""),
                "input_schema": tool.get("input_schema", tool.get("parameters", {})),
            })
        return result

    def _convert_tools_to_openai(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for tool in tools:
            result.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", tool.get("parameters", {})),
                },
            })
        return result

    async def stream(
        self,
        system: str,
        messages: list[dict[str, Any]],
        max_tokens: int = 8192,
    ):
        self.check_budget()

        if self._api_format == "openai":
            async for chunk in self._stream_openai(system, messages, max_tokens):
                yield chunk
        else:
            async for chunk in self._stream_anthropic(system, messages, max_tokens):
                yield chunk

    async def _stream_anthropic(
        self,
        system: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
    ):
        async with self._anthropic_client.messages.stream(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text

    async def _stream_openai(
        self,
        system: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
    ):
        openai_messages = [{"role": "system", "content": system}]
        for msg in messages:
            openai_messages.append(msg)

        stream = await self._openai_client.chat.completions.create(
            model=self._model,
            messages=openai_messages,
            max_tokens=max_tokens,
            stream=True,
        )
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content


def _calc_cost(input_tokens: int, output_tokens: int, model: str) -> float:
    if "opus" in model:
        return (input_tokens * 15 + output_tokens * 75) / 1_000_000
    if "sonnet" in model:
        return (input_tokens * 3 + output_tokens * 15) / 1_000_000
    if "haiku" in model:
        return (input_tokens * 0.25 + output_tokens * 1.25) / 1_000_000
    return (input_tokens * 3 + output_tokens * 15) / 1_000_000
