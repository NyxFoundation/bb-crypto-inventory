"""Tests for Phase 4 active validation probes."""

from __future__ import annotations

import httpx
import pytest

from bbci.phase04 import ActiveValidator


@pytest.mark.asyncio
async def test_validate_padding_oracle_detects_error_disclosure() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if b"ciphertext=" in request.content:
            return httpx.Response(400, text="Padding error: invalid padding byte")
        return httpx.Response(500, text="generic failure")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        validator = ActiveValidator(client, "https://example.test")
        result = await validator.validate_padding_oracle({"endpoint_url": "/api/decrypt"})

    assert result is not None
    assert result["status"] == "validated"
    assert result["probe_type"] == "padding_oracle_leak"
    assert result["evidence"]["leak_detected"] is True


@pytest.mark.asyncio
async def test_validate_timing_leak_detects_amplified_delay() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if "aaaaaaaaaa" in body:
            await sleep_for_signal()
        return httpx.Response(401, json={"status": "invalid"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        validator = ActiveValidator(client, "https://example.test")
        result = await validator.validate_timing_leak(
            {
                "endpoint_url": "https://example.test/api/verify",
                "measurements": 3,
                "threshold_seconds": 0.00001,
            }
        )

    assert result is not None
    assert result["status"] == "validated"
    assert result["probe_type"] == "timing_analysis"
    assert result["evidence"]["delta_seconds"] > 0


async def sleep_for_signal() -> None:
    import asyncio

    await asyncio.sleep(0.001)
