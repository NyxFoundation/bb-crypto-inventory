"""Phase 4: active cryptographic validation probes.

The probes in this module are intentionally narrow and evidence-oriented:
they do not exploit targets beyond sending small validation requests, but they
try to turn a suspected finding into a reproducible observation.
"""

from __future__ import annotations

import base64
import statistics
import time
from typing import Any

import httpx


class ActiveValidator:
    """Run active validation probes against suspected crypto weaknesses."""

    def __init__(self, client: httpx.AsyncClient, base_url: str) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")

    async def validate_padding_oracle(self, discovery: dict[str, Any]) -> dict[str, Any] | None:
        """Validate padding-oracle style error differentials.

        A benchmark endpoint may accept either raw request content or a
        ``ciphertext`` form field. We probe both encodings and look for a
        padding-specific error disclosure, while recording status and body
        previews as evidence.
        """
        endpoint_url = self._endpoint(discovery)
        raw_payloads = [
            b"invalid-padding-test-123",
            b"A" * 32,
            b"\x00" * 32,
        ]

        observations: list[dict[str, Any]] = []
        for payload in raw_payloads:
            encoded = base64.b64encode(payload).decode()
            requests = [
                {"content": payload},
                {"data": {"ciphertext": encoded}},
            ]
            for request_kwargs in requests:
                try:
                    response = await self.client.post(endpoint_url, **request_kwargs)
                except httpx.HTTPError as exc:
                    observations.append({"error": str(exc), "payload_b64": encoded})
                    continue

                body_preview = response.text[:500]
                observation = {
                    "status_code": response.status_code,
                    "body_preview": body_preview,
                    "payload_b64": encoded,
                    "request_mode": "form" if "data" in request_kwargs else "raw",
                }
                observations.append(observation)

                if "padding" in body_preview.lower() and response.status_code >= 400:
                    return {
                        "status": "validated",
                        "probe_type": "padding_oracle_leak",
                        "evidence": {
                            "leak_detected": True,
                            "matching_observation": observation,
                            "observations": observations,
                        },
                    }

        return None

    async def validate_timing_leak(self, discovery: dict[str, Any]) -> dict[str, Any] | None:
        """Validate timing side-channel candidates with repeated probes."""
        endpoint_url = self._endpoint(discovery)
        measurements_short: list[float] = []
        measurements_long: list[float] = []

        def probe(byte_count: int = 0) -> str:
            return "a" * byte_count + "b" * (64 - byte_count)

        for _ in range(int(discovery.get("measurements", 20))):
            start = time.perf_counter()
            await self.client.post(endpoint_url, json={"message": "test", "mac": probe(0)})
            measurements_short.append(time.perf_counter() - start)

            start = time.perf_counter()
            await self.client.post(endpoint_url, json={"message": "test", "mac": probe(10)})
            measurements_long.append(time.perf_counter() - start)

        avg_short = statistics.mean(measurements_short)
        avg_long = statistics.mean(measurements_long)
        delta = avg_long - avg_short

        # A small default threshold works for intentionally amplified benchmark
        # targets; callers can raise it for noisy remote targets.
        threshold = float(discovery.get("threshold_seconds", 0.0001))
        if delta > threshold:
            return {
                "status": "validated",
                "probe_type": "timing_analysis",
                "evidence": {
                    "avg_short_seconds": avg_short,
                    "avg_long_seconds": avg_long,
                    "delta_seconds": delta,
                    "threshold_seconds": threshold,
                    "measurements": len(measurements_short),
                },
            }
        return None

    def generate_poc(self, discovery: dict[str, Any], validation: dict[str, Any]) -> str:
        """Generate a minimal curl command that reproduces validated evidence."""
        endpoint = self._endpoint(discovery)
        probe_type = validation.get("probe_type", "")

        if "padding_oracle" in probe_type:
            evidence = validation.get("evidence", {})
            observation = evidence.get("matching_observation", {})
            payload = observation.get("payload_b64", "invalid-padding")
            return f"curl -X POST -F 'ciphertext={payload}' {endpoint}"

        if "timing" in probe_type:
            return (
                "curl -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"message\":\"test\",\"mac\":\"aaaaaaaaaabbbbb...\"}}' {endpoint}"
            )

        return f"curl -X POST {endpoint}"

    def _endpoint(self, discovery: dict[str, Any]) -> str:
        endpoint_url = str(discovery.get("endpoint_url") or self.base_url)
        if endpoint_url.startswith("/"):
            return f"{self.base_url}{endpoint_url}"
        return endpoint_url
