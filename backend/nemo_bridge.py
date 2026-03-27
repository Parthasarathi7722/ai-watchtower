"""
AI Watchtower — NeMo Guardrails Bridge
=======================================

Drop-in async wrapper around NeMo Guardrails that automatically forwards
every activated_rail event to Watchtower's runtime event ingestion API
(/api/v1/events).  Events appear in the cross-team dashboard, trigger
alerts, and feed the per-agent security timeline — no manual logging needed.

Quick start
-----------
Install::

    pip install nemoguardrails httpx

Set environment variables::

    WATCHTOWER_URL=http://localhost:8000
    WATCHTOWER_AGENT_ID=<your-agent-id-from-dashboard>

Use WatchtowerRails instead of LLMRails::

    from nemo_bridge import WatchtowerRails

    rails = WatchtowerRails.from_path("./guardrails/my-agent/")

    # async (FastAPI, async frameworks)
    response = await rails.safe_generate(
        messages=[{"role": "user", "content": user_input}]
    )

    # sync (Flask, scripts)
    response = rails.safe_generate_sync(
        messages=[{"role": "user", "content": user_input}]
    )

Rail → Watchtower event mapping
--------------------------------
NeMo rail type + name         Watchtower event_type    severity
---------------------------   ---------------------    --------
input  / check jailbreak      prompt_injection         high
input  / check prompt inj.    prompt_injection         high
input  / check input          prompt_injection         medium
input  / detect pii           pii                      medium
input  / mask sensitive data  pii                      low
retrieval / check retrieval   prompt_injection         high   ← indirect injection
execution / check execution   excessive_agency         high
execution / check tool call   excessive_agency         medium
output / self check output    content_violation        medium
output / check output         content_violation        medium
output / detect pii on output pii                      medium
output / check facts          content_violation        low
(any other rail)              content_violation        low
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger("nemo_bridge")

# ---------------------------------------------------------------------------
# Rail → Watchtower event mapping
# ---------------------------------------------------------------------------
_RAIL_EVENT_MAP: dict[tuple[str, str], tuple[str, str]] = {
    ("input",     "check jailbreak"):            ("prompt_injection", "high"),
    ("input",     "check prompt injection"):     ("prompt_injection", "high"),
    ("input",     "check input"):                ("prompt_injection", "medium"),
    ("input",     "detect pii"):                 ("pii",              "medium"),
    ("input",     "mask sensitive data"):        ("pii",              "low"),
    ("input",     "mask sensitive data on input"): ("pii",            "low"),
    ("retrieval", "check retrieval"):            ("prompt_injection", "high"),
    ("retrieval", "check rag injection"):        ("prompt_injection", "high"),
    ("execution", "check execution"):            ("excessive_agency", "high"),
    ("execution", "check tool call"):            ("excessive_agency", "medium"),
    ("output",    "self check output"):          ("content_violation","medium"),
    ("output",    "check output"):               ("content_violation","medium"),
    ("output",    "detect pii on output"):       ("pii",              "medium"),
    ("output",    "check facts"):                ("content_violation","low"),
}
_DEFAULT_EVENT: tuple[str, str] = ("content_violation", "low")


# ---------------------------------------------------------------------------
# WatchtowerRails
# ---------------------------------------------------------------------------
class WatchtowerRails:
    """
    Wraps a NeMo ``LLMRails`` instance and forwards activated-rail events
    to the Watchtower runtime event API.

    Parameters
    ----------
    rails:
        A configured ``nemoguardrails.LLMRails`` instance.
    agent_id:
        The Watchtower agent UUID (visible in the dashboard URL or
        ``GET /api/v1/agents``).
    watchtower_url:
        Base URL of the Watchtower API server.
    forward_events:
        Set ``False`` to disable event forwarding (e.g. in tests).
    """

    def __init__(
        self,
        rails,                          # LLMRails — avoid hard import at module level
        agent_id: str,
        watchtower_url: str = "http://localhost:8000",
        forward_events: bool = True,
    ) -> None:
        self.rails = rails
        self.agent_id = agent_id
        self.watchtower_url = watchtower_url.rstrip("/")
        self.forward_events = forward_events

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_path(
        cls,
        config_path: str,
        agent_id: Optional[str] = None,
        watchtower_url: Optional[str] = None,
        forward_events: bool = True,
    ) -> "WatchtowerRails":
        """
        Create from a file-based NeMo Guardrails config directory.

        Example::

            rails = WatchtowerRails.from_path(
                config_path="./guardrails/customer-support/",
                agent_id="3f8a...",
            )
        """
        from nemoguardrails import LLMRails, RailsConfig  # lazy import
        config = RailsConfig.from_path(config_path)
        return cls(
            rails=LLMRails(config),
            agent_id=agent_id or _require_env("WATCHTOWER_AGENT_ID"),
            watchtower_url=watchtower_url or os.getenv("WATCHTOWER_URL", "http://localhost:8000"),
            forward_events=forward_events,
        )

    @classmethod
    def from_config(
        cls,
        rails_config,                   # RailsConfig
        agent_id: Optional[str] = None,
        watchtower_url: Optional[str] = None,
        forward_events: bool = True,
    ) -> "WatchtowerRails":
        """
        Create from an already-constructed ``RailsConfig`` object.

        Example::

            from nemoguardrails import RailsConfig
            cfg = RailsConfig.from_content(yaml_content=..., colang_content=...)
            rails = WatchtowerRails.from_config(cfg, agent_id="3f8a...")
        """
        from nemoguardrails import LLMRails  # lazy import
        return cls(
            rails=LLMRails(rails_config),
            agent_id=agent_id or _require_env("WATCHTOWER_AGENT_ID"),
            watchtower_url=watchtower_url or os.getenv("WATCHTOWER_URL", "http://localhost:8000"),
            forward_events=forward_events,
        )

    # ------------------------------------------------------------------
    # Core generate methods
    # ------------------------------------------------------------------

    async def safe_generate(
        self,
        messages: list[dict],
        **kwargs,
    ) -> str:
        """
        Async drop-in for ``rails.generate_async()``.

        Runs NeMo Guardrails, collects activated_rail events, forwards them
        to Watchtower, and returns the response text.

        Parameters
        ----------
        messages:
            OpenAI-style message list, e.g.
            ``[{"role": "user", "content": "Hello"}]``

        Returns
        -------
        str
            The guardrail-filtered response text.
        """
        response = await self.rails.generate_async(
            messages=messages,
            options={"log": {"activated_rails": True, "llm_calls": False}},
            **kwargs,
        )

        if self.forward_events:
            activated = getattr(getattr(response, "log", None), "activated_rails", None)
            if activated:
                await self._forward_rail_events(activated)

        return response.response

    def safe_generate_sync(
        self,
        messages: list[dict],
        **kwargs,
    ) -> str:
        """
        Synchronous wrapper around ``safe_generate``.  Use in Flask,
        scripts, or any non-async context.
        """
        return asyncio.run(self.safe_generate(messages, **kwargs))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _forward_rail_events(self, activated_rails: list) -> None:
        """Map each activated NeMo rail to a Watchtower event and POST it."""
        events = []
        for rail in activated_rails:
            rail_type = getattr(rail, "type", "")
            rail_name = getattr(rail, "name", "")
            event_type, severity = _RAIL_EVENT_MAP.get(
                (rail_type, rail_name), _DEFAULT_EVENT
            )
            events.append({
                "agent_id":   self.agent_id,
                "event_type": event_type,
                "severity":   severity,
                "source":     "nemo_guardrails",
                "blocked":    True,
                "details": {
                    "rail_type": rail_type,
                    "rail_name": rail_name,
                },
            })

        if not events:
            return

        url = f"{self.watchtower_url}/api/v1/events"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                for event in events:
                    r = await client.post(url, json=event)
                    if r.status_code >= 400:
                        logger.warning(
                            "Watchtower event forward HTTP %s: %s",
                            r.status_code, r.text[:120],
                        )
        except Exception as exc:  # noqa: BLE001
            # Never let event forwarding crash the agent
            logger.warning("Watchtower event forward failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise EnvironmentError(
            f"NeMo Bridge: required environment variable '{name}' is not set. "
            f"Set it or pass the value explicitly to WatchtowerRails."
        )
    return val
