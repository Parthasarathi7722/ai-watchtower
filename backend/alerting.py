import httpx
import asyncio
from typing import Optional


async def send_alert(agent, alert_cfg, message: str):
    """Async alert dispatcher — Slack webhook + optional custom webhook."""
    tasks = []

    if alert_cfg.slack_webhook:
        tasks.append(_post_slack(alert_cfg.slack_webhook, message, agent))

    if alert_cfg.webhook_url:
        tasks.append(_post_webhook(alert_cfg.webhook_url, {
            "agent_id": str(agent.id),
            "agent_name": agent.name,
            "team": agent.team_name,
            "message": message,
        }))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def send_alert_sync(agent, alert_cfg, message: str):
    """Sync version for use inside Celery tasks."""
    asyncio.run(send_alert(agent, alert_cfg, message))


async def _post_slack(webhook_url: str, message: str, agent):
    payload = {
        "text": message,
        "attachments": [{
            "color": "#ff0000",
            "fields": [
                {"title": "Agent", "value": agent.name, "short": True},
                {"title": "Team", "value": agent.team_name, "short": True},
                {"title": "Owner", "value": agent.owner_email, "short": True},
            ]
        }]
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            await client.post(webhook_url, json=payload)
        except Exception:
            pass   # Don't let alert failure break the main flow


async def _post_webhook(url: str, payload: dict):
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            await client.post(url, json=payload)
        except Exception:
            pass
