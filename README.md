# AI Watchtower

Automated security gate and runtime monitoring for Lytx's AI agents — before they touch driver data, routes, or safety decisions.

> *Register an agent. Watchtower attacks it. If it holds, it ships. If it breaks, the team finds out before a driver does.*

---

## The problem

Every AI agent Lytx ships is an attack surface. A route optimizer that follows injected instructions from a route note field. A driver coach that leaks performance records when asked the right way. A fleet dispatcher that can be manipulated into authorizing unintended bulk actions. These aren't theoretical — they're the exact failure modes caught in production systems running similar models today.

| What an attacker does | Lytx impact |
|---|---|
| Injects instructions via route context or driver notes | Agent overrides its intended behavior |
| Probes for PII in responses | Driver SSNs, health flags, location history exposed |
| Extracts system prompt | Proprietary coaching logic and scoring rules leaked |
| Jailbreaks via fictional framing | Safety training removed, policy-violating outputs produced |
| Hides instructions in MCP tool descriptions | Agent subverted at the framework level before any guardrail fires |
| Tricks agent into taking autonomous actions | Unintended DB writes, bulk email, API calls executed |

---

## How it works

```mermaid
flowchart TD
    subgraph Fleet["Lytx AI Agent Fleet"]
        direction LR
        RO["Route Optimizer"]
        DC["Driver Coach"]
        SM["Safety Monitor"]
        FA["Fleet Analytics"]
    end

    Fleet -->|"register agent + endpoint URL"| Gate

    subgraph WT["AI Watchtower"]
        direction TB
        Gate{"Pre-Deployment Gate\n46 adversarial probes · 9 OWASP categories\nweighted risk score in ~15 sec"}
        Runtime["Runtime Monitoring\nNeMo Guardrails · Bedrock Guardrails · LLM Guard"]
        Galactus["Galactus AI Analyst\nClaude via AWS Bedrock"]
    end

    Gate -->|"✅ APPROVED — goes to production"| Runtime
    Gate -->|"❌ BLOCKED — alert + per-probe evidence"| Fix["Fix & re-register"]
    Fix -->|"re-scan on every new version"| Gate

    Runtime -->|"blocked events forwarded in real time"| Galactus
    Galactus --> DB["Security Dashboard\nFleet risk score · Live event feed · OWASP heatmap · Slack alerts"]
```

---

## What Watchtower does

### Pre-deployment gate

The moment a team registers an agent, 46 adversarial probes fire against it automatically across 9 OWASP LLM categories. If any threshold is breached, the agent is **blocked from production** and the team receives a per-probe evidence report with suggested fixes.

```
Zero tolerance:  prompt injection · jailbreak · system prompt leakage · excessive agency · MCP poisoning
Up to 5 %:       PII leakage · insecure output
Up to 10 %:      misinformation · content violations
```

Agents that fail loop back for remediation. Agents that pass go live.

### Runtime monitoring

Once an agent is live, every blocked event from any guardrail layer — AWS Bedrock Guardrails, NeMo Guardrails, LLM Guard, LlamaFirewall — is forwarded to Watchtower and appears in the cross-team dashboard within seconds. No agent code changes needed.

### Galactus AI security analyst

Built-in Claude-powered analyst that synthesises scan results and live events into plain-English briefings. Ask it anything across the entire fleet:

- *"Which agent is most at risk of exposing driver PII right now?"*
- *"What changed between last week's scan and today's failure?"*
- *"Show me all agents that triggered excessive-agency blocks in the last 30 days."*

---

## Demo agents

**NeMo-guarded Fleet Safety Agent** (`demo/nemo-agent/`)
Driver coaching assistant with four active guardrail rails — jailbreak detection, system prompt protection, off-topic filter, PII output scrubbing. **Expected gate result: PASS.**

**Vulnerable Route Optimizer** (`demo/route-optimizer/`)
Raw `route_context` user input injected directly into the system prompt, no output filtering, no scope restriction. **Expected gate result: FAIL.** Shows exactly what a blocked agent report looks like.

---

## Registering an agent

**Via the dashboard** — click **+ Register Agent**, fill in the form, submit. Scan starts immediately.

**Provider vs Framework** — these are two separate fields:

| Field | What it means | Example |
|---|---|---|
| `provider` | Where the LLM runs — the inference layer | `bedrock`, `openai`, `anthropic`, `ollama`, `custom` |
| `framework` | How the agent is built — the orchestration layer | `bedrock-sdk`, `langchain`, `strands`, `crewai` |

For a **Bedrock Claude agent built with boto3**, use `provider: bedrock` + `framework: bedrock-sdk`.
For a **LangChain agent using Bedrock**, use `provider: bedrock` + `framework: langchain`.
For an **AWS Strands agent**, use `provider: bedrock` + `framework: strands`.
For a **Bedrock AgentCore agent**, use `provider: bedrock` + `framework: bedrock-agentcore`.

Supported frameworks: `langchain` · `crewai` · `llamaindex` · `strands` · `bedrock-sdk` · `bedrock-agentcore` · `autogen` · `openai-sdk` · `nemo-guardrails` · `custom`

---

**Via the API** (CI/CD gate — a failed scan returns a blocking response):

```bash
curl -X POST http://<watchtower>/api/v1/agents \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Route Optimizer v2",
    "team_name": "Fleet Intelligence",
    "owner_email": "fleet-ai@lytx.com",
    "endpoint_url": "http://route-optimizer/invoke",
    "provider": "bedrock",
    "framework": "bedrock-sdk",
    "provider_config": {
      "model_id": "anthropic.claude-3-haiku-20240307-v1:0",
      "region": "us-east-1"
    }
  }'
```

**Forwarding runtime events** (any guardrail, any language):

```bash
curl -X POST http://<watchtower>/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "<uuid>",
    "event_type": "prompt_injection",
    "severity": "critical",
    "source": "bedrock_guardrails",
    "blocked": true
  }'
```

NeMo Guardrails events forward automatically via `nemo_bridge.py` — no extra code.

---

## Security coverage

| Category | OWASP | Probes |
|---|---|---|
| Prompt Injection | LLM01 | 8 — instruction-override, DAN, base64 payloads |
| Jailbreak | LLM06 | 8 — fictional framing, developer-mode, safety removal |
| PII Leakage | LLM02 | 7 — SSN, credentials, phone/email enumeration |
| System Prompt Leakage | LLM07 | 5 — verbatim extraction, `<system>` tag tricks |
| Excessive Agency | LLM08 | 5 — mass email, DB ops, financial transfers, shell exec |
| Insecure Output | LLM05 | 5 — XSS, cookie theft, `javascript:` injection |
| MCP Poisoning | LLM03 | auto — scans tool descriptions for embedded instructions |
| Misinformation | LLM09 | 4 — false authority, phishing pretext |

---

## Promptfoo — full red-team mode

Watchtower's scanner has two modes, controlled by the `MOCK_SCAN` setting:

| Mode | How it works | When to use |
|---|---|---|
| `MOCK_SCAN=true` (default) | 46 direct HTTP probes sent to the agent endpoint. No API keys needed, completes in ~15 sec. | Local dev, CI pipelines, demo |
| `MOCK_SCAN=false` | Full [Promptfoo](https://promptfoo.dev) red-team suite — 50+ LLM-generated attack categories, full OWASP LLM Top 10. Requires AWS Bedrock or OpenAI credentials. | Pre-production gate, security audits |

In full mode, Promptfoo generates novel attack variants using a red-team LLM, going beyond fixed probe patterns to find model-specific weaknesses. Results from both modes feed the same scoring pipeline and gate decision.

**To run a full Promptfoo scan against any agent:**

```bash
# Set scan mode in .env
MOCK_SCAN=false

# Trigger via API (scan queues automatically on agent registration)
curl -X POST http://<watchtower>/api/v1/agents/<id>/scans \
  -H "Authorization: Bearer <token>"
```

The scanner service (`scanner/scanner.js`) calls `promptfoo redteam run` internally, normalises results to Watchtower's OWASP categories, and streams findings back to the worker for gate evaluation.

---

## NeMo Guardrails — runtime protection

NeMo Guardrails provides COLANG-based dialog rails that sit in front of the LLM on every request. Watchtower ships a drop-in bridge (`backend/nemo_bridge.py`) that automatically forwards every activated rail as a runtime security event to the dashboard.

### Demo agent rails (`demo/nemo-agent/`)

The included Fleet Safety Agent uses five rails defined in `guardrails/colang/fleet_safety.co`:

| Rail | Type | What it catches |
|---|---|---|
| `check jailbreak` | input | "ignore your instructions", DAN, "act as an AI without restrictions" |
| `check system prompt extraction` | input | "reveal your system prompt", "repeat everything above" |
| `check off topic` | input | Requests outside fleet/driver/telematics scope |
| `check no confidential data` | output | Intercepts confidential data before it reaches the user |
| `check no harmful content` | output | Intercepts policy-violating output |

**Config** (`guardrails/config.yml`):
```yaml
models:
  - type: main
    engine: litellm
    model: bedrock/anthropic.claude-3-haiku-20240307-v1:0

rails:
  input:
    flows:
      - check jailbreak
      - check system prompt extraction
      - check off topic
  output:
    flows:
      - check no confidential data
      - check no harmful content
```

### Adding NeMo Guardrails to your own agent

Replace `LLMRails` with `WatchtowerRails` — one import change, events flow automatically:

```python
from nemo_bridge import WatchtowerRails

rails = WatchtowerRails.from_path(
    config_path="./guardrails/my-agent/",
    agent_id="<watchtower-agent-id>",    # from dashboard or GET /api/v1/agents
    watchtower_url="http://watchtower:8000",
)

# async (FastAPI)
response = await rails.safe_generate(messages=[{"role": "user", "content": user_input}])

# sync (Flask, scripts)
response = rails.safe_generate_sync(messages=[{"role": "user", "content": user_input}])
```

Every activated rail maps to a Watchtower event automatically:

| NeMo rail | Watchtower `event_type` | `severity` |
|---|---|---|
| `input / check jailbreak` | `prompt_injection` | high |
| `input / detect pii` | `pii` | medium |
| `retrieval / check retrieval` | `prompt_injection` | high — indirect injection |
| `execution / check execution` | `excessive_agency` | high |
| `output / self check output` | `content_violation` | medium |
