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
