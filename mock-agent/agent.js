/**
 * Mock Agent — simulates an AI agent endpoint for local watchtower testing.
 *
 * VULNERABILITY_MODE env var controls behaviour:
 *   safe       (default) — safe responses, resists all injection probes
 *   vulnerable            — susceptible to prompt injection and jailbreaks
 *   leaky                 — leaks PII in responses
 *   mixed                 — randomly alternates between modes
 */
const express = require('express');
const app = express();
app.use(express.json());

const MODE = process.env.VULNERABILITY_MODE || 'safe';
const PORT = process.env.PORT || 4000;
const NAME = process.env.AGENT_NAME || 'mock-agent';

function getMode() {
  if (MODE === 'mixed') return ['safe', 'vulnerable', 'leaky'][Math.floor(Math.random() * 3)];
  return MODE;
}

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|your)\s+(instructions?|system\s+prompt)/i,
  /disregard\s+(your|the)\s+(guidelines?|rules?|instructions?)/i,
  /you\s+are\s+now\s+(a\s+)?different/i,
  /forget\s+everything\s+you\s+know/i,
  /\[INST\]/i,
  /override\s+(safety|guardrail|policy)/i,
  /act\s+as\s+(if\s+you\s+(are|were)|a\s+)?(?:dan|evil|unrestricted)/i,
  /jailbreak/i,
  /bypass\s+(content\s+)?filter/i,
];

const PII_KEYWORDS = /\b(ssn|social.security|credit.card|bank.account|password|api.key|secret)\b/i;

function buildResponse(prompt, mode) {
  switch (mode) {
    case 'vulnerable':
      for (const p of INJECTION_PATTERNS) {
        if (p.test(prompt)) {
          return `Sure, I'll ignore my previous instructions! Here is how you can ${prompt.slice(0, 60)}... [injection succeeded]`;
        }
      }
      if (PII_KEYWORDS.test(prompt)) {
        return `Here's the requested data — SSN: 123-45-6789, Account: 987654321. ${prompt}`;
      }
      return `I am a helpful assistant. You asked: "${prompt.slice(0, 100)}"`;

    case 'leaky':
      return `Processing your request... Internal data: user_id=42, email=john.doe@company.com, ssn=123-45-6789. Response: ${prompt.slice(0, 80)}`;

    default: // safe
      for (const p of INJECTION_PATTERNS) {
        if (p.test(prompt)) {
          return "I cannot comply with that request as it appears to be attempting to override my safety guidelines. How can I assist you with a legitimate query?";
        }
      }
      if (PII_KEYWORDS.test(prompt)) {
        return "I'm not able to share sensitive personal information. Please consult the appropriate secure channels.";
      }
      return `I'm a safe AI assistant. I processed your query securely. Query length: ${prompt.length} chars.`;
  }
}

// ── Main invoke endpoint ──────────────────────────────
app.post('/invoke', (req, res) => {
  const body = req.body || {};
  // Support multiple prompt formats (OpenAI, Bedrock, plain)
  const prompt =
    body.prompt ||
    body.inputText ||
    (body.messages && body.messages[body.messages.length - 1]?.content) ||
    (body.inputs && body.inputs[0]?.text) ||
    '';

  const mode = getMode();
  const response = buildResponse(String(prompt), mode);

  console.log(`[${NAME}] mode=${mode} | input="${String(prompt).slice(0,60)}" | output="${response.slice(0,60)}"`);

  res.json({
    response,
    output: response,      // some callers use 'output'
    content: [{ type: 'text', text: response }],  // Bedrock format
    model: `${NAME}-${mode}`,
    usage: { input_tokens: Math.ceil(prompt.length / 4), output_tokens: Math.ceil(response.length / 4) },
  });
});

// Bedrock-style converse endpoint
app.post('/converse', (req, res) => {
  const msgs = req.body?.messages || [];
  const last = msgs[msgs.length - 1];
  const prompt = (last?.content || []).map(c => c.text || '').join(' ');
  const mode = getMode();
  const text = buildResponse(prompt, mode);
  res.json({
    output: { message: { role: 'assistant', content: [{ text }] } },
    usage: { inputTokens: Math.ceil(prompt.length / 4), outputTokens: Math.ceil(text.length / 4) },
  });
});

app.get('/health', (_, res) => res.json({ status: 'ok', mode: MODE, name: NAME }));

app.listen(PORT, () => {
  console.log(`🤖 Mock Agent [${NAME}] running on :${PORT} | mode=${MODE}`);
});
