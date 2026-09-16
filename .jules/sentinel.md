## 2026-09-16 - Secret Redactor Pattern Gap for Hyphenated/Underscored API Keys
**Vulnerability:** Anthropic (`sk-ant-api03-...`), OpenAI project/service (`sk-proj-...`, `sk-svcacct-...`), Groq (`gsk_...`), and Tavily (`tvly-...`) API keys were not being redacted from tool output before hitting logs or LLM context.
**Learning:** The previous regex pattern `\bsk-[A-Za-z0-9]{10,}` strictly matched alphanumeric characters following `sk-`, failing when hyphens or underscores were embedded in the key format.
**Prevention:** Always use character classes like `[A-Za-z0-9\-_]` or explicit vendor prefix patterns when redacting modern LLM provider API keys.
