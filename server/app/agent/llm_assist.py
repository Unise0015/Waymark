from __future__ import annotations

import os
import logging
from typing import Any

logger = logging.getLogger(__name__)

VAPT_SYSTEM_PROMPT = (
    "You are a strict VAPT guide. You MUST output EXACTLY the requested Markdown "
    "template. DO NOT include internal thoughts, self-corrections, or conversational filler."
)


class LLMAssist:
    """
    Optional LLM reasoning layer that enhances the heuristic agent decisions.

    Supports 4 providers (auto-detected by priority):
    1. Google Gemini (GEMINI_API_KEY)
    2. OpenAI-compatible API (OPENAI_API_KEY) — works with Groq, OpenRouter, etc.
    3. Anthropic Claude (ANTHROPIC_API_KEY)
    4. Ollama (local, free) — default if available on localhost:11434

    When NO LLM is configured, the agent works identically on pure heuristics.
    The LLM only REFINES decisions — it never replaces the heuristic logic.
    """

    def __init__(self):
        self.provider = self._detect_provider()
        self.base_url = os.environ.get("LLM_BASE_URL", "http://localhost:11434")
        self.model_name = os.environ.get("LLM_MODEL", "llama3")
        self.api_key = os.environ.get("LLM_API_KEY", "")

    def _detect_provider(self) -> str | None:
        """Auto-detect which LLM provider is available."""
        # Priority: Gemini > OpenAI-compat > Anthropic > Ollama (free)
        if os.environ.get("GEMINI_API_KEY"):
            return "gemini"
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.environ.get("OLLAMA_HOST") or self._check_ollama():
            return "ollama"
        return None

    @staticmethod
    def _check_ollama() -> bool:
        try:
            import socket
            s = socket.create_connection(("localhost", 11434), timeout=1)
            s.close()
            return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            return False

    def has_llm(self) -> bool:
        """Check if any LLM is configured and available."""
        return self.provider is not None

    async def refine_ranking(
        self,
        heuristic_ranking: list[dict[str, Any]],
        context: str,
    ) -> str | None:
        """Send the heuristic target ranking to the LLM for detailed analysis."""
        if not self.has_llm():
            return None

        ranking_text = "\n".join(
            f"  {i+1}. {t.get('fqdn', 'unknown')} "
            f"(ROI: {t.get('roi_score', 0)}, status: {t.get('status_code', '?')}, "
            f"tech: {', '.join(t.get('technologies', [])[:5])})"
            for i, t in enumerate(heuristic_ranking[:10])
        )

        prompt = (
            "You are a senior bug bounty mentor reviewing recon results for a student.\n"
            f"Context: {context}\n\n"
            f"Discovered targets:\n{ranking_text}\n\n"
            "Give a detailed analysis in 5-8 sentences:\n"
            "1. Which target(s) look MOST promising for bug bounty and WHY specifically\n"
            "2. What technologies were detected and what vulnerabilities they're commonly associated with\n"
            "3. Point out any patterns a beginner would miss (e.g. 'staging' means pre-production, "
            "'api' suggests REST endpoints, 'admin' suggests login panels)\n"
            "4. Rank the top 3 targets and explain what to test on each one\n"
            "5. Suggest specific next steps (e.g. 'Try nuclei on target X for known CVEs', "
            "'Use ffuf on target Y to find hidden admin pages')\n"
            "Be practical, educational, and encouraging. Use real-world examples."
        )

        try:
            return await self._call_llm(prompt)
        except Exception as e:
            logger.warning(f"LLM refinement failed ({self.provider}): {e}")
            return None

    async def explain_decision(
        self,
        observation: str,
        reasoning: str,
        action: str,
    ) -> str | None:
        """Ask the LLM to expand reasoning into a beginner-friendly explanation."""
        if not self.has_llm():
            return None

        prompt = (
            "You are a cybersecurity mentor explaining a recon tool's action to a beginner.\n\n"
            f"What happened: {observation}\n"
            f"Technical reasoning: {reasoning}\n"
            f"Action taken: {action}\n\n"
            "Explain this in 4-6 sentences that a beginner bug bounty hunter would understand:\n"
            "- What just happened in simple terms?\n"
            "- WHY is this step important in the recon process?\n"
            "- What can the user learn from the results?\n"
            "- What should they look for or do next?\n"
            "- Include a practical tip or real-world analogy\n"
            "Be educational, practical, and specific. Don't be generic."
        )

        try:
            return await self._call_llm(prompt)
        except Exception as e:
            logger.warning(f"LLM explanation failed: {e}")
            return None

    async def analyze_tool_results(
        self,
        tool_name: str,
        target_domain: str,
        result_count: int,
        sample_results: list[str],
    ) -> str | None:
        """Ask the LLM to analyze specific tool results and provide insights."""
        if not self.has_llm():
            return None

        samples = "\n".join(f"  - {r}" for r in sample_results[:15])
        
        tool_context = {
            "subfinder": "subdomain discovery (finding all subdomains of the target)",
            "httpx": "HTTP probing (checking which subdomains have live web servers)",
            "nuclei": "vulnerability scanning (finding security issues using templates)",
            "naabu": "port scanning (finding open network ports and services)",
            "dnsx": "DNS resolution (mapping domain names to IP addresses)",
            "katana": "web crawling (discovering pages, endpoints, and JavaScript files)",
            "ffuf": "directory fuzzing (finding hidden files and admin panels)",
            "gau": "URL mining (fetching historical URLs from Wayback Machine and Common Crawl)",
            "paramspider": "parameter discovery (finding URLs with query parameters from web archives)",
        }

        prompt = (
            f"You are a bug bounty mentor analyzing {tool_name} results.\n\n"
            f"Target: {target_domain}\n"
            f"Tool: {tool_name} ({tool_context.get(tool_name, 'reconnaissance tool')})\n"
            f"Results found: {result_count}\n"
            f"Sample discoveries:\n{samples}\n\n"
            "Analyze these specific results and output a JSON object with exactly three keys:\n"
            '1. "reasoning": 2-3 sentences explaining technically what these specific results mean for the attack surface.\n'
            '2. "education": 2-3 sentences teaching the user what security implications to look for in these specific results, acting as a mentor.\n'
            '3. "next_steps": 1-2 sentences recommending specific follow-up tools (like Nuclei, Katana, FFUF, Naabu) or manual testing the user should do next based on these findings.\n'
            "Respond ONLY with valid JSON. Do not include markdown blocks or other text."
        )

        try:
            response = await self._call_llm(prompt)
            if not response: return None
            
            # Clean potential markdown JSON wrapping
            response = response.strip()
            if response.startswith("```json"): response = response[7:]
            if response.startswith("```"): response = response[3:]
            if response.endswith("```"): response = response[:-3]
            
            import json
            data = json.loads(response.strip())
            return {
                "reasoning": data.get("reasoning", "Analyzed tool results with AI."),
                "education": data.get("education", response),
                "next_steps": data.get("next_steps", "")
            }
        except Exception as e:
            logger.warning(f"LLM analysis failed for {tool_name}: {e}")
            return None


    async def analyze_http_traffic(
        self,
        method: str,
        url: str,
        request_headers: str,
        request_body: str,
        response_status: str,
        response_headers: str,
        response_body: str
    ) -> str | None:
        if not self.has_llm():
            return "No AI provider configured. Please connect an LLM to use AI Analysis."

        # Truncate large bodies
        res_body = (response_body[:2000] + '... [TRUNCATED]') if response_body and len(response_body) > 2000 else response_body

        prompt = (
            "You are an expert VAPT (Vulnerability Assessment and Penetration Testing) guide.\n"
            "Analyze the following HTTP Request and Response.\n\n"
            f"### REQUEST\n```http\n{method} {url}\n{request_headers}\n\n{request_body}\n```\n\n"
            f"### RESPONSE\n```http\nStatus: {response_status}\n{response_headers}\n\n{res_body}\n```\n\n"
            "OUTPUT INSTRUCTIONS:\n"
            "You MUST output YOUR ANALYSIS EXACTLY in the following strict Markdown format. "
            "DO NOT include any internal thoughts, self-corrections, or conversational filler. "
            "DO NOT wrap the whole response in a code block.\n\n"
            "### 1. Overview\n"
            "[Brief 2-sentence description of the endpoint's purpose]\n\n"
            "### 2. Response Analysis\n"
            "- **Data Exposures**: [Note any PII or internal flags]\n"
            "- **Interesting Headers**: [Note CORS, Server, etc.]\n"
            "- **Reflections/Anomalies**: [Note injected inputs, weird values]\n\n"
            "### 3. Vulnerabilities Found\n"
            "- **[Vulnerability Name]** (`[Severity]`): [1-sentence description of why it's vulnerable]\n"
            "*(List as many as applicable, Severities: Informational, Low, Medium, High, Critical)*\n\n"
            "### 4. VAPT Attack Guide\n"
            "#### [Attack Vector 1 (e.g., IDOR, Mass Assignment)]\n"
            "- **Test**: [What to do]\n"
            "- **Payload**: `[Payload to use]`\n"
            "#### [Attack Vector 2]\n"
            "- **Test**: [What to do]\n"
            "- **Payload**: `[Payload to use]`"
        )

        try:
            return await self._call_llm(prompt)
        except Exception as e:
            import logging
            logging.warning(f"LLM traffic analysis failed: {e}")
            return f"Analysis failed: {str(e)}"

    async def analyze_request_chain(self, chain_name: str, hypothesis: str, steps: list[dict]) -> str:
        """
        Analyze a chain of HTTP requests as a connected attack flow.
        Each step dict has: step_order, note, method, url, request_headers, request_body,
        response_status, response_headers, response_body
        """
        steps_text = ""
        
        def filter_headers(headers_dict):
            if not isinstance(headers_dict, dict):
                return headers_dict
            boring = {'user-agent', 'accept', 'accept-encoding', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'connection', 'keep-alive'}
            return {k: v for k, v in headers_dict.items() if k.lower() not in boring}

        for step in steps:
            steps_text += f"\n{'='*60}\n"
            steps_text += f"STEP {step['step_order']} of {len(steps)}\n"
            if step.get('note'):
                steps_text += f"TESTER'S NOTE: \"{step['note']}\"\n"
            steps_text += f"{step.get('method', 'GET')} {step.get('url', '')}\n"
            if step.get('request_headers'):
                steps_text += f"Request Headers:\n{filter_headers(step['request_headers'])}\n"
            if step.get('request_body'):
                body = step['request_body'][:800]
                if len(step['request_body']) > 800: body += "\n[TRUNCATED]"
                steps_text += f"Request Body:\n{body}\n"
            steps_text += f"Response Status: {step.get('response_status', 'N/A')}\n"
            if step.get('response_headers'):
                steps_text += f"Response Headers:\n{filter_headers(step['response_headers'])}\n"
            if step.get('response_body'):
                body = step['response_body'][:800]
                if len(step['response_body']) > 800: body += "\n[TRUNCATED]"
                steps_text += f"Response Body:\n{body}\n"
        
        prompt = f"""You are an expert penetration tester analyzing a CHAIN of HTTP requests that may form a vulnerability chain. Analyze them as a connected attack flow, NOT as individual requests.

CHAIN NAME: {chain_name}
TESTER'S HYPOTHESIS: {hypothesis or 'Not specified'}

{steps_text}

{'='*60}

Provide your analysis in this EXACT format:

**VERDICT:** [CONFIRMED VULNERABILITY / PARTIAL VULNERABILITY / FAILED ATTEMPT / INCONCLUSIVE]
**SEVERITY:** [CRITICAL / HIGH / MEDIUM / LOW / INFO]
**CLASSIFICATION:** [OWASP Top 10 category and CWE IDs]

**Chain Summary:**
[2-3 sentence summary of what the attack chain attempts]

**Step-by-Step Breakdown:**
[For each step, explain what happened, what was discovered, and how it connects to the next step]

**Vulnerability Analysis:**
[Detailed technical analysis of the vulnerability chain. What makes it exploitable? What's the impact?]

**Evidence:**
[Key evidence from the request/response data that proves or disproves the vulnerability]

**Recommended Next Steps:**
[What should the tester try next to confirm, expand, or report this finding?]

**Report-Ready Finding:**
Title: [Concise vulnerability title]
Severity: [severity]
Description: [Professional description suitable for a bug bounty report]
Steps to Reproduce:
[Numbered steps]
Impact: [Business impact statement]
"""
        return await self._call_llm(prompt)

    async def _call_llm(self, prompt: str) -> str:
        """Route the prompt to the detected LLM provider."""
        if self.provider == "ollama":
            return await self._call_ollama(prompt)
        elif self.provider == "openai":
            return await self._call_openai(prompt)
        elif self.provider == "anthropic":
            return await self._call_anthropic(prompt)
        elif self.provider == "gemini":
            return await self._call_gemini(prompt)
        raise ValueError(f"Unknown LLM provider: {self.provider}")

    async def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama instance (free, no API key needed)."""
        import aiohttp
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "system": VAPT_SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 6000},
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                data = await resp.json()
                return data.get("response", "")

    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI-compatible API."""
        import aiohttp
        url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo"),
            "messages": [
                {"role": "system", "content": VAPT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1500,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                    data = await resp.json()
                    if not resp.ok or "choices" not in data:
                        err = data.get("error", {}).get("message", str(data)) if isinstance(data, dict) else str(data)
                        return f"LLM Error ({resp.status}): {err}"
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"LLM Error: {str(e)}"

    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        import aiohttp
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": os.environ.get("ANTHROPIC_MODEL", "claude-3-haiku-20240307"),
            "max_tokens": 1500,
            "system": VAPT_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                data = await resp.json()
                return data["content"][0]["text"]

    async def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API."""
        import aiohttp
        model = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash-latest")
        api_key = os.environ.get("GEMINI_API_KEY", "")
        # Strip models/ prefix if user accidentally included it
        if model.startswith("models/"): model = model[7:]
        url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent?key={api_key}"
        headers = {
            "Content-Type": "application/json",
        }
        payload = {
            "systemInstruction": {
                "parts": [{"text": VAPT_SYSTEM_PROMPT}]
            },
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 6000
            }
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                data = await resp.json()
                try:
                    return data["candidates"][0]["content"]["parts"][0]["text"]
                except (KeyError, IndexError):
                    import logging
                    logging.error(f"Gemini API error: {data}")
                    raise ValueError(f"Failed to parse Gemini response: {data}")
