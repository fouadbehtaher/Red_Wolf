"""
ai_analysis.py
---------------
Optional AI-assisted analysis layer for Red Wolf.

Takes the structured report_data produced by report.build_report_data()
and sends a summarized version of it to an LLM (bring-your-own API key)
to get back:
  - a plain-language risk narrative
  - a confirmed/adjusted severity opinion
  - concrete remediation steps
  - a submission-ready write-up paragraph for the bug bounty platform

Works with ANY OpenAI-compatible Chat Completions endpoint, so the
user can plug in their own key from:
  - OpenAI            (https://api.openai.com/v1)
  - OpenRouter          (https://openrouter.ai/api/v1)
  - NVIDIA NIM           (https://integrate.api.nvidia.com/v1)
  - any self-hosted / custom OpenAI-compatible server (--ai-base-url)

No key is ever hardcoded or stored by this module -- it is read from
a CLI flag or an environment variable at call time only.
"""

import json
import os
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

import requests

# Known providers mapped to their OpenAI-compatible base URL.
# "custom" lets the user point at literally anything else.
PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "nvidia": "https://integrate.api.nvidia.com/v1",
}

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "openrouter": "stepfun/step-5-preview",
    "nvidia": "nvidia/llama-3.1-nemotron-70b-instruct",
}


def detect_provider(api_key: Optional[str] = None) -> str:
    """Resolve a provider from configuration or a recognizable API key."""
    configured = os.environ.get("RED_WOLF_AI_PROVIDER", "").strip().lower()
    supported = set(PROVIDER_BASE_URLS) | {"custom"}
    if configured:
        if configured not in supported:
            raise AIAnalysisError(
                f"Unknown RED_WOLF_AI_PROVIDER '{configured}'. "
                f"Choose one of: {', '.join(sorted(supported))}."
            )
        return configured

    key = api_key or os.environ.get("RED_WOLF_AI_API_KEY", "")
    if key.startswith("nvapi-"):
        return "nvidia"
    if key.startswith("sk-or-"):
        return "openrouter"
    if key.startswith("sk-"):
        return "openai"
    if os.environ.get("RED_WOLF_AI_BASE_URL"):
        return "custom"
    return "openai"


SYSTEM_PROMPT = (
    "You are a senior penetration tester and bug bounty triager. "
    "You are given a JSON summary of findings from an authorized "
    "security scan (unauthenticated access / broken access control "
    "testing). Respond with four clearly labeled sections:\n"
    "1) Risk Narrative - plain-language explanation of real-world impact.\n"
    "2) Severity Opinion - your own CVSS-style severity judgement (Low/Medium/High/Critical) with a one-line justification.\n"
    "3) Remediation Steps - concrete, numbered steps a dev team should take.\n"
    "4) Submission Draft - a short, professional paragraph suitable for "
    "pasting into a bug bounty report's 'Description' field.\n"
    "Be concise. Do not invent findings that are not in the provided data. "
    "If the data shows no real findings, say so plainly instead of padding."
)


class AIAnalysisError(Exception):
    pass


@dataclass
class AIConfig:
    provider: str = "openai"          # one of PROVIDER_BASE_URLS keys, or "custom"
    api_key: Optional[str] = None     # if None, read from RED_WOLF_AI_API_KEY env var
    model: Optional[str] = None       # if None, use DEFAULT_MODELS[provider]
    base_url: Optional[str] = None    # required when provider == "custom"
    timeout: int = 60
    max_tokens: int = 2048

    def resolve_base_url(self) -> str:
        if self.provider == "custom":
            if not self.base_url:
                raise AIAnalysisError("provider='custom' requires --ai-base-url")
            return self.base_url.rstrip("/")
        if self.provider not in PROVIDER_BASE_URLS:
            raise AIAnalysisError(
                f"Unknown provider '{self.provider}'. "
                f"Choose one of: {', '.join(PROVIDER_BASE_URLS)}, or 'custom'."
            )
        return PROVIDER_BASE_URLS[self.provider]

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        return DEFAULT_MODELS.get(self.provider, "gpt-4o-mini")

    def resolve_api_key(self) -> str:
        key = self.api_key or os.environ.get("RED_WOLF_AI_API_KEY")
        if not key:
            raise AIAnalysisError(
                "No API key provided. Pass --ai-api-key or set the "
                "RED_WOLF_AI_API_KEY environment variable."
            )
        return key


def _summarize_for_prompt(report_data: dict, max_findings: int = 10) -> dict:
    """
    Trim the full report down to what the model actually needs --
    keeps the prompt small and avoids leaking irrelevant noise
    (e.g. raw body snippets beyond what's useful for judgement).
    """
    findings = report_data.get("findings", [])[:max_findings]

    def safe_path(value: object) -> str:
        parsed = urlsplit(str(value))
        path = parsed.path or "/"
        return path[:500]

    trimmed_findings = [
        {
            "path": safe_path(f.get("url", "")),
            "method": f["method"],
            "status_code": f["status_code"],
            "cors_wildcard": f["cors_wildcard"],
            "content_type": f["content_type"],
            "sensitive_data_found": f["sensitive_data_found"],
            "vrt_guess": f["vrt"],
        }
        for f in findings
    ]
    return {
        "target_location": "<authorized-target>",
        "total_endpoints_tested": report_data.get("total_endpoints_tested"),
        "total_accessible_without_auth": report_data.get("total_accessible_without_auth"),
        "findings_count": report_data.get("findings_count"),
        "confirmed_unauth_downloads": report_data.get("confirmed_unauth_downloads"),
        "findings": trimmed_findings,
        "deep_probe_downloads": [
            {
                "path": safe_path(d.get("resolved_url", "")),
                "downloaded": d.get("downloaded"),
                "status_code": d.get("status_code"),
            }
            for d in report_data.get("deep_probe_downloads", [])
        ],
    }


def analyze_report(report_data: dict, ai_config: AIConfig) -> str:
    """
    Send the (trimmed) report to the configured LLM and return the
    model's raw text response. Raises AIAnalysisError on any failure
    (missing key, bad provider, network error, unexpected response
    shape) so callers can decide whether to abort or just skip the
    AI section and still deliver the rest of the report.
    """
    base_url = ai_config.resolve_base_url()
    model = ai_config.resolve_model()
    api_key = ai_config.resolve_api_key()

    summary = _summarize_for_prompt(report_data)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(summary, ensure_ascii=False)},
        ],
        "temperature": 0.2,
        "max_tokens": ai_config.max_tokens,
    }

    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    }
    # OpenRouter asks for these but ignores them harmlessly if sent elsewhere
    if ai_config.provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/red-wolf-scanner"
        headers["X-Title"] = "Red Wolf"

    try:
        resp = requests.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=ai_config.timeout,
        )
    except requests.RequestException as exc:
        raise AIAnalysisError(f"Request to AI provider failed: {exc}") from exc

    if resp.status_code != 200:
        if resp.status_code == 402:
            raise AIAnalysisError(
                "AI provider credits are insufficient for this analysis. "
                f"Reduce max_tokens below {ai_config.max_tokens} or add provider credits."
            )
        raise AIAnalysisError(
            f"AI provider returned HTTP {resp.status_code}: {resp.text[:500]}"
        )

    try:
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise AIAnalysisError(
            f"Unexpected response shape from AI provider: {exc}. Raw: {resp.text[:500]}"
        ) from exc
