import json
from typing import Any, Dict

from config import LLM_MODEL, OPENAI_API_KEY, OPENAI_BASE_URL


client = None
if OPENAI_API_KEY:
    try:
        from openai import OpenAI  # type: ignore

        client = OpenAI(
            api_key=OPENAI_API_KEY,
            base_url=OPENAI_BASE_URL if OPENAI_BASE_URL else None,
        )
    except Exception:
        client = None
SYSTEM_PROMPT = """You are a cybersecurity analyst.
Extract structured fields from text. Return STRICT JSON only.
Do not add markdown. Do not add explanations outside JSON.
"""


def _safe_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        return {}


def extract_cve_info(text: str) -> Dict[str, Any]:
    if client is None:
        return {}

    prompt = f"""
Extract these fields from the following CVE description:
- products: list of strings
- versions: list of strings
- vuln_type: string
- impact: short string

Text:
{text[:2000]}

Return JSON only.
"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        content = resp.choices[0].message.content or "{}"
        return _safe_json(content)
    except Exception:
        return {}


def classify_dread(text: str) -> Dict[str, Any]:
    if client is None:
        return {}

    prompt = f"""
Classify the following dark-web related text into ONE of these categories:
- exploit_sale
- data_leak
- access_sale
- malware_activity
- noise

Also return:
- confidence: float between 0 and 1

Text:
{text[:2000]}

Return JSON only.
"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        content = resp.choices[0].message.content or "{}"
        return _safe_json(content)
    except Exception:
        return {}


def generate_explanation(context: Dict[str, Any]) -> str:
    if client is None:
        return ""

    prompt = f"""
Write 2-3 concise sentences explaining the risk and why it should be prioritized.

Context:
{json.dumps(context)[:2000]}
"""

    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            temperature=0.3,
            messages=[
                {"role": "system", "content": "You are a concise cybersecurity analyst."},
                {"role": "user", "content": prompt},
            ],
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception:
        return ""
