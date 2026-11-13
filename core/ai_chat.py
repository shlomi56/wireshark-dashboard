"""LLM chat support (Assignment questions 30-34).

DESIGN RULE: the raw PCAP file is NEVER sent to the model. PyShark first turns
the capture into structured HTTP transactions; only a compact JSON rendering of
that structured data is injected into the *system prompt*. The prompt then
forces the model to cite frame numbers and timestamps from that data, so every
claim in an answer can be verified in Wireshark.

LLM PROVIDER: Google Gemini, reached through its OpenAI-compatible REST
endpoint. Because Google mirrors the OpenAI "chat completions" protocol, we can
keep using the official ``openai`` Python package and only change two things:
the ``base_url`` (which server receives the request) and the API key.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from dotenv import load_dotenv
from openai import OpenAI

from core.utils import format_ts

# Hard cap on transactions placed in the prompt: protects the context window
# and the free-tier rate limits. The prompt tells the model when data was cut.
DEFAULT_MAX_TRANSACTIONS = 150

# Gemini's OpenAI-compatibility endpoint. The openai package appends
# "/chat/completions" to this URL, so requests go to Google, not to OpenAI.
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_MODEL = "gemini-2.5-flash"


def load_gemini_client() -> Optional[OpenAI]:
    """Create an ``OpenAI``-protocol client that talks to Google Gemini.

    The class is called ``OpenAI`` because it implements OpenAI's wire protocol,
    but ``base_url`` redirects every request to Google's servers, and the key
    sent is a Gemini key (free from Google AI Studio).

    Returns:
        A configured client, or None if ``GEMINI_API_KEY`` is not set (the UI
        then shows setup instructions instead of failing).
    """
    # load_dotenv reads key=value lines from ./.env into os.environ, so the
    # secret never appears in source code or in version control.
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None
    # base_url is the ONLY change needed to switch provider: the library now
    # sends its chat-completion requests to Gemini instead of api.openai.com.
    return OpenAI(api_key=api_key, base_url=GEMINI_BASE_URL)


def get_default_model() -> str:
    """Return the chat model name (``GEMINI_MODEL`` in .env, else ``gemini-2.5-flash``)."""
    return os.getenv("GEMINI_MODEL", DEFAULT_MODEL)


def _compact_transaction(t: dict, include_bodies: bool) -> dict:
    """Reduce one transaction to the fields worth sending to the model.

    Args:
        t: A transaction dict (``dataclasses.asdict`` of ``HttpTransaction``).
        include_bodies: Whether to include the request body (form fields).

    Returns:
        A small JSON-serialisable dict. Timestamps are converted to readable
        UTC strings so the model can quote them verbatim.
    """
    item = {
        "id": t["transaction_id"],
        "method": t["method"],
        "host": t["host"],
        "uri": t["uri"],
        "client": f'{t["client_ip"]}:{t["client_port"]}',
        "server": f'{t["server_ip"]}:{t["server_port"]}',
        "tcp_stream": t["tcp_stream"],
        "request_frame": t["request_frame"],
        "request_time_utc": format_ts(t["request_ts"]),
        "status_code": t["status_code"],
        "status_phrase": t["status_phrase"],
        "response_frame": t["response_frame"],
        "response_time_utc": format_ts(t["response_ts"]),
        "response_time_ms": None if t["response_time_ms"] is None else round(t["response_time_ms"], 2),
        "content_type": t["content_type"],
        "content_length": t["content_length"],
        "server_header": t["server_header"],
        "user_agent": t["user_agent"],
    }
    if include_bodies:
        item["request_body"] = t["request_body"]
    # Drop empty values: fewer tokens, and no ambiguity between "null" and "absent".
    return {k: v for k, v in item.items() if v is not None}


def build_llm_context(
    overview: dict,
    transactions: List[dict],
    max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
    include_bodies: bool = True,
) -> str:
    """Serialise the parsed capture into the JSON string injected in the prompt.

    Args:
        overview: ``dataclasses.asdict(CaptureOverview)``.
        transactions: All matched HTTP transactions as dicts.
        max_transactions: Maximum number of transactions to include.
        include_bodies: Include request bodies (may contain personal data).

    Returns:
        A JSON document with ``capture_summary``, ``transactions`` and an
        explicit ``truncated`` flag.
    """
    subset = transactions[:max_transactions]
    context = {
        "capture_summary": {
            "total_packets": overview["total_packets"],
            "start_time_utc": format_ts(overview["start_ts"]),
            "end_time_utc": format_ts(overview["end_ts"]),
            "duration_seconds": None if overview["duration_s"] is None else round(overview["duration_s"], 3),
            "protocol_packet_counts": overview["protocol_counts"],
            "http_transactions_total": len(transactions),
        },
        "transactions_included": len(subset),
        "truncated": len(transactions) > len(subset),
        "transactions": [_compact_transaction(t, include_bodies) for t in subset],
    }
    # separators without spaces shrink the JSON ~15%, saving tokens.
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"))


def build_system_prompt(context_json: str) -> str:
    """Create the system prompt that grounds the model in the parsed data.

    Args:
        context_json: Output of :func:`build_llm_context`.

    Returns:
        The full system prompt text.
    """
    return f"""You are a network-forensics assistant helping a student analyse a packet capture.

You do NOT have the PCAP file. You only have the structured HTTP data below, which was
extracted with PyShark/tshark. Treat it as the ONLY source of truth.

RULES
1. Answer ONLY from the DATA block. If the answer is not in the data, say exactly:
   "This is not visible in the extracted HTTP data." Never guess or use outside knowledge
   about what the traffic 'probably' contains.
2. EVIDENCE: every factual claim must cite the supporting evidence in the form
   (Frame <number> @ <timestamp>), using the request_frame / response_frame and
   request_time_utc / response_time_utc values from the data. Cite both request and
   response frames when an answer involves both. Frame numbers are Wireshark frame numbers
   (frame.number), so the user can verify them with the filter  frame.number == <n>.
3. Never invent frame numbers, timestamps, IPs, headers or status codes.
4. If "truncated" is true, say that only the first transactions are available when it matters.
5. HTTPS/TLS traffic is encrypted and is absent from this data; mention this if asked about it.
6. Be concise. Answer in the same language as the user's question.

DATA (JSON):
{context_json}
"""


def ask_llm(
    client: OpenAI,
    model: str,
    system_prompt: str,
    history: List[Dict[str, str]],
    max_history_messages: int = 12,
) -> str:
    """Send the conversation to the LLM and return the assistant's reply text.

    Args:
        client: Client from :func:`load_gemini_client` (pointed at Gemini).
        model: Gemini model name, e.g. ``"gemini-2.5-flash"``.
        system_prompt: Output of :func:`build_system_prompt`.
        history: Chat so far as ``[{"role": "user"|"assistant", "content": ...}]``.
        max_history_messages: Only the most recent N messages are re-sent, so
            long chats do not grow the request without bound. The system prompt
            (with the data) is always included.

    Returns:
        The model's answer as plain text.
    """
    messages = [{"role": "system", "content": system_prompt}] + history[-max_history_messages:]
    # The request is identical to an OpenAI one; Gemini's compatibility layer
    # translates it. No temperature is passed on purpose: the model's default
    # is fine, and fewer parameters means fewer compatibility surprises.
    response = client.chat.completions.create(model=model, messages=messages)
    return response.choices[0].message.content or ""
