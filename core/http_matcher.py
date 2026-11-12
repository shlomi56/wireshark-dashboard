"""HTTP request/response reassembly (Assignment questions 27-29).

Pipeline
--------
1. ``extract_http_events``  - PyShark pass: one ``HttpEvent`` per HTTP packet.
2. ``match_transactions``   - PURE Python: pair requests with responses.
3. ``transactions_to_dataframe`` - table for the UI.

Splitting steps 1 and 2 keeps the interesting algorithm free of PyShark so it
can be reasoned about (and unit-tested) in isolation.

Matching principle
------------------
HTTP/1.x over a single TCP connection is strictly ordered: the server must
answer requests in the order it received them (RFC 7230 section 6.3.2). So, per
TCP stream, the N-th response belongs to the N-th request, i.e. a FIFO queue.
Different connections are independent, hence the grouping by ``tcp.stream``.
Wireshark additionally tells each response which frame holds its request
(``http.request_in``); we use that hint first and FIFO as the fallback.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

import pandas as pd

from core.capture_io import extract_ip_pair, open_capture, safe_field
from core.utils import format_ts

# Longest text we keep for a single dissected field / body. Prevents a huge
# download from bloating memory, the UI, and the LLM prompt.
MAX_FIELD_CHARS = 500


@dataclass
class HttpEvent:
    """One HTTP message (request OR response) as seen in one packet."""

    frame: int  # Wireshark frame number (frame.number)
    ts: float  # capture timestamp, epoch seconds
    stream: int  # tcp.stream index: identifies the TCP connection
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    kind: str  # "request" or "response"
    # --- request-only fields -------------------------------------------------
    method: Optional[str] = None
    uri: Optional[str] = None
    host: Optional[str] = None
    full_uri: Optional[str] = None
    version: Optional[str] = None
    user_agent: Optional[str] = None
    # --- response-only fields ------------------------------------------------
    status_code: Optional[int] = None
    status_phrase: Optional[str] = None
    request_in: Optional[int] = None  # frame of the matching request (Wireshark's own link)
    http_time: Optional[float] = None  # seconds since request (Wireshark's http.time)
    server_header: Optional[str] = None
    # --- shared --------------------------------------------------------------
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    body: Optional[str] = None
    fields: Dict[str, str] = field(default_factory=dict)  # every dissected HTTP field


@dataclass
class HttpTransaction:
    """A matched request/response pair (a response may be missing)."""

    transaction_id: int
    tcp_stream: int
    method: str
    host: str
    uri: str
    full_url: str
    http_version: Optional[str]
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    request_frame: int
    request_ts: float
    status_code: Optional[int] = None
    status_phrase: Optional[str] = None
    response_frame: Optional[int] = None
    response_ts: Optional[float] = None
    response_time_ms: Optional[float] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    server_header: Optional[str] = None
    user_agent: Optional[str] = None
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    request_fields: Dict[str, str] = field(default_factory=dict)
    response_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class MatchResult:
    """Output of :func:`match_transactions`."""

    transactions: List[HttpTransaction]
    orphan_responses: int  # responses whose request is not in the capture
    informational_skipped: int  # 1xx interim responses (e.g. 100 Continue)


# ---------------------------------------------------------------------------
# Step 1: PyShark extraction
# ---------------------------------------------------------------------------
def _to_int(value) -> Optional[int]:
    """Convert a PyShark string field to int, returning None if impossible.

    Args:
        value: Usually a str such as ``"200"``; may be None.

    Returns:
        The integer value or None.
    """
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _truncate(text: Optional[str]) -> Optional[str]:
    """Shorten ``text`` to ``MAX_FIELD_CHARS`` characters, marking the cut.

    Args:
        text: Any string or None.

    Returns:
        The original string if short enough, else a truncated copy with an
        ellipsis, or None when the input is None.
    """
    if text is None:
        return None
    text = str(text)
    return text if len(text) <= MAX_FIELD_CHARS else text[:MAX_FIELD_CHARS] + "...[truncated]"


def dump_layer_fields(layer) -> Dict[str, str]:
    """Collect every dissected field of a PyShark layer as ``{name: text}``.

    Used for the "details" panel so the student can compare our table with what
    Wireshark's packet-details pane shows.

    Args:
        layer: A PyShark layer (we pass ``pkt.http``).

    Returns:
        Dict of field name (without the ``http.`` prefix) to a truncated string.
    """
    result: Dict[str, str] = {}
    # field_names lists the names of all fields the dissector produced here.
    for name in getattr(layer, "field_names", []):
        try:
            result[name] = _truncate(layer.get_field(name)) or ""
        except Exception:  # a malformed field must never abort the whole parse
            continue
    return result


def packet_to_http_event(pkt) -> Optional[HttpEvent]:
    """Convert one PyShark packet into an :class:`HttpEvent`.

    Args:
        pkt: A packet that matched the ``http`` display filter.

    Returns:
        The event, or None if the packet is not a real request/response (for
        example an HTTP "continuation" segment that carries only body bytes).
    """
    http = getattr(pkt, "http", None)
    tcp = getattr(pkt, "tcp", None)
    if http is None or tcp is None:
        return None  # we need the TCP stream id to pair messages

    src_ip, dst_ip = extract_ip_pair(pkt)
    if src_ip is None:
        return None

    # Wireshark's field http.request.method is exposed by PyShark as
    # `request_method`; it exists ONLY on request packets. Likewise
    # `response_code` exists only on responses. That presence test is our
    # request-vs-response discriminator.
    method = safe_field(http, "request_method")
    status_code = _to_int(safe_field(http, "response_code"))
    if method is None and status_code is None:
        return None  # continuation / unknown HTTP packet

    event = HttpEvent(
        frame=int(pkt.number),  # frame.number, same number Wireshark displays
        ts=float(pkt.sniff_timestamp),
        stream=int(tcp.stream),  # tcp.stream: unique id of this TCP connection
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(tcp.srcport),
        dst_port=int(tcp.dstport),
        kind="request" if method is not None else "response",
        content_type=safe_field(http, "content_type"),
        content_length=_to_int(safe_field(http, "content_length")),
        # file_data = the HTTP message body as text (http.file_data).
        body=_truncate(safe_field(http, "file_data")),
        fields=dump_layer_fields(http),
    )

    if event.kind == "request":
        event.method = str(method)
        event.uri = str(safe_field(http, "request_uri", "/"))
        event.host = safe_field(http, "host")  # the Host: header
        event.full_uri = safe_field(http, "request_full_uri")
        event.version = safe_field(http, "request_version")
        event.user_agent = safe_field(http, "user_agent")
    else:
        event.status_code = status_code
        event.status_phrase = safe_field(http, "response_phrase")
        event.version = safe_field(http, "response_version")
        # http.request_in: Wireshark's own back-reference "this response answers
        # the request in frame N". Available because the request precedes it.
        event.request_in = _to_int(safe_field(http, "request_in"))
        # http.time: Wireshark's own measure of seconds between request and response.
        try:
            event.http_time = float(safe_field(http, "time"))
        except (TypeError, ValueError):
            event.http_time = None
        event.server_header = safe_field(http, "server")
    return event


def extract_http_events(path: str, tshark_path: Optional[str] = None) -> List[HttpEvent]:
    """Run tshark with the ``http`` display filter and convert every match.

    Args:
        path: Capture file path.
        tshark_path: Optional explicit tshark executable path.

    Returns:
        HTTP events in capture order.
    """
    events: List[HttpEvent] = []
    # display_filter="http" is evaluated inside tshark, so TLS/DNS/QUIC packets
    # are never converted to XML - a large speed-up on big captures.
    # Note: tshark keeps the ORIGINAL frame numbers when filtering.
    with open_capture(path, display_filter="http", tshark_path=tshark_path) as cap:
        for pkt in cap:
            event = packet_to_http_event(pkt)
            if event is not None:
                events.append(event)
    return events


# ---------------------------------------------------------------------------
# Step 2: pure matching algorithm
# ---------------------------------------------------------------------------
def _build_transaction(tx_id: int, req: HttpEvent, resp: Optional[HttpEvent]) -> HttpTransaction:
    """Merge a request event and an optional response event into one record.

    Args:
        tx_id: Sequential id assigned to the transaction (1-based).
        req: The request event.
        resp: The matching response event, or None if unanswered.

    Returns:
        The combined :class:`HttpTransaction`.
    """
    # Fall back to the destination IP when the Host header is absent
    # (legal in HTTP/1.0).
    host = req.host or req.dst_ip
    uri = req.uri or "/"
    # request_full_uri is Wireshark's own reconstruction; build one if missing.
    full_url = req.full_uri or f"http://{host}{uri}"

    tx = HttpTransaction(
        transaction_id=tx_id,
        tcp_stream=req.stream,
        method=req.method or "?",
        host=host,
        uri=uri,
        full_url=full_url,
        http_version=req.version,
        # Client/server are defined by who sent the REQUEST. The response simply
        # travels in the opposite direction on the same TCP connection.
        client_ip=req.src_ip,
        server_ip=req.dst_ip,
        client_port=req.src_port,
        server_port=req.dst_port,
        request_frame=req.frame,
        request_ts=req.ts,
        user_agent=req.user_agent,
        request_body=req.body,
        request_fields=req.fields,
    )
    if resp is not None:
        tx.status_code = resp.status_code
        tx.status_phrase = resp.status_phrase
        tx.response_frame = resp.frame
        tx.response_ts = resp.ts
        tx.content_type = resp.content_type
        tx.content_length = resp.content_length
        tx.server_header = resp.server_header
        tx.response_body = resp.body
        tx.response_fields = resp.fields
        # Prefer Wireshark's own http.time (seconds -> ms). If absent, compute
        # the difference of the two frame timestamps ourselves.
        if resp.http_time is not None:
            tx.response_time_ms = resp.http_time * 1000.0
        else:
            tx.response_time_ms = (resp.ts - req.ts) * 1000.0
    return tx


def match_transactions(events: List[HttpEvent]) -> MatchResult:
    """Pair HTTP requests with their responses.

    Algorithm (per TCP stream):
      * request  -> append to that stream's FIFO queue of unanswered requests;
      * response -> remove its request from the queue, using Wireshark's
        ``request_in`` frame number when it points to a queued request,
        otherwise the oldest queued request (HTTP/1.x ordering guarantee);
      * 1xx responses are interim ("100 Continue") and do not finish a
        transaction, so they are skipped;
      * requests still queued at the end are unanswered transactions.

    Args:
        events: HTTP events from :func:`extract_http_events`.

    Returns:
        A :class:`MatchResult`.
    """
    # stream id -> queue of requests waiting for their response.
    pending: Dict[int, Deque[HttpEvent]] = defaultdict(deque)
    # (request, response-or-None) pairs in the order they complete.
    pairs: List[Tuple[HttpEvent, Optional[HttpEvent]]] = []
    orphan_responses = 0
    informational = 0

    # Sorting by frame number guarantees capture order even if the input list
    # was assembled out of order.
    for ev in sorted(events, key=lambda e: e.frame):
        queue = pending[ev.stream]

        if ev.kind == "request":
            queue.append(ev)
            continue

        # ---- response ----
        if ev.status_code is not None and 100 <= ev.status_code < 200:
            informational += 1
            continue

        matched: Optional[HttpEvent] = None
        if ev.request_in is not None:
            # Look for the exact request Wireshark says this response answers.
            for candidate in queue:
                if candidate.frame == ev.request_in:
                    matched = candidate
                    queue.remove(candidate)
                    break
        if matched is None and queue:
            matched = queue.popleft()  # FIFO fallback

        if matched is None:
            orphan_responses += 1  # capture started mid-connection
            continue
        pairs.append((matched, ev))

    # Whatever is still queued never received a response in this capture.
    for queue in pending.values():
        for unanswered in queue:
            pairs.append((unanswered, None))

    # Present transactions ordered by when the REQUEST was sent.
    pairs.sort(key=lambda pair: pair[0].frame)
    transactions = [_build_transaction(i, req, resp) for i, (req, resp) in enumerate(pairs, start=1)]
    return MatchResult(transactions, orphan_responses, informational)


def analyze_http(path: str, tshark_path: Optional[str] = None) -> MatchResult:
    """Convenience wrapper: extract events from a file and match them.

    Args:
        path: Capture file path.
        tshark_path: Optional explicit tshark executable path.

    Returns:
        The :class:`MatchResult` for the capture.
    """
    return match_transactions(extract_http_events(path, tshark_path))


# ---------------------------------------------------------------------------
# Step 3: tabular view
# ---------------------------------------------------------------------------
def transactions_to_dataframe(transactions: List[dict]) -> pd.DataFrame:
    """Build the table shown in the dashboard.

    Args:
        transactions: Transactions as plain dicts (``dataclasses.asdict``).

    Returns:
        DataFrame with one row per transaction and the columns required by
        Assignment Q28 (method, host/URI, IPs, ports, status, time, frames).
    """
    rows = []
    for t in transactions:
        rows.append(
            {
                "#": t["transaction_id"],
                "Method": t["method"],
                "Host": t["host"],
                "URI": t["uri"],
                "Client IP": t["client_ip"],
                "Client Port": t["client_port"],
                "Server IP": t["server_ip"],
                "Server Port": t["server_port"],
                "Status": t["status_code"],  # None -> shown as empty (no response)
                "Response Time (ms)": None
                if t["response_time_ms"] is None
                else round(t["response_time_ms"], 3),
                "Request Frame": t["request_frame"],
                "Response Frame": t["response_frame"],
                "Request Time": format_ts(t["request_ts"], with_tz=False),
                "TCP Stream": t["tcp_stream"],
            }
        )
    df = pd.DataFrame(rows)
    # Nullable integer dtype keeps whole numbers (e.g. 200) instead of turning
    # them into floats (200.0) just because some rows are missing a value.
    for col in ("Status", "Response Frame"):
        if col in df:
            df[col] = df[col].astype("Int64")
    return df
