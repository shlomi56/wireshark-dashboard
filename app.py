"""Streamlit dashboard for PCAP / HTTP analysis (Assignment Part 3, Q23-34).

This file contains ONLY presentation code. All PyShark parsing and LLM logic is
in the ``core`` package so each piece can be explained and tested separately:

    core/pcap_stats.py    -> Q23-26  capture overview + charts data
    core/http_matcher.py  -> Q27-29  request/response matching
    core/ai_chat.py       -> Q30-34  prompt building + Gemini calls

Run with:  streamlit run app.py
"""

from __future__ import annotations

import hashlib
import inspect
import os
from dataclasses import asdict
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st

from core import ai_chat
from core.capture_io import TSHARK_HELP, save_upload_to_temp
from core.http_matcher import analyze_http, transactions_to_dataframe
from core.pcap_stats import (
    build_traffic_timeseries,
    choose_bucket_seconds,
    collect_capture_overview,
    combine_endpoint_counts,
    top_n_table,
)
from core.utils import format_duration, format_ts

st.set_page_config(page_title="PCAP / HTTP Dashboard", layout="wide")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def stretch_kwargs(widget) -> dict:
    """Return the keyword that makes a Streamlit widget fill its container.

    Streamlit renamed ``use_container_width=True`` to ``width="stretch"`` and
    later removed the old argument. Inspecting the signature keeps this app
    working on both old and new Streamlit versions.

    Args:
        widget: A Streamlit function such as ``st.plotly_chart``.

    Returns:
        ``{"use_container_width": True}``, ``{"width": "stretch"}`` or ``{}``.
    """
    params = inspect.signature(widget).parameters
    if "use_container_width" in params:
        return {"use_container_width": True}
    if "width" in params:
        return {"width": "stretch"}
    return {}


@st.cache_data(show_spinner=False)
def analyze_capture(file_bytes: bytes, suffix: str, tshark_path: str) -> dict:
    """Parse an uploaded capture ONCE and cache the result.

    Streamlit re-runs the whole script on every click. Without caching, each
    interaction would re-launch tshark; with caching, identical inputs return
    the stored result instantly.

    Args:
        file_bytes: Content of the uploaded capture (part of the cache key).
        suffix: File extension, ``.pcap`` or ``.pcapng``.
        tshark_path: Optional tshark path ("" means search the PATH).

    Returns:
        Dict with ``overview`` (dict), ``transactions`` (list of dicts),
        ``orphan_responses`` and ``informational_skipped``. Only plain types are
        returned so Streamlit can pickle them safely.
    """
    path = save_upload_to_temp(file_bytes, suffix)
    try:
        # Pass 1: statistics over every packet (Q24-26).
        overview = collect_capture_overview(path, tshark_path or None)
        # Pass 2: HTTP-only extraction and request/response matching (Q27-29).
        match = analyze_http(path, tshark_path or None)
    finally:
        os.remove(path)  # never leave user captures behind in the temp folder
    return {
        "overview": asdict(overview),
        "transactions": [asdict(t) for t in match.transactions],
        "orphan_responses": match.orphan_responses,
        "informational_skipped": match.informational_skipped,
    }


def status_class(code) -> str:
    """Group an HTTP status code into a readable class label for charts.

    Args:
        code: Integer status code, or None/NA when there was no response.

    Returns:
        ``"2xx Success"``, ``"3xx Redirect"``, ``"4xx Client error"``,
        ``"5xx Server error"``, ``"1xx Info"`` or ``"No response"``.
    """
    if code is None or pd.isna(code):
        return "No response"
    code = int(code)
    if code >= 500:
        return "5xx Server error"
    if code >= 400:
        return "4xx Client error"
    if code >= 300:
        return "3xx Redirect"
    if code >= 200:
        return "2xx Success"
    return "1xx Info"


def apply_quick_filter(df: pd.DataFrame, mode: str) -> pd.DataFrame:
    """Filter the transaction table according to the chosen quick filter.

    Args:
        df: Full transaction table.
        mode: One of the labels in ``QUICK_FILTERS``.

    Returns:
        The filtered table with a fresh 0..n-1 index (needed because the UI maps
        selected row positions back to rows).
    """
    if df.empty or mode == "All transactions":
        return df.reset_index(drop=True)
    status = df["Status"]
    if mode == "HTTP errors (status >= 400)":
        mask = status >= 400  # pd.NA compares as False, so unanswered rows drop out
    elif mode == "Client errors (4xx)":
        mask = (status >= 400) & (status < 500)
    elif mode == "Server errors (5xx)":
        mask = status >= 500
    else:  # "No response captured"
        mask = status.isna()
    return df[mask.fillna(False)].reset_index(drop=True)


QUICK_FILTERS = [
    "All transactions",
    "HTTP errors (status >= 400)",
    "Client errors (4xx)",
    "Server errors (5xx)",
    "No response captured",
]


# ---------------------------------------------------------------------------
# UI sections
# ---------------------------------------------------------------------------
def render_overview(overview: dict) -> None:
    """Show Q23-26: totals, time range, top IPs, top protocols and charts.

    Args:
        overview: ``asdict(CaptureOverview)`` from :func:`analyze_capture`.
    """
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total packets", f'{overview["total_packets"]:,}')
    c2.metric("Duration", format_duration(overview["duration_s"]))
    c3.metric("Start (UTC)", format_ts(overview["start_ts"], with_tz=False))
    c4.metric("End (UTC)", format_ts(overview["end_ts"], with_tz=False))

    left, right = st.columns(2)
    with left:
        st.subheader("Top IP addresses")
        endpoints = combine_endpoint_counts(overview["src_counts"], overview["dst_counts"])
        st.caption("Packets sent + received per address (like Wireshark > Statistics > Endpoints).")
        st.dataframe(top_n_table(endpoints, 10, "IP Address"), hide_index=True)
        src_tab, dst_tab = st.tabs(["Top sources", "Top destinations"])
        src_tab.dataframe(top_n_table(overview["src_counts"], 5, "Source IP"), hide_index=True)
        dst_tab.dataframe(top_n_table(overview["dst_counts"], 5, "Destination IP"), hide_index=True)
    with right:
        st.subheader("Top protocols")
        proto_df = top_n_table(overview["protocol_counts"], 10, "Protocol")
        st.dataframe(proto_df, hide_index=True)
        fig = px.pie(proto_df, names="Protocol", values="Packets", hole=0.4, title="Protocol distribution")
        st.plotly_chart(fig, **stretch_kwargs(st.plotly_chart))

    # Traffic over time (Q26): packets per bucket.
    bucket = choose_bucket_seconds(overview["duration_s"])
    ts_df = build_traffic_timeseries(overview["timestamps"], bucket)
    fig = px.area(ts_df, x="Time", y="Packets", title=f"Traffic over time ({bucket}-second buckets, UTC)")
    st.plotly_chart(fig, **stretch_kwargs(st.plotly_chart))


def render_transactions(df: pd.DataFrame, transactions: List[dict], result: dict) -> None:
    """Show Q27-29: the transaction table, quick filters and a details view.

    Args:
        df: Full transaction table.
        transactions: Transactions as dicts (for the details panel).
        result: The cached analysis dict (for the orphan/1xx counters).
    """
    if df.empty:
        st.warning(
            "No plain-text HTTP transactions were found. HTTPS (TLS) traffic is encrypted and "
            "cannot be dissected as HTTP. Capture an http:// site (Assignment Part B)."
        )
        return

    notes = []
    if result["orphan_responses"]:
        notes.append(f'{result["orphan_responses"]} response(s) without a request in the capture')
    if result["informational_skipped"]:
        notes.append(f'{result["informational_skipped"]} interim 1xx response(s) skipped')
    if notes:
        st.caption("Note: " + "; ".join(notes) + ".")

    # BONUS quick filter lives right above the table.
    mode = st.radio("Quick filter", QUICK_FILTERS, horizontal=True)
    view = apply_quick_filter(df, mode)
    st.caption(f"{len(view)} of {len(df)} transactions shown. Click a row to see its details.")

    # on_select="rerun" makes row clicks return a selection object.
    event = st.dataframe(
        view,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="tx_table",
        **stretch_kwargs(st.dataframe),
    )
    selected_rows = event.selection.rows
    if not selected_rows:
        return

    # The selection holds the *position* in `view`; the "#" column is the real id.
    tx_id = int(view.iloc[selected_rows[0]]["#"])
    tx = next(t for t in transactions if t["transaction_id"] == tx_id)
    render_transaction_details(tx)


def render_transaction_details(tx: dict) -> None:
    """Show request and response details for one selected transaction.

    Args:
        tx: One transaction dict.
    """
    st.subheader(f'Transaction #{tx["transaction_id"]}: {tx["method"]} {tx["full_url"]}')

    # A ready-made Wireshark filter lets the student verify our numbers.
    frames = [tx["request_frame"]] + ([tx["response_frame"]] if tx["response_frame"] else [])
    frame_filter = " || ".join(f"frame.number == {n}" for n in frames)
    st.code(f"{frame_filter}    # or:  tcp.stream == {tx['tcp_stream']}", language="text")

    req_col, resp_col = st.columns(2)
    with req_col:
        st.markdown(f'**Request** (frame {tx["request_frame"]})')
        st.json(
            {
                "time_utc": format_ts(tx["request_ts"]),
                "from": f'{tx["client_ip"]}:{tx["client_port"]}',
                "to": f'{tx["server_ip"]}:{tx["server_port"]}',
                "method": tx["method"],
                "uri": tx["uri"],
                "host": tx["host"],
                "http_version": tx["http_version"],
                "user_agent": tx["user_agent"],
                "body": tx["request_body"],
            }
        )
    with resp_col:
        if tx["response_frame"] is None:
            st.markdown("**Response**")
            st.info("No response was captured for this request.")
        else:
            st.markdown(f'**Response** (frame {tx["response_frame"]})')
            st.json(
                {
                    "time_utc": format_ts(tx["response_ts"]),
                    "from": f'{tx["server_ip"]}:{tx["server_port"]}',
                    "to": f'{tx["client_ip"]}:{tx["client_port"]}',
                    "status": f'{tx["status_code"]} {tx["status_phrase"] or ""}'.strip(),
                    "response_time_ms": tx["response_time_ms"],
                    "content_type": tx["content_type"],
                    "content_length": tx["content_length"],
                    "server": tx["server_header"],
                    "body": tx["response_body"],
                }
            )
    with st.expander("All raw Wireshark HTTP fields (request / response)"):
        st.json({"request": tx["request_fields"], "response": tx["response_fields"]})


def render_bonus(df: pd.DataFrame) -> None:
    """BONUS: response-time scatter plot and status-code breakdown.

    Args:
        df: Full transaction table.
    """
    if df.empty:
        st.info("No HTTP transactions to plot.")
        return
    plot_df = df.copy()
    plot_df["Status Class"] = plot_df["Status"].apply(status_class)

    counts = plot_df["Status Class"].value_counts().reset_index()
    counts.columns = ["Status Class", "Transactions"]
    st.plotly_chart(
        px.bar(counts, x="Status Class", y="Transactions", color="Status Class", title="Transactions by status class"),
        **stretch_kwargs(st.plotly_chart),
    )

    answered = plot_df.dropna(subset=["Response Time (ms)"]).copy()
    if answered.empty:
        st.info("No answered transactions, so there are no response times to plot.")
        return
    # Convert the display string back to datetime for a proper time axis.
    answered["Request Time"] = pd.to_datetime(answered["Request Time"])
    fig = px.scatter(
        answered,
        x="Request Time",
        y="Response Time (ms)",
        color="Status Class",
        hover_data=["Method", "Host", "URI", "Request Frame", "Response Frame"],
        title="Response time per transaction",
    )
    st.plotly_chart(fig, **stretch_kwargs(st.plotly_chart))
    st.markdown("**Five slowest responses**")
    st.dataframe(
        answered.nlargest(5, "Response Time (ms)")[
            ["#", "Method", "Host", "URI", "Status", "Response Time (ms)", "Request Frame", "Response Frame"]
        ],
        hide_index=True,
    )


def render_chat(overview: dict, transactions: List[dict], file_key: str, model: str, include_bodies: bool) -> None:
    """Show the AI chat (Q30-34) grounded in the parsed HTTP data.

    Args:
        overview: Capture overview dict.
        transactions: All matched transactions.
        file_key: Hash of the uploaded file; the chat resets when it changes.
        model: Gemini model name from the sidebar.
        include_bodies: Whether request bodies may be sent to the LLM.
    """
    client = ai_chat.load_gemini_client()
    if client is None:
        st.error("No API key found. Copy `.env.example` to `.env`, set `GEMINI_API_KEY` (free at aistudio.google.com/apikey), then restart the app.")
        return
    if not transactions:
        st.info("There are no HTTP transactions to ask about in this capture.")
        return

    # Build the system prompt: structured data is injected here, NOT the PCAP.
    context_json = ai_chat.build_llm_context(overview, transactions, include_bodies=include_bodies)
    system_prompt = ai_chat.build_system_prompt(context_json)

    # Start a fresh conversation whenever a different capture is loaded.
    if st.session_state.get("chat_file_key") != file_key:
        st.session_state["chat_file_key"] = file_key
        st.session_state["messages"] = []

    with st.expander("Show the system prompt sent to the model (for your documentation, Q34)"):
        st.code(system_prompt, language="text")
    st.caption(
        "Example questions: Which request failed? How many requests went to each host? "
        "What was the slowest response and in which frames?"
    )

    for msg in st.session_state["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    question = st.chat_input("Ask about the HTTP traffic in this capture...")
    if question:
        st.session_state["messages"].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    answer = ai_chat.ask_llm(client, model, system_prompt, st.session_state["messages"])
                except Exception as exc:  # network / invalid key / free-tier rate limit (HTTP 429)
                    answer = f"LLM request failed: {exc}"
            st.markdown(answer)
        st.session_state["messages"].append({"role": "assistant", "content": answer})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    """Assemble the sidebar and the four tabs of the dashboard."""
    st.title("PCAP / HTTP Analysis Dashboard")

    with st.sidebar:
        st.header("Capture")
        uploaded = st.file_uploader("Upload a .pcap or .pcapng file", type=["pcap", "pcapng"])
        tshark_path = st.text_input(
            "tshark path (optional)",
            value=os.getenv("TSHARK_PATH", ""),
            help="Leave empty if tshark is on your PATH. macOS example: /Applications/Wireshark.app/Contents/MacOS/tshark",
        )
        st.header("AI assistant")
        model = st.text_input("Gemini model", value=ai_chat.get_default_model())
        include_bodies = st.checkbox(
            "Send request bodies to the LLM",
            value=True,
            help="Form data may contain personal data. Untick to keep bodies out of the prompt.",
        )

    if uploaded is None:
        st.info("Upload a capture in the sidebar to begin.")
        st.stop()

    file_bytes = uploaded.getvalue()
    file_key = hashlib.md5(file_bytes).hexdigest()
    suffix = os.path.splitext(uploaded.name)[1] or ".pcapng"

    try:
        with st.spinner("Parsing capture with PyShark (this launches tshark)..."):
            result = analyze_capture(file_bytes, suffix, tshark_path.strip())
    except Exception as exc:
        st.error(f"Could not parse the capture: {exc}")
        st.info(TSHARK_HELP)
        st.stop()

    overview: dict = result["overview"]
    transactions: List[dict] = result["transactions"]
    df = transactions_to_dataframe(transactions)

    tab_overview, tab_http, tab_chat, tab_bonus = st.tabs(
        ["Overview", "HTTP transactions", "AI assistant", "Bonus: errors and response times"]
    )
    with tab_overview:
        render_overview(overview)
    with tab_http:
        render_transactions(df, transactions, result)
    with tab_chat:
        render_chat(overview, transactions, file_key, model, include_bodies)
    with tab_bonus:
        render_bonus(df)


main()
