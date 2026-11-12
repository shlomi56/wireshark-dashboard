"""Whole-capture statistics (Assignment questions 23-26).

Produces: total packets, start/end time, duration, top IP addresses, top
protocols and a per-bucket packet count used for the "traffic over time" chart.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import pandas as pd

from core.capture_io import extract_ip_pair, open_capture


@dataclass
class CaptureOverview:
    """Plain-data container for the statistics of a whole capture.

    Only built-in types are stored (dicts, lists, floats) so the object can be
    cached by Streamlit and serialised safely.
    """

    total_packets: int = 0
    start_ts: Optional[float] = None  # epoch seconds of the first packet
    end_ts: Optional[float] = None  # epoch seconds of the last packet
    duration_s: Optional[float] = None  # end_ts - start_ts
    src_counts: Dict[str, int] = field(default_factory=dict)  # packets per source IP
    dst_counts: Dict[str, int] = field(default_factory=dict)  # packets per destination IP
    protocol_counts: Dict[str, int] = field(default_factory=dict)  # packets per protocol
    timestamps: List[float] = field(default_factory=list)  # every packet's epoch time


def classify_protocol(pkt) -> str:
    """Return the protocol name we count a packet under.

    Wireshark's "Protocol" column shows the *highest* dissected layer. For HTTP
    that is misleading: the packet carrying an HTTP POST body has highest layer
    ``URLENCODED-FORM`` and a JSON response has ``JSON``. We therefore look at
    the full protocol chain and report ``HTTP`` whenever it contains http.

    Args:
        pkt: A PyShark packet.

    Returns:
        An upper-case protocol label such as ``"TCP"``, ``"TLS"``, ``"HTTP"``.
    """
    try:
        # frame.protocols is a colon-separated chain from outermost to innermost
        # layer, e.g. "eth:ethertype:ip:tcp:http:json".
        chain = str(pkt.frame_info.protocols).split(":")
        if "http" in chain:
            return "HTTP"
    except AttributeError:
        # frame_info/protocols missing: fall through to the generic rule below.
        pass
    # highest_layer is PyShark's name for the innermost layer of the packet.
    return str(pkt.highest_layer).upper()


def collect_capture_overview(path: str, tshark_path: Optional[str] = None) -> CaptureOverview:
    """Stream through every packet once and aggregate the summary statistics.

    Args:
        path: Path of the capture file.
        tshark_path: Optional explicit path of the tshark executable.

    Returns:
        A populated :class:`CaptureOverview`.
    """
    src_counter: Counter = Counter()
    dst_counter: Counter = Counter()
    proto_counter: Counter = Counter()
    timestamps: List[float] = []

    # No display_filter here: statistics must cover ALL packets.
    with open_capture(path, tshark_path=tshark_path) as cap:
        for pkt in cap:
            # sniff_timestamp is the capture timestamp as a string of epoch
            # seconds (e.g. "1700000000.123456"); float() makes it arithmetic.
            timestamps.append(float(pkt.sniff_timestamp))

            # Count endpoints. Non-IP frames (ARP, STP...) yield (None, None)
            # and are intentionally excluded from the IP statistics.
            src, dst = extract_ip_pair(pkt)
            if src is not None:
                src_counter[src] += 1
                dst_counter[dst] += 1

            proto_counter[classify_protocol(pkt)] += 1

    overview = CaptureOverview(
        total_packets=len(timestamps),
        src_counts=dict(src_counter),
        dst_counts=dict(dst_counter),
        protocol_counts=dict(proto_counter),
        timestamps=timestamps,
    )
    if timestamps:
        # min/max instead of first/last: pcapng files are *usually* ordered but
        # the format does not guarantee it, so this is the safe definition.
        overview.start_ts = min(timestamps)
        overview.end_ts = max(timestamps)
        overview.duration_s = overview.end_ts - overview.start_ts
    return overview


def combine_endpoint_counts(src_counts: Dict[str, int], dst_counts: Dict[str, int]) -> Dict[str, int]:
    """Merge source and destination counters into a per-IP "total packets" view.

    An IP that sent 10 packets and received 15 took part in 25 packets. This is
    the number Wireshark shows in Statistics > Endpoints.

    Args:
        src_counts: Packets sent, keyed by IP.
        dst_counts: Packets received, keyed by IP.

    Returns:
        Dict mapping IP -> packets sent + received.
    """
    total: Counter = Counter()
    total.update(src_counts)  # Counter.update with a dict ADDS counts
    total.update(dst_counts)
    return dict(total)


def top_n_table(counts: Dict[str, int], n: int, label: str) -> pd.DataFrame:
    """Return the ``n`` largest entries of a counter as a ranked DataFrame.

    Args:
        counts: Mapping of name -> packet count.
        n: How many rows to keep.
        label: Header for the name column (``"IP Address"``, ``"Protocol"``...).

    Returns:
        DataFrame with columns ``[label, "Packets", "Share (%)"]``.
    """
    total = sum(counts.values()) or 1  # avoid division by zero on empty input
    # Counter.most_common sorts descending by count and cuts at n.
    rows = Counter(counts).most_common(n)
    return pd.DataFrame(
        {
            label: [name for name, _ in rows],
            "Packets": [count for _, count in rows],
            "Share (%)": [round(100 * count / total, 1) for _, count in rows],
        }
    )


def choose_bucket_seconds(duration_s: Optional[float], target_buckets: int = 120) -> int:
    """Pick a time-bucket width so the chart has roughly ``target_buckets`` bars.

    Args:
        duration_s: Capture duration in seconds (None/0 gives 1-second buckets).
        target_buckets: Desired number of points on the time axis.

    Returns:
        Bucket width in whole seconds (minimum 1).
    """
    if not duration_s or duration_s <= 0:
        return 1
    return max(1, math.ceil(duration_s / target_buckets))


def build_traffic_timeseries(timestamps: List[float], bucket_s: int) -> pd.DataFrame:
    """Count packets per fixed-width time bucket.

    Args:
        timestamps: Epoch seconds of every packet.
        bucket_s: Bucket width in seconds.

    Returns:
        DataFrame with columns ``Time`` (UTC datetime) and ``Packets``.
    """
    if not timestamps:
        return pd.DataFrame({"Time": [], "Packets": []})
    # Turn epoch seconds into a DatetimeIndex; every packet contributes "1".
    index = pd.to_datetime(timestamps, unit="s", utc=True)
    series = pd.Series(1, index=index)
    # resample() groups by fixed windows AND keeps empty windows as 0, so quiet
    # periods are visible on the chart instead of being silently skipped.
    counts = series.resample(f"{bucket_s}s").sum()
    return pd.DataFrame({"Time": counts.index, "Packets": counts.values})
