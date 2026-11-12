"""Low-level PyShark helpers.

Everything that touches PyShark's *API surface* (opening a capture, reading
layer fields) lives here or in the two analysis modules, never in the UI code.
That keeps ``app.py`` a thin presentation layer and makes the parsing logic
easy to explain and unit-test on its own.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from contextlib import contextmanager
from typing import Iterator, Optional, Tuple

import pyshark

# Shown by the UI when tshark cannot be found. PyShark does NOT parse packets
# itself: it launches Wireshark's command-line tool `tshark` as a subprocess
# and reads its XML/JSON output, so tshark must be installed.
TSHARK_HELP = (
    "PyShark needs Wireshark's command-line tool `tshark`. On macOS install it "
    "with `brew install --cask wireshark` (tshark is then located at "
    "/Applications/Wireshark.app/Contents/MacOS/tshark) and, if it is not on "
    "your PATH, paste that path into the sidebar field 'tshark path'."
)


def save_upload_to_temp(file_bytes: bytes, suffix: str) -> str:
    """Write uploaded bytes to a temporary file and return its path.

    PyShark (via tshark) can only read captures from a *file path*, but
    Streamlit's uploader hands us an in-memory buffer, so we spill it to disk.

    Args:
        file_bytes: Raw content of the uploaded .pcap / .pcapng file.
        suffix: File extension including the dot (e.g. ``".pcapng"``). tshark
            auto-detects the format from content, but keeping the suffix makes
            debugging easier.

    Returns:
        Absolute path of the temporary file. The caller must delete it.
    """
    # delete=False because we need the file to survive after the `with` block
    # so that the tshark subprocess can open it by name.
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        return tmp.name


@contextmanager
def open_capture(
    path: str,
    display_filter: Optional[str] = None,
    tshark_path: Optional[str] = None,
) -> Iterator["pyshark.FileCapture"]:
    """Open a capture file with PyShark and guarantee it is closed afterwards.

    This is a context manager so that the tshark child process and the asyncio
    event loop are always cleaned up, even if parsing raises an exception.

    Args:
        path: Path of the .pcap/.pcapng file on disk.
        display_filter: Optional Wireshark *display filter* (e.g. ``"http"``).
            Filtering inside tshark is much faster than filtering in Python
            because non-matching packets are never serialised to XML.
        tshark_path: Optional absolute path to the tshark executable.

    Yields:
        An iterable ``pyshark.FileCapture``.
    """
    # Streamlit executes our script in a worker thread that has NO asyncio
    # event loop, while PyShark is built on asyncio. Without creating a loop
    # first, PyShark fails with "There is no current event loop in thread
    # 'ScriptRunner.scriptThread'". So we create and register one ourselves.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(
        input_file=path,
        display_filter=display_filter,
        # keep_packets=False: do not cache every parsed packet in RAM. We only
        # stream through the file once, so this keeps memory usage flat.
        keep_packets=False,
        tshark_path=tshark_path or None,
    )
    try:
        yield cap
    finally:
        # Always terminate the tshark subprocess, then release the loop.
        try:
            cap.close()
        finally:
            loop.close()


def extract_ip_pair(pkt) -> Tuple[Optional[str], Optional[str]]:
    """Return the (source, destination) IP addresses of a packet.

    Args:
        pkt: A ``pyshark.packet.packet.Packet``.

    Returns:
        ``(src, dst)`` strings, or ``(None, None)`` for packets that have no IP
        layer at all (e.g. ARP, which works on MAC addresses).
    """
    # PyShark exposes each protocol layer as an attribute named after the layer.
    # Accessing a layer that is absent raises AttributeError, which getattr()
    # turns into the default value we supply (None).
    for layer_name in ("ip", "ipv6"):
        layer = getattr(pkt, layer_name, None)
        if layer is not None:
            # layer.src / layer.dst correspond to the Wireshark fields
            # ip.src / ip.dst (or ipv6.src / ipv6.dst).
            return str(layer.src), str(layer.dst)
    return None, None


def safe_field(layer, name: str, default=None):
    """Read one dissected field from a PyShark layer without raising.

    Args:
        layer: A PyShark layer object (e.g. ``pkt.http``).
        name: Field name *without* the layer prefix (``"request_method"`` for
            Wireshark's ``http.request.method``; dots become underscores).
        default: Value returned when the field does not exist in this packet.

    Returns:
        The field value (PyShark gives strings) or ``default``.
    """
    # A field is present only when the dissector found it in THIS packet, e.g.
    # `response_code` exists on responses but not on requests. PyShark signals
    # absence with AttributeError, so getattr(..., default) is the idiomatic guard.
    value = getattr(layer, name, default)
    return default if value is None else value
