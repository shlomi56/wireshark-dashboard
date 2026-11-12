"""Core (non-UI) logic for the PCAP analysis dashboard.

Sub-modules
-----------
capture_io    : low-level PyShark helpers (open a capture safely, read IP/TCP fields).
pcap_stats    : whole-capture statistics            (Assignment Q23-26).
http_matcher  : HTTP request/response reassembly    (Assignment Q27-29).
ai_chat       : LLM context building + chat calls   (Assignment Q30-34).
utils         : small formatting helpers shared by the other modules.
"""
