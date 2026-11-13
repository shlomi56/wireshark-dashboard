# PCAP / HTTP Analysis Dashboard (Assignment 1, Part C)

Streamlit + PyShark dashboard with a Google Gemini-powered assistant (via Gemini's OpenAI-compatible endpoint).

## Setup (macOS, VS Code)

```bash
brew install --cask wireshark          # provides tshark, which PyShark drives
cd wireshark-dashboard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                   # then put your GEMINI_API_KEY in .env
streamlit run app.py
```

In VS Code choose the `.venv` interpreter (Cmd+Shift+P > "Python: Select Interpreter").
If tshark is not on your PATH, paste `/Applications/Wireshark.app/Contents/MacOS/tshark`
into the sidebar field "tshark path".

## Map to the assignment

| Questions | Feature | Code |
|---|---|---|
| 23-26 | Upload, totals, time range, top IPs/protocols, charts | `core/pcap_stats.py`, `render_overview` |
| 27-29 | HTTP request/response matching, table, details | `core/http_matcher.py`, `render_transactions` |
| 30-34 | Chat grounded in extracted data (no PCAP sent) | `core/ai_chat.py`, `render_chat` |
| Bonus | Error filters, response-time scatter plot | `apply_quick_filter`, `render_bonus` |

## Notes for the write-up

* Only HTTP over port 80 (plain text) is visible. HTTPS/TLS and QUIC are encrypted.
* A message's "frame" is the frame where Wireshark finishes dissecting it. If a
  request spans several TCP segments (headers in one, body in the next), the
  request frame is the LAST segment.
* Request bodies are sent to Google Gemini by default; untick the sidebar box to avoid that. On the free tier Google may use submitted content to improve its products.
* The free tier has rate limits; a 429 error in the chat means: wait a minute and retry.
* Do not include your API key in the submitted files (`.env` is git-ignored).
