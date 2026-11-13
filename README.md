# PCAP / HTTP Analysis Dashboard (Assignment 1, Part C)

Streamlit + PyShark dashboard with a Google Gemini-powered assistant (via Gemini's OpenAI-compatible endpoint).

## Setup and Installation

### 1. Prerequisites (Wireshark & tshark)
This dashboard relies on the PyShark library, which requires `tshark` (the command-line network analyzer bundled with Wireshark) to be installed on your system.

* **macOS:** Download the macOS installer from [wireshark.org](https://www.wireshark.org/) or run `brew install --cask wireshark`.
* **Windows:** Download the Windows installer from [wireshark.org](https://www.wireshark.org/). *Important: During installation, ensure you check the box to install `tshark` and ensure Wireshark is added to your system PATH.*
* **Linux (Ubuntu/Debian):** Run `sudo apt update && sudo apt install tshark`.

### 2. Clone the Repository
```bash
git clone https://github.com/shlomi56/wireshark-dashboard.git
cd wireshark-dashboard
```

### 3. Python Environment Setup
Create an isolated virtual environment and install the required Python dependencies to prevent package conflicts.

**macOS and Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 4. API Configuration (Google Gemini)
The AI assistant chat feature uses the free Google Gemini API. 

1. Generate a free API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Create a hidden file named `.env` in the root of the project directory.
3. Paste your credentials into the `.env` file exactly like this:
```env
GEMINI_API_KEY=your-google-api-key-here
GEMINI_MODEL=gemini-3.8-flash
```
*(Note: If you do not configure an API key, the dashboard UI and local PCAP parsing will still function perfectly, but submitting a question to the AI assistant will return an authentication error).*

### 5. Running the Dashboard
With your virtual environment activated and your `.env` file saved, launch the application:
```bash
streamlit run app.py
```
A new tab will automatically open in your default web browser at `http://localhost:8501`.

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
