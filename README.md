# 🛡️ ThreatDetector

A lean Streamlit app that checks whether an **IP address, domain, or URL** looks safe or
suspicious, using **VirusTotal** and **WHOIS** data, interpreted by **Gemini** into a plain
verdict, confidence score, and explanation.

## Project structure

```text
app.py             # UI, validation, orchestration, Gemini prompt/call, result display
helpers.py         # get_virustotal(), get_whois(), and the SOURCES registry
requirements.txt   # streamlit, requests, google-genai, python-whois
```

## How it works

1. Pick a target type (IP / Domain / URL), enter the target, and pick a knowledge level.
2. `app.py` validates the input (`ipaddress`, a domain regex, or `urllib.parse`).
3. `app.py` loops generically over the `SOURCES` registry in `helpers.py`, calling each
   source function and collecting its result — a failure in one source never blocks the
   others.
4. The collected evidence is serialized to JSON and sent to Gemini **once**, in a prompt
   tailored to the selected knowledge level.
5. Gemini's structured JSON response (`verdict`, `confidence`, `ai_insight`,
   `key_findings`, `recommendation`) is parsed defensively and rendered.
6. Each source's raw result is shown in its own expander, generated dynamically from the
   results dict — not hard-coded.

## Architecture

```text
app.py  ──imports──▶  helpers.py
  UI                     get_virustotal()
  Validation             get_whois()
  Orchestration            │
  Gemini prompt/call       ▼
  Result display        SOURCES = {...}  ──▶  VirusTotal / WHOIS
```

Strict one-way dependency: `helpers.py` never imports from `app.py`, and contains no
Streamlit UI, no Gemini logic, and no orchestration — only source integrations plus
`@st.cache_data` for caching.

### Source contract

Every function registered in `SOURCES` takes `(target_type, target)` and returns:

```python
{"source": "Name", "status": "success", "data": {...}}
# or
{"source": "Name", "status": "error", "error": "human-readable message"}
```

### Adding a new intelligence source

Two edits, both confined to `helpers.py`:

```python
def get_newsource(target_type, target):
    ...
    return {"source": "NewSource", "status": "success", "data": {...}}

SOURCES["NewSource"] = get_newsource
```

Nothing else changes. The new source is automatically called during analysis, included in
the Gemini evidence, and given its own expander in the UI.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure secrets

Create `.streamlit/secrets.toml` (do **not** commit this file):

```toml
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
GEMINI_API_KEY = "your_gemini_api_key"
```

- VirusTotal key: https://www.virustotal.com/gui/my-apikey (free tier available)
- Gemini key: https://aistudio.google.com/app/apikey

If a key is missing, the app degrades gracefully rather than crashing: the affected source
reports a configuration error, or — if the Gemini key is missing — the app shows raw
VirusTotal/WHOIS results without an AI-generated verdict.

### 3. Run

```bash
streamlit run app.py
```

## Knowledge levels

| Level        | Focus |
|--------------|-------|
| Beginner     | Plain-language safe/suspicious verdict, why, and what to do next |
| Intermediate | Reputation indicators, WHOIS observations, security implications, next steps |
| Expert       | Detection ratios, registration/infrastructure indicators, inconsistencies, confidence, evidence limitations |

## Security notes

- ThreatDetector only queries VirusTotal and WHOIS — it never visits, crawls, scans, or
  otherwise interacts with the target itself.
- API keys are read from `st.secrets`, never hard-coded, logged, displayed, or sent to
  Gemini.
- Gemini receives only the structured VirusTotal/WHOIS evidence and is explicitly
  instructed to treat that evidence as untrusted data, not as instructions to follow.
- Results are a reputation/intelligence lookup, not a safety guarantee — the confidence
  score reflects the strength of the available evidence, not certainty.

## Limitations

- WHOIS lookups depend on the target's registrar/RIR responding on port 43; some
  registries rate-limit or block automated queries.
- VirusTotal's free-tier API keys are rate-limited (requests per minute and per day).
- Results are cached in-memory for 1 hour (`@st.cache_data(ttl=3600)`) per unique target,
  to avoid redundant external calls.
- If both sources fail or return no data, the verdict will typically come back `UNKNOWN`
  rather than a guess.
