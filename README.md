# Privacy-Preserving Browser Vision Agent
**SIH Problem Statement 26171 (ISRO / Dept. of Space)** — On-device Visual Perception for Light-weight Browser Agents

A working prototype of a browser agent that reads the screen locally, redacts
every sensitive region **on-device**, and only ever sends a sanitized payload
to a server that decides the next action.

---

## 1. What's in this folder

```
extension/          Chrome/Edge extension (Manifest V3) — the client
  manifest.json
  background.js      capture screen, talk to server, orchestrate
  content.js          local DOM/PII scan + canvas redaction + action executor
  popup.html/js       UI, local face-detection model (client-side CV)
  styles.css
server/              Flask server — the "cloud" side
  server.py           receives ONLY sanitized data, decides next action
  requirements.txt
```

## 2. How it maps to the problem statement

| Brief asks for | What we built |
|---|---|
| Local vision model reading the screen | `content.js` DOM scanner (structural "vision" of the page) **+** `popup.js` runs TinyFaceDetector (a real, ~190KB CNN) client-side over the screenshot via WebGL/WASM |
| Dynamically detect + redact sensitive elements | Regex PII detectors (email/phone/card/aadhaar) + sensitive-input-type detection + face boxes, merged and blacked out with canvas ops **before** anything leaves the browser |
| Only anonymized data sent to server | `background.js` POSTs only the redacted PNG + an abstracted DOM summary (`[REDACTED]` in place of sensitive text) |
| Server aware of the redaction scheme | `server.py::check_for_leaks()` re-scans everything it receives for PII patterns as a defense-in-depth check, logs/flags anything unexpected |
| Server returns actionable commands | `heuristic_decide()` (offline, zero-dependency demo mode) or `vlm_decide()` (real Claude/VLM call) returns `{type: click/type/scroll, selector}` |
| Client executes the action | `content.js::executeAction()` — and it **refuses** to type into any sensitive field even if instructed to, as a second safety layer |
| Balance latency vs accuracy | Two-tier detection: cheap DOM/regex pass always runs (sub-millisecond); the heavier vision model only runs on the screenshot once per cycle. Every stage is timed and shown live in the popup |

## 3. Why this architecture (say this in your presentation)

- **DOM signals first, pixels second.** Most PII on a web page (password
  fields, emails in text) is *structurally* knowable from the DOM at near-zero
  cost — no need to run a heavy vision model for it. The learned vision model
  is reserved for what the DOM *can't* tell you: faces, and other elements
  that are only visible as pixels (e.g. embedded images, PDFs). This is the
  latency/accuracy trade-off the brief explicitly asks you to justify.
- **Redaction happens before the image ever leaves `content.js`.** The
  network request is built from the *already-redacted* canvas output, not the
  raw screenshot — so there's no code path where raw pixels could leak, even
  by a future bug in the server call.
- **Defense in depth.** The server independently re-checks incoming data for
  PII patterns, rather than trusting the client blindly. This is what "server
  aware of the redaction scheme" means in the brief.
- **The client also gatekeeps actions.** Even if a compromised or malicious
  server told the agent to type into a password field, `content.js` refuses.

## 4. Running the demo

### Server
```bash
cd server
pip install -r requirements.txt
python server.py
# -> running on http://localhost:5000  (heuristic mode by default)
```
To use a real hosted VLM instead of the offline heuristic:
```bash
export ANTHROPIC_API_KEY=sk-...
export USE_REAL_VLM=1
python server.py
```

### Extension
1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select the `extension/` folder
4. Pin the extension, open it on any page with a form (a login page, a
   contact form, etc. — good demo pages: any signup form, Gmail compose,
   a page you've filled with a fake email/phone/card number in the text)
5. Type a task like `click the search button` or `click the submit button`
6. Click **Scan & Assist** — watch the popup show:
   - local DOM-scan and redaction timings
   - the **redacted screenshot preview** (black boxes over sensitive regions)
   - the count of PII regions found
   - the action the server decided on, and whether it executed

## 5. Evaluation-metric talking points (map straight to the rubric)

| Metric (weight) | What to show / say |
|---|---|
| Visual context accuracy (25%) | The abstracted DOM summary correctly identifies buttons/links/fields; show the `reasoning` string returned by the server picking the right element |
| PII recall/precision (20%) | Put a fake email, phone number, and a password field on a test page; show all three caught, none of the surrounding normal text falsely flagged |
| Redaction precision (20%) | Zoom into the preview image — boxes align tightly to the field/text, not oversized or offset |
| Client resource utilization (20%) | Quote the live-measured DOM-scan (~1-5ms) and face-detection (~50-150ms on CPU/WebGL) timings shown in the popup; note DOM/regex path needs no GPU at all |
| End-to-end latency (15%) | Quote the `serverRoundTripMs` shown live; explain the heuristic path is near-instant while a real VLM call adds ~1-3s, which is the trade-off worth discussing |

## 6. Known limitations to be upfront about (judges respect this)

- Face detector is loaded from a CDN for demo speed; a Chrome-Web-Store-ready
  build would bundle the ~190KB weights locally (MV3 remote-code policy).
- `heuristic_decide()` is a stand-in for a real VLM call so the demo works
  offline; `vlm_decide()` shows exactly how to swap in a real model.
- Coordinate mapping between screenshot pixel space and CSS pixel space uses
  `devicePixelRatio` as an approximation — good enough for a demo, would need
  tightening for pixel-perfect production redaction.
- Regex-based PII detection will miss novel/unseen formats; a production
  system would add a small NER model for text-based PII.
