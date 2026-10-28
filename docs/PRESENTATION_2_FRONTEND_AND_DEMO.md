# ReconLens - Part 2: The Frontend and the Live Demo (explained simply)

*OSINT-Based Dashboard for Digital Footprint Analysis and Cybersecurity*
*Team: Aryan Sharma (2024A1R101), Varun Sharma (2024A1R107)*

> Part 1 (`PRESENTATION_1_PROTOTYPE_AND_BACKEND.md`) explains the project, the methodology
> and the backend. This part explains **what you see in the browser**, **how each screen
> works**, how the frontend and backend **talk to each other**, and gives a **ready-made
> demo script** for class. Lines marked **🗣 Say it like this** can be read out loud.

---

## 1. What the frontend is

The frontend is everything that runs **inside the browser**: the pages, buttons, charts
and the graph.

**🗣 Say it like this:** *"The backend finds and analyses the information. The frontend
shows it in a way a non-expert can understand in a few seconds."*

We deliberately used **no heavy framework** (no React, no Angular). Only:

| Technology | Job |
|---|---|
| **HTML** with **Jinja2 templates** | The structure of each page (Flask fills in the template) |
| **CSS** (`static/css/style.css`) | Colours, layout, light/dark theme, mobile layout |
| **Plain JavaScript** (`static/js/*.js`) | Fetches data from the API and draws the results |
| **Chart.js** (library) | Bar chart, doughnut chart, vendor-verdict chart |
| **Cytoscape.js** (library) | The interactive relationship graph |
| **Local fonts** (Red Hat Display for headings, Public Sans for text, IBM Plex Mono for data) | Served from our own server - no internet needed |

**Why so simple?** It is easy to explain, loads fast, works fully offline (important for the
demo), and keeps security tight because no outside scripts are loaded.

---

## 2. How a page is built - two steps

Every page loads in **two steps**:

```
 Step 1: Browser asks for a page            Step 2: The page's JavaScript asks for data
 ───────────────────────────────            ────────────────────────────────────────────
 GET /domain                                fetch("/api/demo-targets")   → JSON
        │                                   fetch("/api/scan/domain")    → JSON
        ▼                                          │
 Flask fills a Jinja2 template and                 ▼
 sends back an HTML "shell"                 JavaScript builds the results on the page
 (menu, top bar, empty result area)         (gauge, graph, findings, tabs)
```

**🗣 Say it like this:** *"The server first sends an empty frame of the page. Then our
JavaScript asks the API for data in JSON and fills the frame in. This keeps the backend and
frontend cleanly separated - the same API could serve a mobile app."*

---

## 3. Frontend files and what each one does

### Templates (`templates/`) - the page skeletons

| File | Page |
|---|---|
| `base.html` | The common frame: red mode banner, links bar, white navigation bar (with the Investigate menu), Demo/Live switch, theme button, search strip, page hero and footer. Every page extends it. |
| `index.html` | **Overview** - big search box, sample cards, key numbers, charts, recent scans |
| `domain.html`, `username.html`, `email.html`, `reputation.html` | The four analysis pages |
| `macros.html` | The **shared scan form** used by all four analysis pages (so they all behave the same) |
| `graph.html` | **Investigation graph** page |
| `history.html` | **Scan history** page |
| `scan_detail.html` | One saved scan as its own page |
| `about.html` | **Method & ethics** page |
| `error.html` | Friendly error page (404 etc.) |
| `icons.html` | Small SVG icons |

### JavaScript (`static/js/`) - the behaviour

| File | Job |
|---|---|
| `theme-init.js` | Applies light/dark theme before the page appears (no flash) |
| `common.js` | Shared tools: safe element builder `el()`, API caller `api()`, Demo/Live mode, theme, pop-up messages, mobile menu |
| `search.js` | **Smart search**: detects input type, `/` keyboard shortcut |
| `scan_form.js` | Analysis pages: demo chips, authorisation check, progress animation, sends the scan |
| `render.js` | Draws a scan result: gauge, certainty bar, 5 tabs, findings, actions, history tables |
| `graph.js` | Draws the relationship graph with Cytoscape.js |
| `dashboard.js` | Overview page: sample cards, numbers, the four-chart figure carousel, recent scans |
| `case_graph.js` | Investigation graph page: pick scans and merge them |
| `history.js` | History page: list, filter, delete |
| `scan_detail.js` | Loads and shows one saved scan |

---

## 4. The screen layout

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │      Demo mode: every result is fictional … Nothing real is queried.  Learn more  ✕ │ ← red mode banner
 ├──────────────────────────────────────────────────────────────────────────────┤
 │                       Worried about a breach? | Scan history | Method | Graph │ ← links bar
 │  ⊕ RECONLENS   Overview  Investigate ▾  Graph  History  Method   🔍 [Demo|Live] ☾ [Start investigating →] │ ← white navbar (sticks to the top)
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ ░░░ red / black curved-light HERO: big white heading, search or form ░░░░░░░ │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │ ███ black content bands: results, graph, tables, charts ███████████████████ │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │  black footer: brand, module links, project details                          │
 └──────────────────────────────────────────────────────────────────────────────┘
   on tablets and phones the navbar links move into a slide-out menu (☰)
```

**Design language.** The look follows modern enterprise-security websites: a white
navigation bar, one strong **signal red** for actions, deep **black** sections, heroes lit by
red and teal **curved light bands**, **frosted-glass** cards and very large, bold headings.
Red is used for actions and risk, so the eye always lands on what matters.

- **Red mode banner** - always says whether the data is fictional (Demo, red) or real (Live,
  dark orange). It can be closed for the session and comes back when the mode changes.
- **Investigate ▾ menu** - opens the four modules, each with a one-line description.
- **Demo / Live switch** - remembered in the browser.
- **Theme button (☾)** - dark is the default; a light theme is available and remembered.
- **Search (🔍 or the `/` key)** - opens a search strip under the navbar on every page; on the
  Overview it jumps to the big search box.
- **Start investigating →** - the red call-to-action, jumps to the Overview search.

---

## 5. Screen by screen - how each one works

### 5.1 Overview page (`/`)

What you see, from top to bottom:

1. **Hero** (red curved light): the ReconLens lockup, the huge question *"What does the
   internet already know about you?"* and a white **search box** with a red **Investigate**
   button. Under it, **"Detected type"** pills (Domain / Email / IP-URL / Username) light up
   as you type; click another pill to override.
2. **Frosted-glass sample strip** - eight fictional sample investigations in columns (red
   type label, bold target, arrow). One click runs it (switches to Demo mode automatically).
3. **"One map of everything public about a target"** - four big key numbers (scans stored,
   average exposure, entities mapped, links between scans) and four **module cards**.
4. **"Turning public data into defensive action"** - the method in one paragraph and the red
   **pill strip**: Passive only · Certainty labels · Transparent score · Privacy by design ·
   Offline demo mode.
5. **"Exposure at a glance"** - a **figure carousel**: four charts, each on a white figure card
   inside a red/teal frame - recent scores, certainty of all findings, scans by exposure
   level, scans by module. Use the red bar indicators, click a dimmed side card, swipe, or
   use the arrow keys.
6. **Recent scans** table.

How it works: `dashboard.js` calls **three API requests at the same time**
(`/api/stats`, `/api/scans?limit=10`, `/api/graph?limit=20`) and fills in the numbers and
charts when they arrive.

### 5.2 Smart search (`search.js`)

You type one value; the code decides the module:

| You type | Detected as | Goes to |
|---|---|---|
| `alice@demo-corp.test` | Email | `/email` |
| `https://…` or `8.8.8.8` | IP / URL | `/reputation` |
| `demo-corp.test` | Domain | `/domain` |
| `demo_analyst` | Username | `/username` |

It then opens that module's page with the value filled in, and the scan starts automatically
(in Live mode it first asks you to tick the authorisation box). The server has the same
detection rules (`POST /api/detect`, `POST /api/scan/auto`), so browser and API agree.

### 5.3 The four analysis pages (`/domain`, `/username`, `/email`, `/reputation`)

All four use the **same form** (`macros.html` + `scan_form.js`). The top of the page is a red
hero: the module name and explanation on the left, the form in a **frosted-glass card** on the
right. Results appear in the black band underneath ("Results appear here" until you run a scan).

1. A short explanation of what the module checks and **which sources** it uses.
2. An input box and a **Run analysis** button.
3. **Demo mode:** clickable chips with the fictional demo targets.
   **Live mode:** the chips are replaced by the **authorisation statement** checkbox:
   *"I own this domain or have explicit permission to assess it…"*
4. When you press Run:
   - empty input → "Enter a value to analyse."
   - Live mode without the tick → "Tick the authorisation statement…" (the request is not even sent)
   - otherwise a **progress animation** shows the steps *Validating input → Collecting public
     intelligence → Correlating entities → Scoring exposure*
5. The page sends `POST /api/scan/<type>` with `{target, mode, authorized}`.
6. When the answer arrives, `render.js` draws the result and a pop-up says
   *"Scan #5 saved - exposure score 56."*
7. If the server refuses (bad input, not a demo target…), its message appears in red under
   the input box.

### 5.4 The result screen (`render.js`) - the most important screen

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │   ╭──────╮    demo-corp.test                                                │
 │  ╱   56   ╲   [Demo data] Domain intelligence · Scan #1 · completed · <1 ms │
 │  High exposure                                                              │
 │               How certain are these results?                                │
 │               ████████████████████████████████  Confirmed 21 · Inconcl. 0 … │
 │               [Download PDF] [Download CSV] [Add to graph] [Open as page]   │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │  Overview | Relationship graph (33) | Findings (21) | What to do next (13) | Limitations │
 └─────────────────────────────────────────────────────────────────────────────┘
```

**Top summary:**

- **Exposure gauge** - a half-circle that fills up to the score, coloured by level
  (green Low → amber Moderate → orange High → red Critical).
- **Certainty bar** - one coloured bar split into Confirmed / Inconclusive / Not found / Error.
  This is our "honesty bar": it shows at a glance how much of the result is solid.
- **Buttons** - PDF, CSV, add this scan to the investigation graph, open as its own page.

**The five tabs:**

| Tab | What it shows |
|---|---|
| **Overview** | Top 6 risk indicators (sorted by severity); mini graph statistics; the status and time of every source; **"How the score of 56 was calculated"** table (finding, severity, +points) |
| **Relationship graph** | The interactive map (next section) |
| **Findings** | Grouped by source (Registration data, DNS, Certificate transparency, TLS…). Each finding shows title, value, severity badge, certainty pill, source name, time and a **"view source"** link to check it yourself. Tables (DNS records, subdomains) are expandable. Username results are shown in three columns: **Profile found / Inconclusive / Not found**. Reputation results include a doughnut chart of vendor verdicts. |
| **What to do next** | Recommendations ordered by priority (High → Medium → Low → Baseline), each with a **"Because: …"** line naming the finding that caused it |
| **Limitations** | Honest notes about what this scan cannot know |

Tabs can also be switched with the arrow keys (accessibility).

### 5.5 The relationship graph (`graph.js`, Cytoscape.js)

**🗣 Say it like this:** *"Lists are hard to read. The graph shows the whole footprint as a
map: the target in the middle and everything connected to it around it."*

- **Layout - "radar":** the scanned target sits in the **centre**; directly connected things
  form a **ring** around it, grouped by type; second-level things (like the email provider
  behind a mail server) sit **outside** their parent.
- **Colour and shape = type** (14 types): IP address, subdomain, server, organisation,
  third-party service, TLS certificate, breach, exposed data type, risk issue, verdict…
- **Risky nodes** get a red / orange / yellow outline by severity.
- **Click a node** → its neighbours are highlighted, everything else fades, and a side
  panel shows the type, details, all its links, and which scans found it.
- **Click a legend item** → hides or shows that type (e.g. hide all subdomains).
- **Toolbar:** Fit to screen · Re-arrange · Show link labels · **Export PNG** (for your report).

Example for `demo-corp.test`: **33 entities, 33 relationships** - IPs, nameservers, mail
servers, the email provider, SaaS tools, 13 subdomains (risky ones like `vpn` and `dev`
highlighted), the certificate authority and the risk issues.

### 5.6 Investigation graph page (`/graph`, `case_graph.js`)

This is the **correlation** feature.

1. The left panel lists saved scans with tick boxes (the 8 newest are ticked).
2. Ticking or unticking calls `GET /api/graph?ids=1,2,3`.
3. The backend merges the scans; the page shows how many scans, entities, relationships,
   **shared entities** and risky entities there are.
4. Shared entities are drawn with a **double ring** - they are the links between investigations.
   This view uses a force-directed ("cose") layout so connected clusters pull together.

**Example:** merge `demo-corp.test` + `alice@demo-corp.test` + `phish-login.demo-corp.test`
→ **50 entities**, and all three meet at **`demo-corp.test`**. The tool shows that a breached
employee address and a phishing site both relate to the same organisation.

### 5.7 Scan history (`/history`) and scan detail (`/scan/<id>`)

- History lists every saved scan (newest first): number, module, target, mode, exposure
  score and level, number of findings, and date.
- Filter buttons by module, plus a text filter by target.
- Clicking a **target** opens the full result as its own page; **Delete** removes the scan
  after a confirmation (data minimisation).

### 5.8 Method & ethics (`/about`)

Explains the sources, the certainty labels, the scoring formula and the ethical rules inside
the app itself, so any user (or examiner) can read them.

---

## 6. How frontend and backend talk - one full example

What happens when you click the sample card **`demo-corp.test`** on the Overview page:

```
 BROWSER (frontend)                                   SERVER (backend)
 ──────────────────                                   ────────────────
 1. dashboard.js: card clicked → make sure Demo mode
 2. search.js: go to /domain?target=demo-corp.test&run=1
 3. ─────────────── GET /domain ────────────────────►  page_routes.py fills domain.html
 4. ◄────────────── HTML shell ─────────────────────
 5. scan_form.js: sees ?target=…&run=1, fills the box,
    removes the value from the address bar, presses Run
 6. Progress animation starts
 7. ─── POST /api/scan/domain {"target":"demo-corp.test","mode":"demo"} ──►
                                                      8. rate limit → validate → demo check
                                                      9. collectors (demo data) → findings
                                                     10. score 56 → 13 recommendations
                                                     11. save to SQLite → build graph
 12. ◄──── 201 {"ok":true,"scan":{… score, findings, graph …}} ────
 13. render.js draws gauge, certainty bar, tabs
 14. graph.js draws the 33-node map when the Graph tab is opened
 15. Pop-up: "Scan #1 saved - exposure score 56."
```

**🗣 Say it like this:** *"The browser never does the analysis itself. It only sends one
JSON request and draws the JSON answer. All the logic and all the safety checks are on the
server."*

---

## 7. Frontend security

| Rule | Why |
|---|---|
| Data from sources is always inserted as **text** (`textContent` through `el()`), never as HTML | A malicious DNS record like `<script>…` is shown as harmless text → no cross-site scripting (XSS) |
| Links only allowed if they start with `http://`, `https://` or `/` | Blocks `javascript:` links hidden in data |
| External links open with `rel="noopener noreferrer"` | The opened site cannot control our tab |
| **No inline scripts**; all JS is in files; server sends a strict **Content-Security-Policy** | Even if HTML were injected, the browser would refuse to run it |
| No outside CDNs - libraries and fonts are served locally | Works offline and no third party can change our code |
| Authorisation tick checked in the browser **and again on the server** | The browser check is for the user; the server check is the real protection |

---

## 8. Usability and design choices

- **Plain language** labels ("How certain are these results?", "What to do next").
- **Colour + text together** - a severity is never shown by colour alone (helps colour-blind users).
- **Light and dark themes**; charts and graph redraw in the right colours when you switch.
- **Responsive** - on tablets and phones the navbar links move into a slide-out menu; tables scroll.
- **Accessibility** - "Skip to content" link, ARIA labels on charts and gauge, keyboard tabs,
  pop-up messages read out by screen readers.
- **Mode banner** always visible, so demo data is never mistaken for real data.

---

## 9. Class demo script (about 7 minutes)

**Before class:** run `run_tests.bat` (expect `132 passed`), delete `database/osint.db` for an
empty history, start `run.bat`, keep the switch on **Demo**, keep one PDF downloaded as backup.

| Time | Do this | Say this |
|---|---|---|
| 0:00 | Show the Overview page | "ReconLens shows what the internet already knows about an organisation - safely, with public data only." |
| 0:30 | Type `alice@demo-corp.test` in the big box, point at the **Email** pill | "Smart search detects the type automatically." |
| 0:45 | Click the sample card **`demo-corp.test`** | "This is a fictional, weakly configured company." |
| 1:00 | Point at the **gauge (56, High)** and the **certainty bar** | "56 out of 100. The bar shows all 21 results are confirmed - nothing guessed." |
| 1:30 | **Overview tab** → scroll to "How the score was calculated" | "Every point comes from one confirmed finding: 4 medium problems × 10, 4 low × 4." |
| 2:15 | **Relationship graph tab** → click the `vpn` subdomain | "The target is in the middle. Red outlines are risks - a VPN host visible in public certificate logs." |
| 3:00 | **Findings tab** → open the DNS records table, click "view source" | "Every finding has its source and time, so anyone can verify it." |
| 3:30 | **What to do next** tab | "Each problem becomes a concrete fix, ordered by priority, with the reason." |
| 4:00 | Click **Download PDF report** | "The same results as a report for the owner." |
| 4:30 | Back to Overview → run `secure-shop.test` | "A well-configured company scores 0. The tool also recognises good security." |
| 5:00 | Run samples `alice@demo-corp.test` and `phish-login.demo-corp.test` | "A breached employee email, and a phishing site." |
| 5:45 | Open **Investigation graph** | "Three separate scans… and they all meet at one node: demo-corp.test. That is correlation." |
| 6:30 | Flip to **Live**, show the authorisation checkbox (do not run) | "Live mode only works after this statement, and the server enforces it." |
| 7:00 | Open **Method & ethics** | "Passive only, honest labels, transparent score, privacy by design." |

**If the internet works and you want one live moment:** Live mode → Domain → `example.com`
(reserved for documentation) or Email → `account-exists@hibp-integration-tests.com`
(HIBP's official test address). Tick the statement and run.

---

## 10. Likely viva questions about the frontend

**Q: Why does it look like a security company's website?**
We followed the design language of modern enterprise-security sites (white navigation, signal
red, black sections, bold headings) so the dashboard feels familiar and professional to
security users. The branding, logo and content are our own.

**Q: Why no React or Angular?**
The UI is small. Plain JavaScript is easier to explain, needs no build step, loads fast,
works offline and keeps the security policy strict.

**Q: How do you prevent XSS when you display data from the internet?**
All external data is inserted as text, never as HTML, links are filtered, and the
Content-Security-Policy blocks any script that is not our own file.

**Q: How does the page get its data?**
The `api()` helper in `common.js` uses `fetch()` to call our JSON API and turns server
errors into readable messages.

**Q: How is the graph drawn?**
With Cytoscape.js. The backend sends nodes and edges as JSON; `graph.js` places the target
in the centre with a radar layout and adds colours, shapes, click details, filters and PNG export.

**Q: What happens if a user skips the authorisation tick using the browser console?**
Nothing - the server checks `"authorized": true` again and returns 403.

**Q: Does it work on a phone?**
Yes - the layout is responsive; the navigation becomes a slide-out menu and the carousel can be swiped.

**Q: Where are the Demo/Live choice and theme stored?**
In the browser's local storage. If storage is blocked, the app falls back to Demo mode and
the system theme.
