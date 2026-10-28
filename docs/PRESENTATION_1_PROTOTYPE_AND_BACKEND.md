# ReconLens - Part 1: The Prototype and the Backend (explained simply)

*OSINT-Based Dashboard for Digital Footprint Analysis and Cybersecurity*
*Team: Aryan Sharma (2024A1R101), Varun Sharma (2024A1R107) · B.E. Computer Science · MDC Cybersecurity*

> **How to use this file in class.** Each section starts with the idea in plain words, then
> shows how we built it. Lines marked **🗣 Say it like this** are short sentences you can
> say out loud. Part 2 (`PRESENTATION_2_FRONTEND_AND_DEMO.md`) covers the screens and the
> live demo script.

---

## 1. The project in one minute

**🗣 Say it like this:** *"Every organisation and every person leaves traces on the internet:
domain records, email servers, old subdomains, social media accounts, leaked passwords.
Attackers collect these traces before they attack. ReconLens collects the same public
information first, so the owner can see their exposure and fix it before an attacker uses it."*

You type **one thing** (a domain, an email, an IP/URL or a username). ReconLens:

1. works out what kind of input it is,
2. asks trusted **public** sources about it,
3. labels every result by **how certain** it is,
4. draws a **relationship graph** of everything it found,
5. gives an **exposure score from 0 to 100**,
6. lists **what to fix**, in priority order,
7. saves everything and exports a **PDF / CSV report**.

---

## 2. Key words, in simple language

| Word | Simple meaning |
|---|---|
| **OSINT** | *Open-Source Intelligence* - information anyone can legally get from public sources (DNS, public profiles, breach databases). No hacking. |
| **Digital footprint** | All the traces a person or organisation leaves online. |
| **Passive** | We only *read* public data. We never attack, log in, scan ports or try passwords. |
| **Exposure** | How much useful information an attacker could find about you. |
| **Domain** | A website name, e.g. `example.com`. |
| **DNS** | The internet's phone book: turns `example.com` into an IP address and lists mail servers. |
| **RDAP / WHOIS** | Public registration records of a domain: registrar, created date, expiry date. |
| **Certificate Transparency (CT)** | Every HTTPS certificate is logged publicly. These logs reveal subdomain names like `dev.example.com`. |
| **SPF / DMARC** | DNS records that stop criminals sending fake emails "from" your domain. |
| **Data breach** | When a website is hacked and its user data (emails, passwords) leaks. |
| **API** | A way for one program to ask another program for data. |
| **Backend** | The server-side program (Python). It does the real work. |
| **Frontend** | What you see in the browser (HTML, CSS, JavaScript). |

---

## 3. The problem we solve

- Attacks such as phishing start with **reconnaissance** - collecting public information.
- Most small organisations and students **never check** what is visible about them.
- Existing OSINT tools are command-line tools for experts, show raw data, and often do not
  say **how reliable** a result is.

**Our goal:** a simple, safe, honest dashboard that shows exposure clearly, explains *why*,
and tells you *what to do* about it.

---

## 4. What the prototype can do (features)

| Module | What you type | Sources asked | What you learn |
|---|---|---|---|
| **Domain intelligence** | `example.com` | RDAP (WHOIS backup), DNS, crt.sh, TLS certificate | Registrar, age, expiry, transfer lock, DNSSEC, hosting IPs, mail servers, SPF/DMARC, CAA, SaaS tools used, subdomains, HTTPS certificate health |
| **Username footprint** | `demo_analyst` | 19 public platforms (GitHub, GitLab, Reddit, PyPI, Chess.com …) | Where the same handle exists; whether it is reused |
| **Email exposure** | `alice@company.com` | Have I Been Pwned (HIBP) | Which breaches leaked the address and what data leaked |
| **IP / URL reputation** | `1.2.3.4` or `https://…` | VirusTotal | How many security vendors flag it as malicious |

On top of the modules:

- **Smart search** - type anything; the app detects the type.
- **Relationship graph** - every entity becomes a node, every relation a line.
- **Investigation graph** - merges several scans; shared entities link them (correlation).
- **Exposure score (0-100)** with a full, visible calculation.
- **Recommendations** in priority order.
- **Scan history**, **PDF and CSV reports**.
- **Demo mode** - fully offline with fictional `.test` data, safe for a classroom.

---

## 5. Methodology (how we approached the project)

### 5.1 Research approach - build and evaluate a prototype

We followed a **prototype-based (design-science) approach**:

1. **Study the problem** - how attackers do reconnaissance; which public sources exist.
2. **Pick safe, legal, reliable sources** - official APIs and public records only.
3. **Design** the architecture and a common data format.
4. **Build** in small iterations (one module at a time).
5. **Test** every part automatically (132 tests) and manually (test plan).
6. **Evaluate** with clear measures: pass rate, response time, report completeness.

### 5.2 The OSINT intelligence cycle (the core method)

Our backend follows the classic intelligence cycle. Every scan goes through the same five stages:

```
  1. PLAN        2. COLLECT          3. PROCESS            4. ANALYSE              5. REPORT
  ---------      -------------       ----------------      -------------------     ---------------
  What is the    Ask each public     Turn every answer     Score the exposure,     Show on screen,
  target? Is it  source, in          into one standard     build the graph,        save to database,
  allowed?       parallel            "Finding" + label     pick recommendations    export PDF / CSV
                                     its certainty
```

**🗣 Say it like this:** *"Our method is the standard intelligence cycle: plan, collect,
process, analyse and report. Each stage is a separate part of our code."*

| Cycle stage | Where it lives in our code |
|---|---|
| Plan | `services/validation.py` (what is the input?) + `routes/common.py` (is it allowed?) |
| Collect | `collectors/*.py` (one file per source) |
| Process | `collectors/base.py` - the common **Finding** format |
| Analyse | `services/scoring.py`, `services/recommendations.py`, `services/graph.py` |
| Report | `database/db.py`, `services/report.py`, the frontend |

### 5.3 Five design principles

1. **Passive and legal** - read public data only; never attack or log in.
2. **Honest certainty** - every result is labelled *Confirmed*, *Not found*,
   *Inconclusive* or *Error*. A blocked request is **never** counted as "found".
3. **Transparent scoring** - simple points anyone can check; no hidden AI.
4. **Ethics by design** - authorisation checkbox, email masking, data deletion, demo mode.
5. **Modular** - adding a new source = writing one new file.

### 5.4 Development methodology

- **Iterative / incremental model** - first a working domain module, then usernames,
  email, reputation, then graph, TLS and smart search (version 2).
- **Test-driven checks with mocks** - tests replace the internet with fake answers, so they
  run offline in about 2 seconds and never touch real targets.

---

## 6. Technology used, and why

| Technology | Used for | Why we chose it |
|---|---|---|
| **Python 3.10+** | All backend code | Easy to read, great libraries for networking |
| **Flask** | Web server and API | Small and simple; perfect for a prototype |
| **SQLite** | Database | Built into Python, no server to install, one file |
| **requests** | Calling web APIs | The standard Python HTTP library |
| **dnspython** | DNS lookups | Reads any DNS record type |
| **Flask-Limiter** | Rate limiting | Stops abuse / too many scans |
| **python-dotenv** | Reads `.env` settings | Keeps API keys out of the code |
| **ReportLab** | PDF reports | Creates PDFs directly from Python |
| **pytest** | Automated tests | Simple, popular test framework |
| HTML, CSS, JavaScript, Chart.js, Cytoscape.js | Frontend | See Part 2 |

---

## 7. The architecture (big picture)

The backend is built in **layers**. Each layer has one job and only talks to the layer next to it.

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  BROWSER  (frontend: pages, charts, graph)                           │
 └───────────────▲──────────────────────────────────┬───────────────────┘
                 │ JSON answer                      │ request (JSON)
 ┌───────────────┴──────────────────────────────────▼───────────────────┐
 │  1. ROUTES  (routes/*.py)      "the reception desk"                  │
 │     check JSON, rate limit, validate input, check authorisation      │
 └───────────────────────────────────┬──────────────────────────────────┘
 ┌───────────────────────────────────▼──────────────────────────────────┐
 │  2. SERVICES  (services/*.py)  "the manager"                         │
 │     run the scan, score, recommend, build graph, make reports        │
 └──────────────┬────────────────────────────────────┬──────────────────┘
 ┌──────────────▼───────────────────┐   ┌────────────▼──────────────────┐
 │ 3. COLLECTORS (collectors/*.py)  │   │ 4. DATABASE (database/db.py)  │
 │   "the field agents"             │   │   SQLite file osint.db        │
 │   one per public source          │   │   tables: scans, findings     │
 └──────────────┬───────────────────┘   └───────────────────────────────┘
 ┌──────────────▼───────────────────────────────────────────────────────┐
 │  PUBLIC SOURCES: RDAP/WHOIS · DNS · crt.sh · TLS · 19 platforms ·     │
 │                  Have I Been Pwned · VirusTotal   (or demo data)      │
 └──────────────────────────────────────────────────────────────────────┘
```

**🗣 Say it like this:** *"Think of it like an office. Routes are the reception desk that
checks who you are. Services are the manager who plans the job. Collectors are field
agents who each visit one public source. The database is the filing cabinet."*

---

## 8. The journey of one scan - step by step

Example: you scan the demo domain **`demo-corp.test`**.

| Step | What happens | File |
|---|---|---|
| 1 | The browser sends `POST /api/scan/domain` with `{"target": "demo-corp.test", "mode": "demo"}` | frontend |
| 2 | **Rate limit check** - max 10 scans per minute per computer | `extensions.py` |
| 3 | **JSON check** - the request must be JSON (blocks some web attacks) | `routes/common.py` |
| 4 | **Validation** - is it a real-looking domain? Cleaned to lower case | `services/validation.py` |
| 5 | **Mode rules** - demo mode only accepts fictional demo targets; live mode needs the "I am authorised" tick | `routes/common.py` |
| 6 | **Choose collectors** - a domain needs RDAP, DNS, crt.sh and TLS | `services/scan_service.py` |
| 7 | **Collect in parallel** - all 4 collectors run at the same time, each with its own time limit | `scan_service.py` |
| 8 | **Standardise** - every answer becomes a *Finding* with a certainty label | `collectors/base.py` |
| 9 | **Score** - add points for confirmed problems → **56 / 100, High** | `services/scoring.py` |
| 10 | **Recommend** - each problem maps to a fix → 13 actions | `services/recommendations.py` |
| 11 | **Save** - one row in `scans`, 21 rows in `findings` | `database/db.py` |
| 12 | **Build graph** - 33 entities, 33 relationships | `services/graph.py` |
| 13 | **Reply** - the whole result goes back to the browser as JSON (HTTP 201) | `routes/common.py` |
| 14 | The browser draws the gauge, graph, findings and actions | frontend |

---

## 9. Each backend part explained

### 9.1 `app.py` - the starting point

- Creates the Flask app (`create_app()`), loads settings, connects the database and
  registers all routes.
- Adds **security headers** to every response (explained in section 11).
- Turns every error into a clean message (JSON for the API, a friendly page for the browser).
- Masks email addresses in all log lines.
- Starts the server on `127.0.0.1:5000` - **only this computer** can open it.

### 9.2 `config.py` and `.env` - the settings

All settings come from a `.env` file, so secrets like API keys are **never written in the
code**. Examples: `HIBP_API_KEY`, `VIRUSTOTAL_API_KEY`, `ALLOW_LIVE_MODE`,
`SCAN_RATE_LIMIT=10 per minute`, `RETENTION_DAYS=30`, timeouts.

### 9.3 Routes - the API (the reception desk)

| Method + address | What it does |
|---|---|
| `POST /api/scan/domain`, `/username`, `/email`, `/reputation` | Run a scan |
| `POST /api/scan/auto` | Smart search: detect the type, then run that scan |
| `POST /api/detect` | Only say what type an input is |
| `GET /api/scans` | Scan history |
| `GET /api/scans/<id>` | One full scan |
| `DELETE /api/scans/<id>` | Delete a scan |
| `GET /api/scans/<id>/report.pdf` / `.csv` | Download reports |
| `GET /api/graph?ids=1,2,3` | Merged investigation graph |
| `GET /api/stats`, `/api/health`, `/api/demo-targets` | Numbers for the overview page, server status, demo list |

All four scan routes share **one** function, `handle_scan()` in `routes/common.py`, so every
module has exactly the same safety checks.

### 9.4 Input validation - the gatekeeper (`services/validation.py`)

We use **allow-lists**: we describe what *good* input looks like and reject everything else.

| Input | Rule |
|---|---|
| Domain | Letters, digits, hyphens, dots; valid ending (TLD); max 253 chars; URLs are cut down to the host name; international names converted (e.g. `bücher.de` → `xn--bcher-kva.de`) |
| Username | 2-39 chars: letters, digits, `.`, `_`, `-` |
| Email | Exactly one `@`, valid local part, valid domain |
| IP / URL | Only **public** IPs; only `http://` or `https://` URLs |

Blocked examples: `<script>alert(1)</script>`, `192.168.1.10` (private), `ftp://…`,
`javascript:…`. This prevents injection attacks and stops the tool being used to reach
internal systems.

**Smart search detection** (same rules in the browser and the server):

```
contains name@host.tld        → email
starts with http(s):// or IP  → IP / URL reputation
name.with.dots                → domain
anything else handle-shaped   → username
```

### 9.5 The scan service - the manager (`services/scan_service.py`)

- Picks collectors for the scan type:
  domain → 4 collectors, username → 1, email → 1, reputation → 1.
- Runs them **in parallel** with a thread pool - so the scan takes as long as the
  *slowest* source, not the sum of all sources.
- Joins all findings, then calls scoring, recommendations and adds the **limitations**
  (honest notes about what the scan cannot know).
- Sets the overall status: **completed** (all sources fine), **partial** (some failed),
  **failed** (all failed).

### 9.6 Collectors - the field agents

Every collector follows the same contract (`collectors/base.py`). It receives a target and
returns a list of **Findings**. If a source fails, `run()` catches the error and returns an
"error" finding instead - **one broken source never crashes the whole scan.**

**The Finding - our standard format.** Every piece of information from every source looks the same:

```
module      dns
source      DNS (public resolver)
code        DNS_DMARC_MISSING            ← machine code used for scoring & advice
title       DMARC (Domain-based Message Authentication)
value       No DMARC record at _dmarc …
status      confirmed                    ← HOW SURE we are
severity    medium                       ← HOW BAD it is
source_url  https://dns.google/…         ← proof link
collected_at 2026-10-27T10:15:00+00:00   ← when
```

**The four certainty labels** (our most important honesty rule):

| Status | Meaning |
|---|---|
| **Confirmed** | The source clearly reported it |
| **Not found** | The source answered and clearly said "nothing" |
| **Inconclusive** | We could not tell (blocked, rate-limited, CAPTCHA, redacted) |
| **Error** | The source failed (timeout, network problem) |

**The seven collectors:**

| Collector | How it works (simple) | Example findings |
|---|---|---|
| **RDAP** (`rdap_collector.py`) | Looks up which registry handles the domain ending (IANA list), asks that registry's RDAP server. If the country has no RDAP, falls back to classic WHOIS (port 43). | Registrar, created date, expiry soon, no transfer lock, DNSSEC off, registrant details public |
| **DNS** (`dns_collector.py`) | Asks for A, AAAA, CNAME, MX, NS, TXT, CAA, SOA records and the `_dmarc` record. | Hosting IPs, mail provider, SPF missing/weak, DMARC missing, no CAA, SaaS tools revealed by TXT tokens |
| **crt.sh** (`crtsh_collector.py`) | Searches public certificate logs for `%.domain`. | Subdomain list; *sensitive-looking* names like `dev.`, `vpn.`, `admin.`; wildcard certificates; certificate authorities |
| **TLS** (`tls_collector.py`) | Makes **one** normal HTTPS handshake (like a browser) and reads the certificate. Refuses private IPs. | Issuer, valid until, expired, expires within 14 days, untrusted (self-signed) |
| **Username** (`username_collector.py`) | Visits the public profile URL on 19 platforms (6 at a time). 200 = found, 404 = not found, 403/429/CAPTCHA/login page = inconclusive. | Profile found on GitHub…; "same username reused on many platforms" (5+) |
| **HIBP** (`hibp_collector.py`) | Calls Have I Been Pwned API v3 with the email. | Each breach, date, leaked data types; passwords leaked = high |
| **VirusTotal** (`vt_collector.py`) | Reads the **existing** report for a domain/IP/URL. Never submits new URLs (that would make them public). Local guard keeps to 4 requests/minute. | Malicious by 7 of 92 engines, suspicious, clean, vendor categories |

**Demo mode** (`collectors/demo_data.py`) returns realistic but **fictional** results for
`.test` targets, using the exact same Finding format, so everything after the collectors
works identically.

### 9.7 Scoring - the exposure score (`services/scoring.py`)

A simple formula anyone can check by hand:

```
score = sum of points of CONFIRMED findings, capped at 100

points:   high = 20    medium = 10    low = 4    info = 0

level:    0-19 Low   |   20-49 Moderate   |   50-74 High   |   75-100 Critical
```

Inconclusive, not-found and error results give **0 points**: *we never increase the score
using data we could not verify.*

**Worked example - `demo-corp.test`:**

| Confirmed problem | Severity | Points |
|---|---|---|
| Registration expires soon | medium | 10 |
| DMARC missing | medium | 10 |
| Sensitive-looking subdomains discoverable | medium | 10 |
| TLS certificate expires soon | medium | 10 |
| No transfer lock | low | 4 |
| DNSSEC not enabled | low | 4 |
| Registrant contact details public | low | 4 |
| SPF neutral (`?all`) | low | 4 |
| **Total** | | **56 → High** |

The well-configured `secure-shop.test` scores **0 (Low)**.

**🗣 Say it like this:** *"We did not use a black-box AI score. Every point can be traced
to one confirmed finding, and the table is shown on screen and in the PDF."*

### 9.8 Recommendations (`services/recommendations.py`)

A rule table maps each problem code to a fix and a priority (High / Medium / Low), plus
"baseline" good-practice advice for every scan type. Examples:

| Problem code | Recommendation |
|---|---|
| `DNS_DMARC_MISSING` | Publish a DMARC policy (start with `p=none`, then move to `p=reject`) |
| `TLS_EXPIRY_SOON` | Renew the certificate and automate renewal (e.g. Let's Encrypt) |
| `HIBP_BREACH_PASSWORDS` | Change the leaked password everywhere it was reused; use a password manager |
| `USERNAME_REUSE` | Use different handles for professional and personal accounts |
| `VT_MALICIOUS` | Do not visit or enter credentials; investigate |

Each recommendation also says **"Because: …"** - which finding triggered it.

### 9.9 The relationship graph (`services/graph.py`)

- Every entity becomes a **node** with an ID like `ip:203.0.113.10` or
  `domain:demo-corp.test`. Every relation becomes an **edge**, e.g. "resolves to",
  "mail via", "subdomain", "found in breach", "issued by".
- Node types: target, domain, subdomain, IP, server, organisation, service, certificate,
  account, breach, data type, risk issue, verdict, category.
- **Correlation trick:** the same real-world thing always gets the **same ID**. So when we
  merge several scans, matching IDs automatically join together.

**Example:** scanning `demo-corp.test` (domain), `alice@demo-corp.test` (email) and
`phish-login.demo-corp.test` (reputation) gives one map of **50 entities** that meet at the
shared node **`domain:demo-corp.test`**. The tool *discovers* that three separate
investigations are about the same organisation.

The graph is calculated from saved findings each time it is requested - no extra tables needed.

### 9.10 The database (`database/schema.sql`, `database/db.py`)

SQLite, two tables, one-to-many:

```
 scans (one row per scan)                     findings (many rows per scan)
 ─────────────────────────                    ─────────────────────────────
 id  (primary key)          1 ───────── many  scan_id  (foreign key → scans.id)
 scan_type, target, mode                      module, source, code, title, value
 status, exposure_score, exposure_level       status, severity, source_url
 authorization (audit trail)                  collected_at, details_json
 started_at, completed_at, duration_ms
 modules_json, recommendations_json,
 limitations_json, scoring_json
```

- Every query uses `?` placeholders (**parameterised queries**) → no SQL injection.
- Deleting a scan deletes its findings too (`ON DELETE CASCADE`).
- **Retention policy:** scans older than 30 days are deleted automatically (at start-up
  and every time a scan is saved).
- Email targets are stored **masked**: `a***@demo-corp.test`.

### 9.11 Reports (`services/report.py`)

- **PDF** (ReportLab): score, scoring method, sources queried, every finding with source
  and time, recommendations, limitations, and appendix tables. "DEMO MODE" banner on demo reports.
- **CSV**: the same content in sections, opens in Excel.
- **Safety:** CSV cells starting with `= + - @` get an apostrophe so Excel will not run them
  as formulas (*CSV injection*). PDF text is escaped so third-party data cannot inject markup.

---

## 10. Demo mode vs Live mode

| | Demo mode | Live mode |
|---|---|---|
| Data | Fictional, generated offline | Real public sources |
| Internet needed | No | Yes |
| Allowed targets | Only the fictional demo targets (`.test`) | Any valid target |
| Extra step | None | Must tick the **authorisation statement** (checked by the server, saved with the scan) |
| Best for | Classroom, viva | Your own domain, `example.com`, HIBP test addresses |

Demo targets: `demo-corp.test` (weak), `secure-shop.test` (strong), `demo_analyst`,
`ghost_user_404`, `alice@demo-corp.test`, `bob@secure-shop.test`,
`phish-login.demo-corp.test`.

---

## 11. Security and ethics (very important for the viva)

| Risk | Our protection |
|---|---|
| Misuse against other people | Live mode requires an authorisation statement, **enforced on the server**, stored as an audit trail. `ALLOW_LIVE_MODE=false` makes a demo-only deployment. |
| Being an attack tool | Passive only: no port scans, no logins, no password guessing, no CAPTCHA bypass. |
| Reaching internal systems (SSRF) | Private/internal IPs rejected; the TLS check connects only to the public IP it verified; URLs are never opened by the app. |
| Injection attacks | Allow-list validation; parameterised SQL; frontend inserts data as text only. |
| Cross-site scripting | Content-Security-Policy: only our own scripts can run. |
| Clickjacking / sniffing | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. |
| Too many requests | Rate limits (10 scans/minute; 1000 page/API requests/hour); VirusTotal quota guard. |
| Leaking API keys | Keys only in `.env` (not in code, logs or reports). |
| Privacy of email addresses | Sent only to HIBP; masked in database, logs, reports. |
| Keeping data too long | 30-day retention, delete button, raw WHOIS never stored. |
| Exposure of the app itself | Server listens on `127.0.0.1` only. |

**🗣 Say it like this:** *"The safety checks are on the server, not only in the browser,
so they cannot be skipped by someone using the API directly."*

---

## 12. Testing

- **132 automated tests** with `pytest`, in about 2 seconds, **no internet needed**. Network
  answers are replaced by fake ("mocked") answers.
- What they cover:
  - input validation (good and bad inputs, injection attempts)
  - every collector's interpretation rules (SPF, DMARC, RDAP dates, username status codes,
    HIBP, VirusTotal, TLS expiry)
  - safeguards (authorisation required, demo-only targets, private IPs blocked, email masking,
    rate limits, CSV injection)
  - the full API, database, reports, graph and correlation
- Manual test plan: `docs/TEST_PLAN.md` (functional, invalid input, security, errors, performance).
- Run: `run_tests.bat` → `132 passed`.

---

## 13. Limitations (be honest - examiners like this)

- Only the 19 listed platforms are checked; a matching username does not prove it is the same person.
- Certificate logs show **past** certificates - a subdomain may be offline now.
- Registration data is often hidden for privacy (GDPR) - we label it, we do not guess.
- HIBP only knows breaches it has loaded; "not found" ≠ "never leaked".
- VirusTotal is vendor opinion, not proof; the free key allows 4 requests/minute.
- Email checks of real addresses need a paid HIBP key (test addresses are free).
- Single-user, local prototype (SQLite, in-memory rate limiter).

## 14. Future scope

- More sources (Shodan, GitHub code search for leaked secrets, paste sites).
- Scheduled re-scans with alerts when exposure changes.
- User accounts and teams; PostgreSQL for multi-user use.
- Look-alike (typosquatting) domain detection for phishing.
- Trend charts of the score over time.

---

## 15. Likely viva questions - short answers

**Q: Is this legal / ethical?**
Yes. It only reads public data, needs authorisation for live scans, and demo mode uses
fictional data on the reserved `.test` domain.

**Q: Why not just use one tool like Sherlock or theHarvester?**
They are expert command-line tools giving raw output. We combine several sources, label
certainty, score exposure, map relationships and give fixes in one simple dashboard.

**Q: How is the score calculated?**
Sum of points of confirmed findings (high 20, medium 10, low 4), capped at 100. Unverified
results add nothing. The breakdown is shown on screen.

**Q: What if a source is down?**
That collector returns an "error" finding; the others still work; the scan is marked "partial".

**Q: How do the scans run so fast?**
Collectors run in parallel threads, each with its own timeout.

**Q: How does correlation work?**
Every entity gets a standard ID. When scans are merged, equal IDs become one node that
links the scans.

**Q: How do you stop SQL injection?**
Allow-list validation and parameterised queries (`?` placeholders).

**Q: Why SQLite and Flask?**
Zero setup, built into Python, enough for a single-user prototype; easy to swap later.

**Q: How would you add a new source?**
Write one collector class returning Findings, add it to `COLLECTORS` in
`scan_service.py`, optionally add recommendation rules. Nothing else changes.
