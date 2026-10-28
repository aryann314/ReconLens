# ReconLens - OSINT-Based Dashboard for Digital Footprint Analysis and Cybersecurity

A web application that performs **passive, authorised OSINT** on a domain, a username, an
email address or an IP/URL. It aggregates public sources, labels every result by
certainty, **maps how the collected intelligence connects in an interactive relationship
graph**, correlates separate scans through shared entities, computes a transparent
exposure score, and produces security recommendations and PDF/CSV reports.

Team: Aryan Sharma (2024A1R101), Varun Sharma (2024A1R107)

### What's new in version 2

- **Relationship graph** (Cytoscape.js) for every scan: domains, IPs, nameservers, mail
  servers, subdomains, certificate authorities, SaaS services, accounts, breaches and risk
  issues as linked nodes. Click a node for details, hide types via the legend, export PNG.
- **Investigation graph** page: merge any stored scans into one map; entities found while
  investigating different targets become links between them (correlation).
- **SSL/TLS certificate analysis**: issuer, validity, protocol; expiring, expired and
  untrusted certificates are flagged and scored.
- **Smart search**: type anything - the type (domain / email / IP-URL / username) is
  detected and the right module runs. Press `/` to focus it from any page. The same
  detection is available to API clients: `POST /api/detect` and `POST /api/scan/auto`.
- Redesigned interface in an enterprise-security style: white top navigation with an
  Investigate menu, red/black curved-light heroes, a frosted-glass sample strip, a figure
  carousel of charts, one-click sample investigations, tabbed results
  (Overview, Graph, Findings, Actions, Limitations), light/dark theme, mobile layout.

B.E. Computer Science · Minor Discipline Course (MDC) Cybersecurity project.

| Module | Sources | Key needed? |
|---|---|---|
| Domain intelligence | RDAP (IANA bootstrap) with WHOIS fallback, DNS, crt.sh, TLS certificate | No |
| Username footprint | 19 public platforms (`collectors/sites.json`) | No |
| Email exposure | Have I Been Pwned API v3 | Paid key, **or** the free official test key for test addresses |
| IP / URL reputation | VirusTotal API v3 | Free community key |

**Demo mode** works fully offline with fictional `.test` targets, so the project can be
presented without the internet and without analysing anyone real.

---

## 1. Requirements

- Windows 10/11 (also works on Linux/macOS)
- Python **3.10 or newer**. Check with `python --version`. During installation tick
  "Add python.exe to PATH".
- ~100 MB disk space, any laptop with 4 GB RAM.
- Internet only for installation and for live lookups.

## 2. Setup on Windows

Option A - double-click **`setup.bat`**, then **`run.bat`**.

Option B - manually in Command Prompt, inside the `osint-dashboard` folder:

```bat
py -3 -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Expected terminal output:

```
  OSINT Footprint Dashboard running at  http://127.0.0.1:5000
  Press CTRL+C to stop.
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000** in your browser.

> PowerShell users: if `venv\Scripts\activate` is blocked, run
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt.

## 3. Using the dashboard

1. Keep the header switch on **Demo**.
2. On the Overview, click the sample card `demo-corp.test` (or type it in the big search box).
3. Read the exposure gauge and certainty bar, then use the tabs: **Overview** (top risks,
   score breakdown), **Relationship graph**, **Findings**, **What to do next**, **Limitations**.
   Click **Download PDF report**.
4. Run the samples `alice@demo-corp.test` and `phish-login.demo-corp.test`, then open
   **Investigation graph**: all three scans meet at the shared node `demo-corp.test`.
5. Compare with `secure-shop.test` (well configured, score 0).
6. **Scan history** lists stored scans; filter, open or delete any of them.

### Live lookups

Switch the header to **Live lookups**. An authorisation statement appears; you must tick
it (the server also enforces this). Only analyse assets you own or are authorised to assess.

| What to try live | Needs |
|---|---|
| Your own domain, or `example.com` (reserved for documentation, RFC 2606) | Nothing |
| Your own username | Nothing |
| `account-exists@hibp-integration-tests.com`, `multiple-breaches@hibp-integration-tests.com` | Nothing - uses HIBP's official test key |
| Your own email address | `HIBP_API_KEY` (paid) in `.env` |
| Any public domain / IP / URL reputation | `VIRUSTOTAL_API_KEY` (free account at virustotal.com) in `.env` |

After editing `.env`, stop the server (CTRL+C) and start it again.

## 4. Running the tests

```bat
venv\Scripts\activate
python -m pytest -v
```

or double-click `run_tests.bat`. The suite (132 tests) uses mocked network responses, so it
needs no internet and never queries real targets. Expected last line:
`132 passed in ...s`.

## 5. Project structure

```
osint-dashboard/
├── app.py                    Flask application factory, security headers, error handlers
├── config.py                 Settings loaded from .env (keys, timeouts, rate limit, retention)
├── extensions.py             Rate limiter (Flask-Limiter) shared by the routes
├── .env.example              Template for .env (copy it; never commit .env)
├── requirements.txt          Pinned Python dependencies
├── setup.bat / run.bat / run_tests.bat   Windows helpers
├── database/
│   ├── schema.sql            Tables: scans, findings
│   └── db.py                 SQLite helpers (parameterised queries, retention purge)
├── collectors/               One file per OSINT source - all return the same Finding format
│   ├── base.py               Finding / CollectorResult / BaseCollector (timeouts, errors)
│   ├── rdap_collector.py     RDAP via IANA bootstrap + WHOIS port-43 fallback
│   ├── dns_collector.py      DNS records, SPF, DMARC, CAA, SaaS footprint
│   ├── crtsh_collector.py    Certificate transparency subdomains
│   ├── username_collector.py Username checks, confirmed / not found / inconclusive
│   ├── sites.json            Curated platform list for username checks
│   ├── hibp_collector.py     Have I Been Pwned breaches
│   ├── vt_collector.py       VirusTotal reputation (+ local 4/min quota guard)
│   ├── tls_collector.py      TLS certificate via one HTTPS handshake (SSRF-safe)
│   └── demo_data.py          Fictional fixtures for safe demo mode
├── services/
│   ├── validation.py         Allow-list input validation, email masking
│   ├── scan_service.py       Runs collectors in parallel, builds the scan result
│   ├── scoring.py            Transparent 0-100 exposure score
│   ├── recommendations.py    Finding code -> defensive action rules
│   ├── graph.py              Findings -> nodes/edges; merges scans into a case graph
│   └── report.py             PDF (ReportLab) and CSV export
├── routes/
│   ├── common.py             Shared scan handler: JSON check, validation, authorisation
│   ├── domain_routes.py      POST /api/scan/domain
│   ├── username_routes.py    POST /api/scan/username
│   ├── email_routes.py       POST /api/scan/email (+ email-specific policy)
│   ├── reputation_routes.py  POST /api/scan/reputation
│   ├── auto_routes.py        POST /api/detect, POST /api/scan/auto (smart search)
│   ├── scan_routes.py        history, detail, delete, stats, health, demo targets
│   ├── report_routes.py      PDF / CSV downloads
│   └── page_routes.py        HTML pages
├── templates/                Jinja2 pages (base layout, one page per module, history, about)
├── static/
│   ├── css/style.css         Responsive theme, light + dark
│   ├── js/                   common.js, search.js, graph.js, render.js, scan_form.js,
│   │                         dashboard.js, history.js, case_graph.js, scan_detail.js,
│   │                         vendor/chart.umd.min.js (Chart.js, MIT),
│   │                         vendor/cytoscape.min.js (Cytoscape.js, MIT)
│   └── fonts/                Red Hat Display, Public Sans, IBM Plex Mono (SIL OFL) - served locally
├── logs/                     app.log (rotating)
├── tests/                    pytest suite
└── docs/                     Architecture diagrams, API reference, test plan
```

Small additions to the original plan: `extensions.py`, `routes/common.py`,
`routes/reputation_routes.py`, `routes/auto_routes.py`, `routes/scan_routes.py`,
`routes/page_routes.py`,
`services/validation.py`, `services/scan_service.py`, `collectors/vt_collector.py`,
`collectors/demo_data.py`, and the `about`, `reputation`, `scan_detail` and `error` templates.

## 6. How it works (short)

Browser → `POST /api/scan/<type>` (JSON) → validation, rate limit, authorisation check →
collectors run **in parallel**, each with its own timeout → findings in one common format →
score + recommendations + limitations → saved in SQLite → turned into a relationship graph
(services/graph.py) → rendered in the browser → exported as PDF/CSV. Stored scans can be
merged into one investigation graph via `GET /api/graph`. Full diagrams: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). API reference:
[`docs/API.md`](docs/API.md). Test plan: [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

### Adding a new OSINT source

1. Create `collectors/my_collector.py` with a class extending `BaseCollector` and a
   `collect(target)` method returning `Finding` objects.
2. Add the class to `COLLECTORS` in `services/scan_service.py`.
3. Optionally add rules for its finding codes in `services/recommendations.py`.

No changes are needed in the database, UI or reports.

## 7. Security and ethical safeguards

- Passive only: no port scanning, exploitation, password attacks, logins or CAPTCHA bypass.
  The only direct contact is one standard HTTPS handshake to read the TLS certificate;
  hosts resolving to private/internal addresses are never contacted, and the connection
  goes to the exact address that was checked (no DNS-rebinding bypass).
- Live mode needs an explicit, server-enforced authorisation statement per scan; it is stored
  with the scan as an audit trail. `ALLOW_LIVE_MODE=false` makes a demo-only deployment.
- Demo mode uses only fictional data on the reserved `.test` TLD.
- Email addresses are sent only to HIBP and are stored, logged and reported masked
  (`a***@domain`) - including the console access log, where page URLs could carry them. `AUTHORIZED_EMAIL_DOMAINS` can restrict live email checks to your organisation.
- API keys only in `.env` (git-ignored); never in code, logs or reports.
- Flask-Limiter rate limit on scan endpoints (`SCAN_RATE_LIMIT`) plus a general limit on
  pages and API reads (`DEFAULT_RATE_LIMIT`); per-source timeouts; VirusTotal quota guard.
- Allow-list validation; private/internal IPs rejected; URLs are never fetched by the app.
- CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`; all third-party data rendered as text.
- CSV formula-injection protection; PDF text escaped.
- Data minimisation: retention purge (`RETENTION_DAYS`, applied at start-up and on every
  save), delete button, raw WHOIS not stored. Registrar RDAP links are followed only over HTTPS.
- Server binds to `127.0.0.1` only.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python with "Add to PATH", or use `py -3` |
| `ModuleNotFoundError: No module named 'flask'` | Activate the venv first: `venv\Scripts\activate` |
| `Address already in use` / port 5000 busy | Close the other server, or change `port=5000` at the bottom of `app.py` |
| Live domain scan: crt.sh "busy or unavailable" | crt.sh is often overloaded - retry after a minute; other sources still work |
| Every DNS record type fails | Check internet/DNS; on college Wi-Fi a captive portal may block DNS |
| Username results all "inconclusive" | The network or platforms are blocking automated requests; that is reported honestly |
| Email live: "No HIBP API key is configured" | Use a `@hibp-integration-tests.com` test address, demo mode, or add a key |
| `429 Too many requests` | Rate limit reached (default 10 scans/minute) - wait a minute |
| Charts missing | Make sure `static/js/vendor/chart.umd.min.js` exists |
| Want a fresh database | Stop the app and delete `database/osint.db` |

## 9. Demo-day checklist

- [ ] Run `run_tests.bat` the day before - all tests pass.
- [ ] Delete `database/osint.db` for an empty history, then run 3-4 demo scans so the
      overview charts have data.
- [ ] Keep the switch on **Demo data** unless the venue has reliable internet.
- [ ] For a live moment, use `example.com` (domain) and
      `account-exists@hibp-integration-tests.com` (email).
- [ ] Have one PDF report already downloaded as a backup.

## 10. Credits and licences

Chart.js (MIT), Cytoscape.js (MIT), Red Hat Display, Public Sans and IBM Plex Mono (SIL Open Font License), Flask, dnspython,
requests, Flask-Limiter, python-dotenv, ReportLab. Username detection approach adapted
from the open-source Sherlock project. Data from IANA/ICANN RDAP, crt.sh, Have I Been Pwned
and VirusTotal is subject to each provider's terms of use.
