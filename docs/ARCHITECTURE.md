# System Architecture and Design

All diagrams are written in Mermaid (rendered PNGs are in `docs/diagrams/`). They render on GitHub, or paste them into
https://mermaid.live to export PNG/SVG images for the project report.

## 1. System architecture

```mermaid
flowchart TB
    UI["Browser<br/>HTML pages + JavaScript + Chart.js"]:::client
    R["Routes / API layer<br/>JSON check, rate limit,<br/>authorisation check"]
    V["Validation service"]
    S["Scan service<br/>(parallel collectors)"]
    C1["RDAP / WHOIS<br/>collector"]
    C2["DNS<br/>collector"]
    C3["crt.sh<br/>collector"]
    C4["Username<br/>collector"]
    C5["HIBP<br/>collector"]
    C6["VirusTotal<br/>collector"]
    D["Demo fixtures<br/>(fictional data)"]
    SC["Scoring +<br/>recommendations"]
    REP["Report generator<br/>PDF / CSV"]
    DB[("SQLite<br/>scans, findings")]
    E1["IANA RDAP bootstrap,<br/>registry RDAP, WHOIS :43"]:::ext
    E2["DNS resolvers"]:::ext
    E3["crt.sh"]:::ext
    E4["Public profile<br/>pages / APIs"]:::ext
    E5["Have I Been Pwned"]:::ext
    E6["VirusTotal"]:::ext

    UI -- "JSON over HTTP" --> R
    R --> V --> S
    S --> C1 & C2 & C3 & C4 & C5 & C6
    S -. "demo mode" .-> D
    C1 --> E1
    C2 --> E2
    C3 --> E3
    C4 --> E4
    C5 --> E5
    C6 --> E6
    S --> SC --> DB
    R --> REP --> DB
    R --> DB

    classDef client fill:#efeafb,stroke:#6d4bc4,color:#132235
    classDef ext fill:#e1eff0,stroke:#0b6e77,color:#132235
    classDef default fill:#ffffff,stroke:#7b8b9b,color:#132235
```

Purple = client, white = Flask application, teal = external public sources.

**In simple terms:** the browser never talks to OSINT sources directly. It sends one JSON
request to Flask. Flask checks the input and the authorisation, then the scan service
starts the relevant collectors at the same time. Each collector talks to exactly one
external source and returns findings in a shared format. Those findings are scored, turned
into recommendations, saved in SQLite and sent back to the browser. In demo mode the
collectors are replaced by fictional fixtures, so nothing external is contacted.

## 2. Data-flow diagram

### Level 0 (context)

```mermaid
flowchart LR
    U(["Operator<br/>(asset owner / authorised analyst)"])
    P(("OSINT Footprint<br/>Dashboard"))
    X(["Public sources<br/>and APIs"])
    U -- "target, mode, authorisation" --> P
    P -- "scan result, PDF/CSV report" --> U
    P -- "lookup queries" --> X
    X -- "public records, API responses" --> P
```

### Level 1

```mermaid
flowchart TD
    U(["Operator"]) -- "target + mode + authorised" --> P1["1.0 Validate request"]
    P1 -- "rejected input" --> U
    P1 -- "normalised target" --> P2["2.0 Collect OSINT<br/>(parallel collectors)"]
    P2 <-->|"queries / responses"| X(["External sources"])
    P2 -- "findings" --> P3["3.0 Score and<br/>recommend"]
    P3 -- "scan record" --> D1[("D1 scans")]
    P3 -- "finding records" --> D2[("D2 findings")]
    D1 & D2 --> P4["4.0 Present results"]
    P4 -- "dashboard view" --> U
    D1 & D2 --> P5["5.0 Generate report"]
    P5 -- "PDF / CSV" --> U
```

## 3. Use-case diagram

Mermaid has no native UML use-case diagram, so it is drawn as a flowchart. The prototype
has one human role, the **operator**. An administrator role is represented by
configuration (the `.env` file) rather than a login, which keeps the prototype simple.

```mermaid
flowchart LR
    OP(["Operator"])
    AD(["Administrator<br/>(edits .env)"])
    subgraph System["OSINT Footprint Dashboard"]
        UC1(["Analyse domain"])
        UC2(["Check username footprint"])
        UC3(["Check email breach exposure"])
        UC4(["Check IP / URL reputation"])
        UC5(["Confirm authorisation"])
        UC6(["View exposure score and<br/>recommendations"])
        UC7(["Export PDF / CSV report"])
        UC8(["View / delete scan history"])
        UC9(["Configure API keys,<br/>live mode, retention"])
    end
    OP --- UC1 & UC2 & UC3 & UC4 & UC6 & UC7 & UC8
    UC1 & UC2 & UC3 & UC4 -. "include (live mode)" .-> UC5
    AD --- UC9
```

## 4. Component diagram

```mermaid
flowchart TB
    subgraph Presentation
        T["templates/*.html"]
        JS["static/js<br/>common · render · scan_form<br/>dashboard · history · scan_detail"]
        CSS["static/css/style.css"]
    end
    subgraph API["routes/"]
        RC["common.py<br/>handle_scan()"]
        RD["domain / username / email /<br/>reputation routes"]
        RA["auto_routes.py<br/>smart search"]
        RS["scan_routes.py"]
        RR["report_routes.py"]
        RP["page_routes.py"]
    end
    subgraph Services["services/"]
        VAL["validation.py"]
        SS["scan_service.py"]
        SCO["scoring.py"]
        REC["recommendations.py"]
        REPT["report.py"]
    end
    subgraph Collectors["collectors/"]
        BASE["base.py<br/>Finding · BaseCollector"]
        COLS["rdap · dns · crtsh ·<br/>username · hibp · vt"]
        DEMO["demo_data.py"]
    end
    subgraph Data["database/"]
        DBPY["db.py"]
        SQL["schema.sql"]
    end
    JS --> RD & RS & RR
    RP --> T
    RD & RA --> RC --> VAL
    RC --> SS --> COLS & DEMO
    COLS --> BASE
    SS --> SCO & REC
    RC & RS & RR --> DBPY --> SQL
    RR --> REPT
```

| Component | Responsibility |
|---|---|
| `collectors/base.py` | The contract: `Finding` (module, source, code, title, value, status, severity, source_url, timestamp, details) and `BaseCollector.run()` (timing, timeout and error handling) |
| Collectors | One external source each; translate raw responses into findings |
| `scan_service.py` | Picks collectors for the scan type, runs them in a thread pool, aggregates results |
| `scoring.py` / `recommendations.py` | Turn findings into a 0-100 score and prioritised actions |
| `validation.py` | Allow-list validation and email masking |
| `routes/common.py` | Enforces JSON, demo/live rules and authorisation for all scan endpoints |
| `routes/auto_routes.py` | Smart search on the server: detects the target type and hands over to the matching module's scan |
| `db.py` | Parameterised SQLite access, retention purge (start-up and every save) |
| `report.py` | PDF and CSV generation with injection protection |

## 5. Database design

```mermaid
erDiagram
    SCANS ||--o{ FINDINGS : contains
    SCANS {
        INTEGER id PK
        TEXT scan_type "domain | username | email | reputation"
        TEXT target "emails stored masked"
        TEXT mode "demo | live"
        TEXT status "completed | partial | failed"
        INTEGER exposure_score "0-100"
        TEXT exposure_level "Low | Moderate | High | Critical"
        TEXT authorization "accepted statement (audit)"
        TEXT started_at "ISO-8601 UTC"
        TEXT completed_at
        INTEGER duration_ms
        TEXT modules_json "per-source status and timing"
        TEXT recommendations_json
        TEXT limitations_json
        TEXT scoring_json "method and breakdown"
    }
    FINDINGS {
        INTEGER id PK
        INTEGER scan_id FK
        TEXT module "rdap, dns, crtsh, username, hibp, virustotal"
        TEXT source
        TEXT code "e.g. DNS_DMARC_MISSING"
        TEXT title
        TEXT value
        TEXT status "confirmed | not_found | inconclusive | error"
        TEXT severity "info | low | medium | high"
        TEXT source_url
        TEXT collected_at
        TEXT details_json
    }
```

- **One-to-many:** a scan has many findings; `ON DELETE CASCADE` removes findings with
  their scan.
- `CHECK` constraints restrict status, severity, scan type and mode to valid values.
- JSON columns hold structured but rarely-queried data (tables for the UI, scoring
  breakdown), which keeps the schema to two tables.
- Indexes on `findings.scan_id` and `scans.started_at` support the history page and the
  retention purge.

## 6. Sequence of a live domain scan

```mermaid
sequenceDiagram
    actor Op as Operator
    participant B as Browser (scan_form.js)
    participant F as Flask (routes/common.py)
    participant S as scan_service
    participant R as RDAP collector
    participant D as DNS collector
    participant C as crt.sh collector
    participant DB as SQLite
    Op->>B: enter domain, tick authorisation, Run analysis
    B->>F: POST /api/scan/domain {target, mode: live, authorized: true}
    F->>F: JSON check, rate limit, validate, authorisation
    F->>S: run_scan("domain", target, "live")
    par in parallel
        S->>R: run(target)
        R-->>S: findings (registrar, dates, DNSSEC...)
    and
        S->>D: run(target)
        D-->>S: findings (records, SPF, DMARC...)
    and
        S->>C: run(target)
        C-->>S: findings (subdomains) or error after timeout
    end
    S->>S: score + recommendations + limitations
    S-->>F: scan dict
    F->>DB: INSERT scan and findings
    F-->>B: 201 {ok: true, scan}
    B->>Op: gauge, certainty bar, findings, recommendations
```

## 7. How the parts interact

1. **Frontend to backend:** the pages are server-rendered shells; JavaScript calls the JSON
   API with `fetch`. All third-party values are inserted with `textContent`, and the CSP
   forbids inline scripts.
2. **Backend to collectors:** `scan_service` gives each collector a plain dict of settings
   (collectors run in worker threads without Flask's context). Every collector call is
   wrapped by `BaseCollector.run()`, so a timeout or crash in one source becomes an `error`
   finding instead of failing the whole scan.
3. **Collectors to external APIs:** HTTPS with a descriptive User-Agent, a per-request
   timeout, API keys read from `.env`, and only GET requests for existing data.
4. **Backend to database:** after the scan, one row goes into `scans` and N rows into
   `findings`, using parameterised queries.
5. **Modularity:** a new source needs one collector class plus one line in `COLLECTORS`.
