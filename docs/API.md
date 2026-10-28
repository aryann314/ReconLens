# API Reference

Base URL: `http://127.0.0.1:5000`. All API responses are JSON with `"ok": true|false`.

## Scan endpoints

| Method | Path | Rate limit |
|---|---|---|
| POST | `/api/scan/domain` | `SCAN_RATE_LIMIT` (default 10/minute per IP) |
| POST | `/api/scan/username` | same |
| POST | `/api/scan/email` | same |
| POST | `/api/scan/reputation` | same |

### Request

Header `Content-Type: application/json` is **required** (otherwise HTTP 415).

```json
{ "target": "demo-corp.test", "mode": "demo", "authorized": false }
```

| Field | Type | Rules |
|---|---|---|
| `target` | string | domain: valid hostname (URLs accepted, host extracted, IDN converted); username: 2-39 chars `[A-Za-z0-9._-]`; email: single valid address; reputation: domain, **public** IP, or `http(s)://` URL |
| `mode` | `"demo"` or `"live"` | default `"demo"`; demo mode only accepts the fictional demo targets |
| `authorized` | boolean | must be literally `true` in live mode |

### Success response - HTTP 201

```json
{
  "ok": true,
  "scan": {
    "id": 1,
    "scan_type": "domain",
    "target": "demo-corp.test",
    "mode": "demo",
    "status": "completed",
    "exposure_score": 46,
    "exposure_level": "Moderate",
    "authorization": null,
    "started_at": "2026-10-21T05:31:22+00:00",
    "completed_at": "2026-10-21T05:31:22+00:00",
    "duration_ms": 3,
    "modules": [
      {"module": "rdap", "source": "...", "status": "ok", "error": null,
       "duration_ms": 640, "finding_count": 8}
    ],
    "findings": [
      {"id": 1, "module": "dns", "source": "DNS (public resolver)",
       "code": "DNS_DMARC_MISSING", "title": "DMARC (Domain-based Message Authentication)",
       "value": "No DMARC record at _dmarc...", "status": "confirmed", "severity": "medium",
       "source_url": "https://dns.google/query?name=demo-corp.test",
       "collected_at": "2026-10-21T05:31:22+00:00", "details": {}}
    ],
    "scoring": {"score": 46, "level": "Moderate", "method": "...",
                "breakdown": [{"code": "DNS_DMARC_MISSING", "points": 10, "...": "..."}],
                "status_counts": {"confirmed": 19, "not_found": 0, "inconclusive": 0, "error": 0}},
    "recommendations": [{"code": "DNS_DMARC_MISSING", "title": "Publish a DMARC policy",
                         "action": "...", "priority": "Medium", "triggered_by": ["..."]}],
    "limitations": ["..."]
  }
}
```

`scan.status`: `completed` (all sources ok), `partial` (some failed or were skipped),
`failed` (all failed). Module `status`: `ok`, `partial`, `error`, `skipped`.

### Error response

```json
{ "ok": false, "error": { "code": "invalid_input", "message": "That is not a valid domain name.", "field": "target" } }
```

| HTTP | `error.code` | When |
|---|---|---|
| 400 | `bad_json` | body is not a JSON object |
| 400 | `bad_mode` | mode not demo/live |
| 400 | `invalid_input` | validation failed |
| 400 | `not_a_demo_target` | demo mode with a non-demo target (response includes `demo_targets`) |
| 400 | `hibp_key_missing` | live email check of a non-test address without `HIBP_API_KEY` |
| 400 | `virustotal_key_missing` | live reputation check without `VIRUSTOTAL_API_KEY` |
| 400 | `undetectable_target` | `/api/scan/auto`: the value is not domain-, email-, IP/URL- or username-shaped |
| 403 | `authorization_required` | live mode without `"authorized": true` |
| 403 | `live_disabled` | `ALLOW_LIVE_MODE=false` |
| 403 | `domain_not_authorised` | email domain not in `AUTHORIZED_EMAIL_DOMAINS` |
| 404 | `not_found` | unknown endpoint or scan id |
| 405 | `method_not_allowed` | wrong HTTP method |
| 413 | `request_entity_too_large` | body over 16 KB |
| 415 | `unsupported_media_type` | not `application/json` |
| 429 | `too_many_requests` | rate limit exceeded |
| 500 | `internal_error` | unexpected error (details only in `logs/app.log`) |

Failures of an individual OSINT source are **not** HTTP errors: the scan still returns
201 with that module marked `error`/`skipped` and an `error`-status finding explaining why.

## Read and manage scans

| Method | Path | Description |
|---|---|---|
| GET | `/api/scans?limit=50&type=domain` | History, newest first. `limit` 1-200, optional `type` |
| GET | `/api/scans/<id>` | One scan with findings (same shape as the scan response) |
| DELETE | `/api/scans/<id>` | Delete a scan and its findings → `{"ok": true, "deleted": id}` |
| GET | `/api/scans/<id>/report.pdf` | PDF report (attachment) |
| GET | `/api/scans/<id>/report.csv` | CSV report (UTF-8 with BOM for Excel) |
| GET | `/api/stats` | `total_scans`, `average_score`, `scans_by_type`, `scans_by_level`, `findings_by_status` |
| GET | `/api/health` | `live_mode_allowed`, `hibp_key_configured`, `virustotal_key_configured`, `retention_days`, `scan_rate_limit` |
| GET | `/api/demo-targets` | Fictional demo targets per scan type |

## Smart search endpoints

Both take the value in a JSON body (never in the URL), so email addresses do not end up in
URLs, browser history or the access log. Detection uses the same rules as the browser
(`static/js/search.js`): `name@host.tld` → email, `http(s)://` or an IP → reputation,
`name.with.dots` → domain, any other handle → username.

### `POST /api/detect`

```json
{ "target": "https://www.Example.com/x" }
```
```json
{ "ok": true, "scan_type": "reputation", "valid": true,
  "endpoint": "/api/scan/reputation", "normalised": "https://www.Example.com/x" }
```
If the value matches a type but fails that module's validation (e.g. `192.168.0.1`),
`valid` is `false` and `message` explains why. `scan_type` is `null` when nothing fits.
For emails `normalised` is always `null` so the address is never echoed back.

### `POST /api/scan/auto`

Same body and response as the scan endpoints (`target`, `mode`, `authorized`); the detected
module runs with **all** of its usual safeguards (validation, demo-target check,
authorisation, HIBP/VirusTotal policies, `SCAN_RATE_LIMIT`). In demo mode a domain-shaped
value that is only a reputation demo target (`phish-login.demo-corp.test`) runs the
reputation module. The response's `scan.scan_type` shows which module ran.

## Example with curl (Windows Command Prompt)

```bat
curl -X POST http://127.0.0.1:5000/api/scan/domain -H "Content-Type: application/json" -d "{\"target\":\"demo-corp.test\",\"mode\":\"demo\"}"
curl http://127.0.0.1:5000/api/scans?limit=5
curl -o report.pdf http://127.0.0.1:5000/api/scans/1/report.pdf
curl -X POST http://127.0.0.1:5000/api/scan/auto -H "Content-Type: application/json" -d "{\"target\":\"alice@demo-corp.test\",\"mode\":\"demo\"}"
```

## Finding codes

| Module | Codes |
|---|---|
| rdap | `RDAP_REGISTRAR`, `RDAP_REGISTRATION_DATE`, `RDAP_RECENTLY_REGISTERED`, `RDAP_EXPIRY`, `RDAP_EXPIRY_SOON`, `RDAP_EXPIRED`, `RDAP_NAMESERVERS`, `RDAP_STATUS`, `RDAP_NO_TRANSFER_LOCK`, `RDAP_DNSSEC_ON`, `RDAP_DNSSEC_OFF`, `RDAP_REGISTRANT_PUBLIC`, `RDAP_REGISTRANT_REDACTED`, `RDAP_NOT_REGISTERED` |
| dns | `DNS_RECORDS`, `DNS_HOST_IPS`, `DNS_MX`, `DNS_NO_MX`, `DNS_TXT_SERVICES`, `DNS_SPF_MISSING`, `DNS_SPF_MULTIPLE`, `DNS_SPF_PERMISSIVE`, `DNS_SPF_NEUTRAL`, `DNS_SPF_OK`, `DNS_DMARC_MISSING`, `DNS_DMARC_MONITOR`, `DNS_DMARC_OK`, `DNS_DMARC_UNKNOWN`, `DNS_CAA_MISSING`, `DNS_CAA_OK`, `DNS_PARTIAL`, `DNS_NXDOMAIN` |
| crtsh | `CRTSH_SUBDOMAINS`, `CRTSH_SENSITIVE_SUBDOMAINS`, `CRTSH_WILDCARD`, `CRTSH_ISSUERS`, `CRTSH_NONE`, `CRTSH_TOO_LARGE` |
| username | `USERNAME_FOUND`, `USERNAME_NOT_FOUND`, `USERNAME_INCONCLUSIVE`, `USERNAME_REUSE` |
| hibp | `HIBP_SUMMARY`, `HIBP_BREACH`, `HIBP_BREACH_PASSWORDS`, `HIBP_BREACH_SPAMLIST`, `HIBP_NO_BREACH` |
| tls | `TLS_CERT`, `TLS_EXPIRY_SOON`, `TLS_EXPIRED`, `TLS_UNTRUSTED`, `TLS_HANDSHAKE_FAILED`, `TLS_NO_HTTPS` |
| virustotal | `VT_MALICIOUS`, `VT_SUSPICIOUS`, `VT_CLEAN`, `VT_STATS`, `VT_COMMUNITY_SCORE`, `VT_CATEGORIES`, `VT_NETWORK`, `VT_NOT_FOUND` |
| any | `<MODULE>_ERROR` - the source could not be queried |


## Graph endpoints (version 2)

### `GET /api/scans/<id>/graph`
Relationship graph of one scan. Also included as `scan.graph` in every scan response.

```json
{"ok": true, "graph": {
  "nodes": [{"id": "domain:demo-corp.test", "label": "demo-corp.test", "kind": "target",
             "kind_label": "Scan target", "severity": "medium", "detail": "...",
             "scans": [1], "targets": ["demo-corp.test"], "root": true}],
  "edges": [{"id": "e0", "source": "domain:demo-corp.test", "target": "ip:203.0.113.10",
             "label": "resolves to"}],
  "stats": {"nodes": 33, "edges": 33, "by_kind": {"subdomain": 13}, "risky_nodes": 11}}}
```

### `GET /api/graph?ids=1,2,3` (or `?limit=20` for the most recent scans)
Merges scans into one correlated investigation graph. `stats.shared_nodes` counts entities
discovered while investigating more than one different target. `ids` must be integers (400 otherwise).
