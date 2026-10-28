"""
services/graph.py - Turns scan findings into a relationship graph.

Every piece of intelligence becomes a NODE (domain, IP address, nameserver,
mail server, subdomain, certificate authority, SaaS service, platform
account, breach, exposed data type, risk issue ...) and every relationship
becomes an EDGE ("resolves to", "mail via", "subdomain", "found in breach").

Node ids are canonical, e.g. "ip:203.0.113.10" or "domain:demo-corp.test".
Because two scans that discover the same entity produce the SAME id,
merging several scan graphs automatically correlates them: an email scan of
alice@demo-corp.test and a domain scan of demo-corp.test meet at the node
"domain:demo-corp.test". That merged view is the investigation (case) graph.

The graph is computed from stored findings on request - no extra tables.
"""
from __future__ import annotations

import ipaddress
import re

MAX_SUBDOMAINS = 40
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
LEVEL_TO_SEVERITY = {"Low": "info", "Moderate": "low", "High": "medium", "Critical": "high"}

# Two-label public suffixes, so "shop.example.co.in" -> parent "example.co.in"
TWO_LEVEL_SUFFIXES = {
    "co.in", "ac.in", "gov.in", "edu.in", "net.in", "org.in", "res.in", "nic.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "co.nz", "com.br", "com.cn", "com.sg", "co.za",
}

KIND_LABEL = {
    "target": "Scan target", "domain": "Domain", "subdomain": "Subdomain", "ip": "IP address",
    "host": "Server", "org": "Organisation", "service": "Third-party service",
    "cert": "TLS certificate", "account": "Platform account", "breach": "Breach",
    "data": "Exposed data type", "issue": "Risk issue", "verdict": "Reputation verdict",
    "tag": "Category",
}


def parent_domain(host: str) -> str | None:
    labels = host.lower().strip(".").split(".")
    if len(labels) < 3:
        return None
    keep = 3 if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 2
    if len(labels) <= keep:
        return None
    return ".".join(labels[-keep:])


def id_kind(kind: str, value: str) -> str:
    """Canonical id prefix, so the same real-world entity always gets the same id."""
    if kind not in ("target", "subdomain", "domain"):
        return kind
    if "@" in value:
        return "email"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    return "domain" if "." in value else "username"


class GraphBuilder:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple, dict] = {}
        self.current_target: str | None = None

    # ------------------------------------------------------------ primitives
    def node(self, kind: str, value: str, label: str | None = None, *,
             severity: str = "info", detail: str = "", scan_id=None, root=False) -> str:
        value = str(value).strip()
        node_id = f"{id_kind(kind, value)}:{value.lower()}"
        existing = self.nodes.get(node_id)
        if existing is None:
            existing = {"id": node_id, "label": label or value, "kind": kind,
                        "kind_label": KIND_LABEL.get(kind, kind), "severity": severity,
                        "detail": detail, "scans": [], "targets": [], "root": root}
            self.nodes[node_id] = existing
        else:
            if SEVERITY_RANK[severity] > SEVERITY_RANK[existing["severity"]]:
                existing["severity"] = severity
            if root and not existing["root"]:
                existing.update(root=True, kind=kind, kind_label=KIND_LABEL.get(kind, kind))
            if detail and not existing["detail"]:
                existing["detail"] = detail
        if scan_id is not None and scan_id not in existing["scans"]:
            existing["scans"].append(scan_id)
        if self.current_target and self.current_target not in existing["targets"]:
            existing["targets"].append(self.current_target)
        return node_id

    def edge(self, source: str, target: str, label: str):
        if source == target:
            return
        key = (source, target, label)
        if key not in self.edges:
            self.edges[key] = {"id": f"e{len(self.edges)}", "source": source,
                               "target": target, "label": label}

    def result(self) -> dict:
        nodes = list(self.nodes.values())
        counts: dict[str, int] = {}
        for n in nodes:
            counts[n["kind"]] = counts.get(n["kind"], 0) + 1
        return {"nodes": nodes, "edges": list(self.edges.values()),
                "stats": {"nodes": len(nodes), "edges": len(self.edges), "by_kind": counts,
                          "risky_nodes": sum(1 for n in nodes
                                             if SEVERITY_RANK[n["severity"]] >= 2)}}

    # ------------------------------------------------------------- per scan
    def add_scan(self, scan: dict):
        sid = scan.get("id")
        findings = [f for f in scan.get("findings", []) if f["status"] == "confirmed"]
        by_code: dict[str, list[dict]] = {}
        for f in findings:
            by_code.setdefault(f["code"], []).append(f)
        target = scan["target"]
        self.current_target = target
        root = self.node("target", target, target, scan_id=sid, root=True,
                         severity=LEVEL_TO_SEVERITY.get(scan.get("exposure_level"), "info"),
                         detail=f"Exposure {scan.get('exposure_score', 0)}/100 "
                                f"({scan.get('exposure_level', 'Low')}) - scan #{sid}")
        handler = {"domain": self._domain, "username": self._username,
                   "email": self._email, "reputation": self._reputation}[scan["scan_type"]]
        handler(root, target, by_code, sid)

        # every confirmed risky finding becomes a visible issue node
        for f in findings:
            if f["severity"] in ("low", "medium", "high") and f["code"] not in (
                    "USERNAME_FOUND", "CRTSH_SENSITIVE_SUBDOMAINS", "VT_MALICIOUS", "VT_SUSPICIOUS") \
                    and not f["code"].startswith("HIBP_BREACH"):
                issue = self.node("issue", f"{target}:{f['code']}", f["title"],
                                  severity=f["severity"], detail=f.get("value") or "", scan_id=sid)
                self.edge(root, issue, "risk")

    def _domain(self, root, target, by_code, sid):
        for f in by_code.get("RDAP_REGISTRAR", []):
            self.edge(root, self.node("org", f["value"], detail="Domain registrar",
                                      scan_id=sid), "registered with")
        for f in by_code.get("RDAP_NAMESERVERS", []):
            for row in (f.get("details") or {}).get("table", {}).get("rows", []):
                self.edge(root, self.node("host", row[0], detail="Authoritative nameserver",
                                          scan_id=sid), "nameserver")
        for f in by_code.get("DNS_HOST_IPS", []):
            for ip in (f["value"] or "").split(","):
                if ip.strip():
                    self.edge(root, self.node("ip", ip.strip(), detail="Hosting address (A/AAAA)",
                                              scan_id=sid), "resolves to")
        for f in by_code.get("DNS_MX", []):
            servers, _, provider = (f["value"] or "").partition(" - provider: ")
            mx_ids = []
            for mx in servers.split(","):
                if mx.strip():
                    mx_ids.append(self.node("host", mx.strip().rstrip("."), detail="Mail server (MX)",
                                            scan_id=sid))
                    self.edge(root, mx_ids[-1], "mail via")
            for p in provider.split(","):
                if p.strip():
                    pid = self.node("service", p.strip(), detail="Email provider", scan_id=sid)
                    for mid in mx_ids:
                        self.edge(mid, pid, "operated by")
        for f in by_code.get("DNS_TXT_SERVICES", []):
            for svc in (f["value"] or "").split(","):
                if svc.strip():
                    self.edge(root, self.node("service", svc.strip(),
                                              detail="Revealed by a DNS TXT verification token",
                                              scan_id=sid), "uses")
        sensitive = {}
        for f in by_code.get("CRTSH_SENSITIVE_SUBDOMAINS", []):
            for row in (f.get("details") or {}).get("table", {}).get("rows", []):
                sensitive[row[0]] = row[1]
        for f in by_code.get("CRTSH_SUBDOMAINS", []):
            rows = (f.get("details") or {}).get("table", {}).get("rows", [])
            hosts = [r[0] for r in rows if r[0] != target]
            hosts.sort(key=lambda h: (h not in sensitive, h))   # risky ones first
            for host in hosts[:MAX_SUBDOMAINS]:
                kw = sensitive.get(host)
                sub = self.node("subdomain", host, host.replace("." + target, "") or host,
                                severity="medium" if kw else "info", scan_id=sid,
                                detail=(f"Sensitive-looking name (keyword '{kw}') seen in "
                                        "certificate logs" if kw else "Seen in certificate logs"))
                self.edge(root, sub, "subdomain")
        for f in by_code.get("CRTSH_ISSUERS", []):
            for name, count in re.findall(r"([^,]+?) \((\d+)\)", f["value"] or ""):
                self.edge(root, self.node("org", name.strip(),
                                          detail=f"Certificate authority ({count} certificates)",
                                          scan_id=sid), "certificates from")
        for f in by_code.get("TLS_CERT", []):
            d = f.get("details") or {}
            cert = self.node("cert", f"{target}:tls", f"TLS cert · {d.get('days_left', '?')} days",
                             detail=f["value"] or "", scan_id=sid,
                             severity="medium" if by_code.get("TLS_EXPIRY_SOON") else
                             "high" if by_code.get("TLS_EXPIRED") else "info")
            self.edge(root, cert, "serves")
            if d.get("issuer"):
                self.edge(cert, self.node("org", d["issuer"], detail="Certificate authority",
                                          scan_id=sid), "issued by")

    def _username(self, root, target, by_code, sid):
        for f in by_code.get("USERNAME_FOUND", []):
            cat = (f.get("details") or {}).get("category", "")
            acc = self.node("account", f"{f['title']}/{target}", f["title"], severity="low",
                            detail=f"Public profile ({cat}) - {f.get('value') or ''}", scan_id=sid)
            self.edge(root, acc, "profile on")

    def _email(self, root, target, by_code, sid):
        domain = target.split("@")[-1]
        self.edge(root, self.node("domain", domain, detail="Email domain", scan_id=sid),
                  "address at")
        for code in ("HIBP_BREACH_PASSWORDS", "HIBP_BREACH", "HIBP_BREACH_SPAMLIST"):
            for f in by_code.get(code, []):
                d = f.get("details") or {}
                name = f["title"].replace("Breach: ", "")
                b = self.node("breach", name, severity=f["severity"], scan_id=sid,
                              detail=f.get("value") or "")
                self.edge(root, b, "found in")
                for dc in d.get("data_classes", []):
                    sev = "medium" if dc.lower() in ("passwords", "phone numbers",
                                                     "physical addresses") else "info"
                    self.edge(b, self.node("data", dc, severity=sev, scan_id=sid,
                                           detail="Type of data exposed in a breach"), "exposed")

    def _reputation(self, root, target, by_code, sid):
        host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        if host != target:
            self.edge(root, self.node("domain", host, detail="Host of the URL", scan_id=sid),
                      "hosted on")
        parent = parent_domain(host) if re.search(r"[a-z]", host) else None
        if parent:
            self.edge(self.node("domain", parent, detail="Parent domain", scan_id=sid),
                      self.node("domain", host, scan_id=sid) if host != target else root,
                      "subdomain")
        for code in ("VT_MALICIOUS", "VT_SUSPICIOUS", "VT_CLEAN"):
            for f in by_code.get(code, []):
                v = self.node("verdict", f"{target}:{code}", f["title"],
                              severity=f["severity"], detail=f.get("value") or "", scan_id=sid)
                self.edge(root, v, "vendor verdict")
        for f in by_code.get("VT_CATEGORIES", []):
            for c in (f["value"] or "").split(","):
                if c.strip():
                    self.edge(root, self.node("tag", c.strip(), detail="Vendor category",
                                              scan_id=sid), "categorised as")
        for f in by_code.get("VT_NETWORK", []):
            self.edge(root, self.node("org", f["value"], detail="Network owner", scan_id=sid),
                      "network")


def build_graph(scan: dict) -> dict:
    g = GraphBuilder()
    g.add_scan(scan)
    return g.result()


def build_case_graph(scans: list[dict]) -> dict:
    """Merge several scans into one correlated investigation graph."""
    g = GraphBuilder()
    for s in scans:
        g.add_scan(s)
    data = g.result()
    data["stats"]["scans"] = len(scans)
    # an entity discovered while investigating two DIFFERENT targets links them
    data["stats"]["shared_nodes"] = sum(1 for n in data["nodes"] if len(n["targets"]) > 1)
    return data
