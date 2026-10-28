"""
tests/measure_performance.py - measure real response times for your report.

Start the app first (python app.py), then in a second terminal:

    python tests/measure_performance.py                 # demo mode, 5 runs each
    python tests/measure_performance.py --live example.com --runs 3

Live mode only queries the domain you pass (use your own domain or example.com).
Results are printed as a table you can copy into the "Actual result" column of
docs/TEST_PLAN.md. Nothing here is invented - every number is measured.
Note: the default rate limit is 10 scans/minute; the script pauses to respect it.
"""
import argparse
import statistics
import time

import requests

BASE = "http://127.0.0.1:5000"
DEMO = [("domain", "demo-corp.test"), ("username", "demo_analyst"),
        ("email", "alice@demo-corp.test"), ("reputation", "phish-login.demo-corp.test")]


def timed_scan(scan_type, target, mode):
    body = {"target": target, "mode": mode, "authorized": mode == "live"}
    t0 = time.perf_counter()
    resp = requests.post(f"{BASE}/api/scan/{scan_type}", json=body, timeout=120)
    elapsed = (time.perf_counter() - t0) * 1000
    data = resp.json()
    if resp.status_code == 429:
        return None, "rate-limited", {}
    scan = data.get("scan", {})
    modules = {m["module"]: (m["status"], m["duration_ms"]) for m in scan.get("modules", [])}
    return elapsed, scan.get("status", data.get("error", {}).get("code")), modules


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--live", metavar="DOMAIN", help="also time live domain scans of DOMAIN")
    args = ap.parse_args()

    jobs = [(t, v, "demo") for t, v in DEMO]
    if args.live:
        jobs.append(("domain", args.live, "live"))

    sent = 0
    print(f"{'scan':<34}{'mode':<6}{'runs':>5}{'min ms':>10}{'median ms':>11}{'max ms':>10}  status")
    for scan_type, target, mode in jobs:
        times, statuses, modules = [], set(), {}
        for _ in range(args.runs):
            if sent and sent % 9 == 0:
                time.sleep(61)  # stay under the 10/minute rate limit
            ms, status, mods = timed_scan(scan_type, target, mode)
            sent += 1
            if ms is not None:
                times.append(ms)
            statuses.add(status)
            modules = mods or modules
        label = f"{scan_type}:{target}"[:33]
        if times:
            print(f"{label:<34}{mode:<6}{len(times):>5}{min(times):>10.0f}"
                  f"{statistics.median(times):>11.0f}{max(times):>10.0f}  {','.join(sorted(statuses))}")
        if mode == "live":
            for name, (st, dur) in modules.items():
                print(f"    last run - {name:<12} {st:<8} {dur} ms")


if __name__ == "__main__":
    main()
