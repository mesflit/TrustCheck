#!/usr/bin/env python3
# TrustCheck — SPDX-License-Identifier: GPL-3.0-only
"""
Builds TrustCheck's daily threat list from openly licensed sources.

Output (in OUT_DIR):
  feed.txt.gz  one normalized domain per line, with a header crediting every source
  feed.json    {version, count, sha256 (of feed.txt.gz), file, sources[]}

The app downloads these from the `threat-feed` GitHub Release and checks links on-device.
Standard library only, so the workflow needs no dependencies.

Only sources whose license allows use in a monetized app may be added here.
"""
import gzip
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

SOURCES = [
    {
        "name": "Phishing.Database",
        "license": "MIT",
        "url": "https://github.com/Phishing-Database/Phishing.Database",
        "download": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "category": "phishing",
        "attribution": "Copyright (c) 2018-2025 Mitchell Krog, Nissar Chababy and Phishing.Database contributors (MIT License)",
    },
    # USOM (TR-CERT) is intentionally not included until its terms of reuse are confirmed.
]

HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
MIN_TOTAL = 1000
MAX_TOTAL = 2_000_000


def load_allowlist(path):
    """Domains that must never be listed. Entries block the domain AND all its subdomains."""
    out = set()
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip().lower()
            if line:
                out.add(line)
    return out


def normalize(line):
    s = line.split("#", 1)[0].strip()
    if not s:
        return None
    s = s.split()[-1]
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split(":", 1)[0].rstrip(".").lower()
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode("ascii") if any(ord(c) > 127 for c in s) else s
    except UnicodeError:
        return None
    if not HOST.match(s) or IPV4.match(s):
        return None
    return s


def allowed(domain, allow, hosting_suffixes):
    if domain in hosting_suffixes:
        return False  # never block a whole hosting platform
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in allow:
            return False
    return True


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "TrustCheck-threat-feed-builder (+https://github.com/mesflit/TrustCheck)"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read().decode("utf-8", errors="replace")


def main(out_dir, allowlist_path):
    allow = load_allowlist(allowlist_path)
    hosting = load_allowlist(os.path.join(os.path.dirname(allowlist_path), "hosting-suffixes.txt"))
    domains = set()
    used_sources = []
    for src in SOURCES:
        try:
            text = fetch(src["download"])
        except Exception as e:  # keep going with other sources
            print(f"::warning::{src['name']} download failed: {e}")
            continue
        before = len(domains)
        dropped = 0
        for line in io.StringIO(text):
            d = normalize(line)
            if d is None:
                continue
            if not allowed(d, allow, hosting):
                dropped += 1
                continue
            domains.add(d)
        added = len(domains) - before
        print(f"{src['name']}: +{added} domains ({dropped} allowlisted)")
        if added:
            used_sources.append({k: src[k] for k in ("name", "license", "url", "category")})

    if len(domains) < MIN_TOTAL:
        print(f"::error::Only {len(domains)} domains collected; refusing to publish a suspiciously small feed.")
        return 1
    if len(domains) > MAX_TOTAL:
        print(f"::warning::Truncating feed from {len(domains)} to {MAX_TOTAL} entries.")

    version = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = [
        "# TrustCheck threat feed — https://github.com/mesflit/TrustCheck",
        f"# version: {version}",
        f"# entries: {min(len(domains), MAX_TOTAL)}",
        "# sources:",
    ] + [f"#   {s['name']} — {s['url']} — {next(x['attribution'] for x in SOURCES if x['name'] == s['name'])}" for s in used_sources]
    body = "\n".join(header + sorted(domains)[:MAX_TOTAL]) + "\n"

    os.makedirs(out_dir, exist_ok=True)
    gz_path = os.path.join(out_dir, "feed.txt.gz")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(body.encode("utf-8"))
    data = buf.getvalue()
    with open(gz_path, "wb") as f:
        f.write(data)
    meta = {
        "version": version,
        "count": min(len(domains), MAX_TOTAL),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file": "feed.txt.gz",
        "sources": used_sources,
    }
    with open(os.path.join(out_dir, "feed.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(json.dumps(meta, indent=2))
    print(f"feed.txt.gz: {len(data) / 1024 / 1024:.2f} MiB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "threat-feed-out",
                  sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "..", "threat-feed", "allowlist.txt")))
