#!/usr/bin/env python3
"""End-to-end TLS/HTTP2 fingerprint assertion against kittens.sh /api/clean.

Pinned values (fingerprint-baseline/expected.json):
  no profile   : JA4 t13d2010h2_a8347f2c98c8_08b0b9cb7c24
                 Akamai 55cb2bd667724e6d46cc3c8dd15d50de (moli default)
  chrome152    : JA4 t13d1517h2_8daaf6152771_cb7bf5808d99
                 Akamai 52d84b11737d980aef856699f885ca86 (Chrome 157)

Only JA4 + Akamai are asserted (Chrome randomizes extension order, so JA3 is
unstable). UA coherence is checked for the profile case (Chrome/152.0.7977.85).

Usage: MOLI_BIN=/path/to/moli python3 scripts/check_fingerprint.py
Set MOLI_HTTPS_PROXY if the CI runner needs an egress proxy.
"""
import html
import json
import os
import re
import subprocess
import sys

KITTENS = "https://kittens.sh/api/clean"
MOLI = os.environ.get("MOLI_BIN", "moli")

EXPECTED = {
    None: {
        "ja4": "t13d2010h2_a8347f2c98c8_08b0b9cb7c24",
        "akamai_hash": "55cb2bd667724e6d46cc3c8dd15d50de",
    },
    "chrome152": {
        "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99",
        "akamai_hash": "52d84b11737d980aef856699f885ca86",
        "ua_contains": "Chrome/152.0.7977.85",
    },
}


def fetch(profile):
    cmd = [MOLI, "fetch", "--dump", "json"]
    if profile:
        cmd += ["--tls-profile", profile]
    cmd.append(KITTENS)
    env = dict(os.environ)
    if os.environ.get("MOLI_HTTPS_PROXY"):
        env["HTTPS_PROXY"] = os.environ["MOLI_HTTPS_PROXY"]
    # Three attempts: the endpoint / egress proxy can reset a TLS handshake.
    last = ""
    for _ in range(3):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
        if r.returncode == 0 and r.stdout.strip():
            outer = json.loads(r.stdout)
            body = html.unescape(re.sub(r"<[^>]+>", "", outer["html"])).strip()
            return json.loads(body)
        last = (r.stderr or r.stdout)[-200:]
    raise RuntimeError(f"moli fetch failed for profile={profile}: {last}")


def main():
    failures = []
    for profile, want in EXPECTED.items():
        label = profile or "default"
        try:
            got = fetch(profile)
        except Exception as exc:
            failures.append(f"{label}: fetch error: {exc}")
            continue
        for field in ("ja4", "akamai_hash"):
            if got.get(field) != want[field]:
                failures.append(
                    f"{label}: {field} = {got.get(field)!r}, expected {want[field]!r}"
                )
        if "ua_contains" in want and want["ua_contains"] not in got.get("user_agent", ""):
            failures.append(
                f"{label}: user_agent = {got.get('user_agent')!r}, "
                f"expected to contain {want['ua_contains']!r}"
            )
        print(
            f"[{label}] ja4={got.get('ja4')} akamai={got.get('akamai_hash')} "
            f"ua={got.get('user_agent')}"
        )
    if failures:
        for f in failures:
            print("FAIL:", f, file=sys.stderr)
        return 1
    print("fingerprint check: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
