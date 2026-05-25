# CVE-2026-48710 — Starlette Host-Header Authentication Bypass

## Overview

Starlette versions prior to the fix construct `request.url` by combining the
`Host` header with the ASGI `scope["path"]`:

```python
url = f"{scheme}://{host}{path}"
```

When middleware derives the request path from this URL (via `urlparse().path`)
for authorization decisions, an attacker can inject an allowlisted path into
the `Host` header to bypass authentication on protected endpoints:

```
Host: target.example.com/health?x=
```

The middleware sees `/health` (allowlisted), but the actual request reaches the
protected endpoint at `scope["path"]`.

## Scanner

`scan_cve_2026_48710.py` is a standalone Python scanner — no dependencies
beyond the standard library (Python 3.8+).  Use it to scan targets locally.

### Quick start

```bash
# MCP mode — auto-discovers MCP endpoints and common allowlisted paths
python scan_cve_2026_48710.py https://target.example.com

# Generic mode — test specific path pairs
python scan_cve_2026_48710.py https://target.example.com \
    --mode generic --unauth /health --protected /admin/api

# JSON output for CI / tooling
python scan_cve_2026_48710.py https://target.example.com --json
```

### Options

| Flag | Description |
|------|-------------|
| `--mode mcp\|generic` | `mcp` (default) auto-discovers MCP endpoints; `generic` tests user-supplied paths |
| `--unauth PATH` | Override default unauthenticated paths (repeatable) |
| `--mcp-path PATH` | Override default MCP endpoint paths (repeatable) |
| `--protected PATH` | Protected path for generic mode (repeatable, required) |
| `--timeout N` | Per-request timeout in seconds (default: 10) |
| `--json` | JSON output |
| `--no-color` | Disable ANSI colors |

Exit code is `1` when the target is vulnerable, `0` otherwise.

### How it works

1. **Discover unauthenticated paths** — probes common allowlisted paths
   (`/health`, `/.well-known/oauth-protected-resource`, etc.) and keeps those
   returning 2xx/3xx.
2. **Discover protected endpoints** — in MCP mode, sends a JSON-RPC
   `initialize` request to candidate paths and classifies by response; in
   generic mode, verifies user-supplied paths return 401/403.
3. **Bypass attempt** — injects each unauthenticated path into the `Host`
   header using two strategies (`prefix` and `query-absorb`) and checks
   whether the protected endpoint responds as if authenticated.

## Static Analysis

In addition to the network scanner, this repository provides rules for
detecting the vulnerable pattern in source code:

- **Semgrep** — `semgrep.yml` finds usages of `request.url` and `.path` in
  Starlette/FastAPI code that may be influenced by the `Host` header.  The
  rules use severity levels to express **confidence**, not actual severity:
  `CRITICAL` = high confidence (type-checked taint from `request.url` →
  `.path`), `MEDIUM` = medium confidence (any typed `request.url` usage),
  `LOW` = low confidence (regex-based heuristic matching `*req*.url`).
- **CodeQL** — tracks data flow from ASGI/WSGI host
  headers through URL construction into authorization checks.

Run semgrep locally:

```bash
semgrep --config semgrep.yml /path/to/your/project
```

## Remediation

Use `scope["path"]` (or the framework-equivalent that reads the path from the
ASGI scope) instead of parsing the path from a URL that incorporates the `Host`
header.  Update Starlette to the patched release.

## License

MIT — see `scan_cve_2026_48710.py` for the full license text.
