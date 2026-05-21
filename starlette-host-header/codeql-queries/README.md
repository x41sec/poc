# CodeQL Queries for Starlette/FastAPI Host Header Injection

These queries detect vulnerable patterns where `request.url.path` can be manipulated via malformed `Host` headers.

## Queries

| Query | Severity | Description |
|-------|----------|-------------|
| `ConnReqUrlPath.ql` | CRITICAL | Taint tracking from `HTTPConnection.url`/`Request.url`/`URL(...)` to `.path` access |
| `ConnReqUrl.ql` | MEDIUM | Direct usage of potentially untrusted URL objects |
| `ReqUrlPath.ql` | LOW | Heuristic detection based on variable names containing "req" |

## Usage

### Create database
```bash
codeql database create my-db --language=python --source-root=/path/to/your/app
```

### Run queries
```bash
# Run all queries in the suite
codeql database analyze my-db codeql-queries/starlette-security.qls --format=sarif-latest --output=results.sarif

# Run a single query
codeql database analyze my-db codeql-queries/ConnReqUrlPath.ql --format=sarif-latest --output=results.sarif
```

### Run against a CodeQL database on GitHub (Code Scanning)
Add to `.github/workflows/codeql.yml`:
```yaml
- uses: github/codeql-action/analyze@v3
  with:
    queries: ./codeql-queries/starlette-security.qls
```

## Vulnerability Background

ASGI servers fail to validate `Host` headers per RFC 9112, allowing requests like:
```http
GET /foo HTTP/1.1
Host: example.com/admin?x=
```

This causes `request.url` to reconstruct as `http://example.com/admin?x=/foo`, making `request.url.path` return `/admin` instead of `/foo`. Path-based security middleware using `request.url.path` can be bypassed.
