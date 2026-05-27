# SARIF Comparison Report — CodeQL vs Semgrep

## 1. Total Findings

| Tool | Total |
|------|-------|
| CodeQL  | 171 |
| Semgrep | 108 |
| **Combined** | **279** |

## 2. Findings by Kind

| Kind     | CodeQL | Semgrep |
|----------|--------|---------|
| Security | 39  | 108 |
| Quality  | 49 | 0 |
| Other    | 83 | 0 |

Note: CodeQL was run with the `security-and-quality` query suite, while Semgrep was run with security-focused rule packs (`p/python`, `p/django`, `p/security-audit`, `p/owasp-top-ten`). The 'Quality' and 'Other' rows therefore reflect a configuration difference rather than a capability difference between the tools.

## 3. Severity Breakdown — All Findings

| Severity | CodeQL | Semgrep |
|----------|--------|---------|
| High | 24 | 19 |
| Medium | 32 | 89 |
| Low | 115 | 0 |
| Unknown | 0 | 0 |

## 4. Severity Breakdown — Security Findings Only

| Severity | CodeQL | Semgrep |
|----------|--------|---------|
| High | 24 | 19 |
| Medium | 15 | 89 |
| Low | 0 | 0 |
| Unknown | 0 | 0 |

Note: tool severities are normalised onto a common 3-tier scale (CodeQL's Critical/High → High; Medium/Warning → Medium; Low/Note → Low; Semgrep's Error → High; Warning → Medium; Info → Low). Comparing tools by raw severity labels would be misleading because the underlying vocabularies differ.

## 5. Security Findings by Category

| Category | CodeQL | Semgrep |
|----------|--------|---------|
| CSRF | 0 | 44 |
| Code Injection | 2 | 4 |
| Command Injection | 5 | 5 |
| Cookie Security | 6 | 12 |
| Cross-Site Scripting | 0 | 10 |
| Dangerous File Write | 0 | 4 |
| Framework Misconfiguration | 3 | 8 |
| Hardcoded Credentials | 0 | 1 |
| Insecure Deserialization | 3 | 8 |
| Log Injection | 4 | 0 |
| Path Traversal | 1 | 0 |
| SQL Injection | 2 | 2 |
| SSRF | 1 | 1 |
| Sensitive Data Exposure | 6 | 0 |
| Weak Cryptography | 4 | 6 |
| XML Security | 1 | 0 |
| XXE | 1 | 3 |

## 6. Quality Findings by Category

| Category | CodeQL | Semgrep |
|----------|--------|---------|
| Resource Management | 14 | 0 |
| Unsafe Exception Handling | 35 | 0 |

## 7. Within-Tool Duplication

This measures how concentrated each tool's output is. A high `Max fan-out` value means a single rule is responsible for a disproportionate share of alerts — a likely indicator of pattern noise rather than 'many distinct problems'.

| Metric | CodeQL | Semgrep |
|--------|--------|---------|
| Total findings        | 171 | 108 |
| Distinct rules fired  | 28  | 27  |
| Avg findings per rule | 6.11      | 4.0      |
| Max fan-out (one rule)| 46      | 25      |
| Top-firing rule       | `py/mixed-returns` | `python.django.security.audit.csrf-exempt.no-csrf-exempt` |

### Top 5 Most-Fired Rules — CodeQL

| Rule | Count |
|------|-------|
| `py/mixed-returns` | 46 |
| `py/catch-base-exception` | 30 |
| `py/unused-import` | 24 |
| `py/file-not-closed` | 14 |
| `py/clear-text-logging-sensitive-data` | 5 |

### Top 5 Most-Fired Rules — Semgrep

| Rule | Count |
|------|-------|
| `python.django.security.audit.csrf-exempt.no-csrf-exempt` | 25 |
| `python.django.security.django-no-csrf-token.django-no-csrf-token` | 19 |
| `python.django.security.audit.secure-cookies.django-secure-set-cookie` | 10 |
| `python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe` | 7 |
| `dockerfile.security.missing-user.missing-user` | 4 |

## 8. Cross-Tool Overlap (Security + Quality)

- Categories+files flagged by **both** tools (lines within 5): **12**
- Categories+files unique to **CodeQL**:  **31**
- Categories+files unique to **Semgrep**: **35**

## 9. Methodology Notes

- Each finding is tagged with a `kind` (security / quality / other) so the comparison can be sliced by intent.
- Category is inferred first from CWE tags in the SARIF metadata (leading zeros are normalised) and, where absent, from keyword matching on rule IDs and rule names.
- Severity vocabularies are normalised onto a common 3-tier scale (High / Medium / Low).
- Cross-tool overlap is computed per (category, filename) and requires at least one CodeQL line within 5 lines of a Semgrep line.
- Within-tool duplication is computed by grouping findings by `rule_id`. 'Max fan-out' indicates the largest single-rule alert count, which is a proxy for pattern-driven noise.