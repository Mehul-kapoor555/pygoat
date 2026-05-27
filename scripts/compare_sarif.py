r"""
SARIF Comparison Tool — CodeQL vs Semgrep
=========================================

This script performs comparative analysis of SARIF reports generated
by CodeQL and Semgrep inside the DevSecOps security pipeline.

The framework normalizes findings from both tools into a common format
and generates normalized outputs for comparative analysis.

Main features:

  - SARIF parsing and normalization
  - CWE based vulnerability categorization
  - Severity normalization across tools
  - Security versus quality finding classification
  - Cross tool overlap analysis
  - Within tool duplication analysis
  - Rule frequency analysis
  - CSV dataset generation
  - Markdown report generation

Input files:
    sarif_reports/python.sarif
    sarif_reports/semgrep-results.sarif

Generated outputs:
    comparison_output/
        all_findings.csv
        overlap_analysis.csv
        rule_duplication.csv
        comparison_report.md

Run:
    python scripts/compare_sarif.py
"""

import json
import csv
import re
from pathlib import Path
from collections import defaultdict, Counter


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

SARIF_DIR = BASE_DIR / "sarif_reports"

CODEQL_SARIF = SARIF_DIR / "python.sarif"
SEMGREP_SARIF = SARIF_DIR / "semgrep-results.sarif"

OUTPUT_DIR = BASE_DIR / "comparison_output"

# ---------------------------------------------------------------------------
# Kind classification
# ---------------------------------------------------------------------------

SECURITY_CATEGORIES = {
    "Cross-Site Scripting", "SQL Injection", "Command Injection",
    "Code Injection", "SSRF", "XXE", "Insecure Deserialization",
    "Path Traversal", "Weak Cryptography", "Hardcoded Credentials",
    "CSRF", "Open Redirect", "Improper Authorization",
    "Broken Authentication", "Missing Authorization",
    "Cookie Security", "Sensitive Data Exposure", "Log Injection",
    "XML Security", "Framework Misconfiguration",
    "Dockerfile Misconfiguration", "Dangerous File Write",
}

QUALITY_CATEGORIES = {
    "Resource Management", "Unsafe Exception Handling",
}


def classify_kind(category):
    if category in SECURITY_CATEGORIES:
        return "security"
    if category in QUALITY_CATEGORIES:
        return "quality"
    return "other"


# ---------------------------------------------------------------------------
# Parse SARIF
# ---------------------------------------------------------------------------

def load_sarif(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def extract_cwe(tags):
    cwes = []
    for tag in tags or []:
        match = re.search(r"cwe[-_]?(\d+)", tag, re.IGNORECASE)
        if match:
            num = str(int(match.group(1)))
            cwes.append(f"CWE-{num}")
    return cwes


def infer_category(rule_id, name, cwes):

    cwe_to_category = {
        "CWE-79":  "Cross-Site Scripting",
        "CWE-89":  "SQL Injection",
        "CWE-78":  "Command Injection",
        "CWE-88":  "Command Injection",
        "CWE-94":  "Code Injection",
        "CWE-95":  "Code Injection",
        "CWE-918": "SSRF",
        "CWE-611": "XXE",
        "CWE-502": "Insecure Deserialization",
        "CWE-22":  "Path Traversal",
        "CWE-23":  "Path Traversal",
        "CWE-36":  "Path Traversal",
        "CWE-73":  "Path Traversal",
        "CWE-99":  "Path Traversal",
        "CWE-327": "Weak Cryptography",
        "CWE-328": "Weak Cryptography",
        "CWE-916": "Weak Cryptography",
        "CWE-798": "Hardcoded Credentials",
        "CWE-259": "Hardcoded Credentials",
        "CWE-522": "Hardcoded Credentials",
        "CWE-352": "CSRF",
        "CWE-601": "Open Redirect",
        "CWE-285": "Improper Authorization",
        "CWE-287": "Broken Authentication",
        "CWE-862": "Missing Authorization",
        "CWE-614":  "Cookie Security",
        "CWE-1004": "Cookie Security",
        "CWE-312": "Sensitive Data Exposure",
        "CWE-315": "Sensitive Data Exposure",
        "CWE-359": "Sensitive Data Exposure",
        "CWE-532": "Sensitive Data Exposure",
        "CWE-200": "Sensitive Data Exposure",
        "CWE-209": "Sensitive Data Exposure",
        "CWE-117": "Log Injection",
        "CWE-776": "XML Security",
        "CWE-400": "XML Security",
        "CWE-215": "Framework Misconfiguration",
        "CWE-489": "Framework Misconfiguration",
        "CWE-668": "Framework Misconfiguration",
        "CWE-250": "Framework Misconfiguration",
        "CWE-269": "Framework Misconfiguration",
        "CWE-20":  "Framework Misconfiguration",
        "CWE-93":  "Dangerous File Write",
        "CWE-772": "Resource Management",
        "CWE-390": "Unsafe Exception Handling",
        "CWE-396": "Unsafe Exception Handling",
    }

    for cwe in cwes:
        if cwe in cwe_to_category:
            return cwe_to_category[cwe]

    text = f"{rule_id} {name}".lower()

    keyword_map = [
        ("ssrf",                "SSRF"),
        ("xxe",                 "XXE"),
        ("xml.*external",       "XXE"),
        ("sql.*inject",         "SQL Injection"),
        ("sqli",                "SQL Injection"),
        ("deserial",            "Insecure Deserialization"),
        ("pickle",              "Insecure Deserialization"),
        ("command.*inject",     "Command Injection"),
        ("command.line",        "Command Injection"),
        ("shell.command",       "Command Injection"),
        ("subprocess",          "Command Injection"),
        ("shell.*true",         "Command Injection"),
        ("code.*inject",        "Code Injection"),
        ("eval",                "Code Injection"),
        ("xss",                 "Cross-Site Scripting"),
        ("cross.site",          "Cross-Site Scripting"),
        ("hardcoded",           "Hardcoded Credentials"),
        ("jwt",                 "Hardcoded Credentials"),
        ("path.travers",        "Path Traversal"),
        ("path.injection",      "Path Traversal"),
        ("open.redirect",       "Open Redirect"),
        ("crypto",              "Weak Cryptography"),
        ("csrf",                "CSRF"),
        ("dockerfile",          "Dockerfile Misconfiguration"),
        ("cookie",              "Cookie Security"),
        ("clear.text",          "Sensitive Data Exposure"),
        ("sensitive.data",      "Sensitive Data Exposure"),
        ("xml.bomb",            "XML Security"),
        ("flask.debug",         "Framework Misconfiguration"),
        ("debug.enabled",       "Framework Misconfiguration"),
        ("bad.host",            "Framework Misconfiguration"),
        ("log.inject",          "Log Injection"),
        ("catch.base.exception", "Unsafe Exception Handling"),
        ("empty.except",         "Unsafe Exception Handling"),
        ("file.not.closed",      "Resource Management"),
        ("request.data.write",   "Dangerous File Write"),
    ]

    for pattern, category in keyword_map:
        if re.search(pattern, text):
            return category

    return "Other"


def normalise_severity(raw):
    if not raw:
        return "Unknown"
    raw = str(raw).lower()
    if raw in ("critical", "high", "error"):
        return "High"
    if raw in ("medium", "moderate", "warning"):
        return "Medium"
    if raw in ("low", "note", "info", "informational"):
        return "Low"
    return raw.capitalize()


def parse_findings(sarif, tool_label):

    findings = []

    for run in sarif.get("runs", []):

        rules_index = {}

        driver = run.get("tool", {}).get("driver", {})

        for rule in driver.get("rules", []):
            rules_index[rule.get("id")] = rule

        for ext in run.get("tool", {}).get("extensions", []):
            for rule in ext.get("rules", []):
                rules_index[rule.get("id")] = rule

        for result in run.get("results", []):

            rule_id = result.get("ruleId", "unknown")
            rule_meta = rules_index.get(rule_id, {})

            name = (
                rule_meta.get("name")
                or rule_meta.get("shortDescription", {}).get("text", "")
            )

            props = rule_meta.get("properties", {})

            severity_raw = (
                result.get("level")
                or props.get("security-severity")
                or props.get("severity")
                or rule_meta.get("defaultConfiguration", {}).get("level")
                or "warning"
            )

            if isinstance(severity_raw, str) and severity_raw.replace(".", "").isdigit():
                score = float(severity_raw)
                if score >= 9.0:
                    severity_raw = "critical"
                elif score >= 7.0:
                    severity_raw = "high"
                elif score >= 4.0:
                    severity_raw = "medium"
                else:
                    severity_raw = "low"

            tags = props.get("tags", [])
            cwes = extract_cwe(tags)
            category = infer_category(rule_id, name, cwes)
            kind = classify_kind(category)

            file_path = "unknown"
            line = 0

            locations = result.get("locations", [])

            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                file_path = artifact.get("uri", "unknown")
                line = phys.get("region", {}).get("startLine", 0)

            message = result.get("message", {}).get("text", "")

            findings.append({
                "tool": tool_label,
                "rule_id": rule_id,
                "name": name or rule_id,
                "category": category,
                "kind": kind,
                "cwes": ";".join(cwes) if cwes else "",
                "severity": normalise_severity(severity_raw),
                "file": file_path,
                "line": line,
                "message": message,
            })

    return findings


# ---------------------------------------------------------------------------
# Overlap (between tools)
# ---------------------------------------------------------------------------

def overlap_analysis(findings, line_tolerance=5):

    grouped = defaultdict(list)

    for f in findings:
        normalized_path = f["file"].split("/")[-1] if f["file"] else "unknown"
        key = (f["category"], normalized_path)
        grouped[key].append(f)

    overlap_rows = []

    for (category, fname), items in grouped.items():

        tools = set(item["tool"] for item in items)
        codeql_lines = sorted(i["line"] for i in items if i["tool"] == "CodeQL")
        semgrep_lines = sorted(i["line"] for i in items if i["tool"] == "Semgrep")

        is_overlap = False
        if "CodeQL" in tools and "Semgrep" in tools:
            for cl in codeql_lines:
                for sl in semgrep_lines:
                    if abs(cl - sl) <= line_tolerance:
                        is_overlap = True
                        break
                if is_overlap:
                    break

        overlap_rows.append({
            "category": category,
            "file": fname,
            "codeql_count": len(codeql_lines),
            "semgrep_count": len(semgrep_lines),
            "tools": ",".join(sorted(tools)),
            "overlap": "yes" if is_overlap else "no",
        })

    return overlap_rows


# ---------------------------------------------------------------------------
# Severity and duplication analysis
# ---------------------------------------------------------------------------

def severity_breakdown(findings):
    """
    Return counts of High/Medium/Low/Unknown for the given findings.
    """
    sev = Counter(f["severity"] for f in findings)
    return {
        "High":    sev.get("High", 0),
        "Medium":  sev.get("Medium", 0),
        "Low":     sev.get("Low", 0),
        "Unknown": sev.get("Unknown", 0),
    }


def duplication_analysis(findings):
    """
    Compute within-tool duplication stats:
      - distinct_rules:   how many unique rule_ids fired
      - total_findings:   total alerts
      - max_fanout:       most alerts from a single rule
      - max_fanout_rule:  the rule_id responsible
      - avg_fanout:       average alerts per rule
      - top_rules:        list of (rule_id, count) for the top 5 most-fired rules
    """
    per_rule = Counter(f["rule_id"] for f in findings)
    if not per_rule:
        return {
            "distinct_rules": 0, "total_findings": 0,
            "max_fanout": 0, "max_fanout_rule": "",
            "avg_fanout": 0.0, "top_rules": [],
        }
    top_rule, top_count = per_rule.most_common(1)[0]
    return {
        "distinct_rules":  len(per_rule),
        "total_findings":  sum(per_rule.values()),
        "max_fanout":      top_count,
        "max_fanout_rule": top_rule,
        "avg_fanout":      round(sum(per_rule.values()) / len(per_rule), 2),
        "top_rules":       per_rule.most_common(5),
    }


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def write_markdown_report(out_path,
                          codeql_findings,
                          semgrep_findings,
                          overlap_rows):

    cq = len(codeql_findings)
    sg = len(semgrep_findings)

    def counts_by_kind(findings, kind):
        return sum(1 for f in findings if f["kind"] == kind)

    cq_sec   = counts_by_kind(codeql_findings,  "security")
    cq_qual  = counts_by_kind(codeql_findings,  "quality")
    cq_other = counts_by_kind(codeql_findings,  "other")

    sg_sec   = counts_by_kind(semgrep_findings, "security")
    sg_qual  = counts_by_kind(semgrep_findings, "quality")
    sg_other = counts_by_kind(semgrep_findings, "other")

    cq_sec_cat   = Counter(f["category"] for f in codeql_findings  if f["kind"] == "security")
    sg_sec_cat   = Counter(f["category"] for f in semgrep_findings if f["kind"] == "security")
    cq_qual_cat  = Counter(f["category"] for f in codeql_findings  if f["kind"] == "quality")
    sg_qual_cat  = Counter(f["category"] for f in semgrep_findings if f["kind"] == "quality")

    both_count = sum(1 for r in overlap_rows if r["overlap"] == "yes")
    only_cq    = sum(1 for r in overlap_rows if r["tools"] == "CodeQL")
    only_sg    = sum(1 for r in overlap_rows if r["tools"] == "Semgrep")

    # Severity breakdown (overall + security-only)
    cq_sev_all = severity_breakdown(codeql_findings)
    sg_sev_all = severity_breakdown(semgrep_findings)
    cq_sev_sec = severity_breakdown([f for f in codeql_findings  if f["kind"] == "security"])
    sg_sev_sec = severity_breakdown([f for f in semgrep_findings if f["kind"] == "security"])

    # Duplication analysis
    cq_dup = duplication_analysis(codeql_findings)
    sg_dup = duplication_analysis(semgrep_findings)

    lines = []
    lines.append("# SARIF Comparison Report — CodeQL vs Semgrep\n")

    # ---- 1. Totals ----
    lines.append("## 1. Total Findings\n")
    lines.append("| Tool | Total |")
    lines.append("|------|-------|")
    lines.append(f"| CodeQL  | {cq} |")
    lines.append(f"| Semgrep | {sg} |")
    lines.append(f"| **Combined** | **{cq + sg}** |\n")

    # ---- 2. Kind ----
    lines.append("## 2. Findings by Kind\n")
    lines.append("| Kind     | CodeQL | Semgrep |")
    lines.append("|----------|--------|---------|")
    lines.append(f"| Security | {cq_sec}  | {sg_sec} |")
    lines.append(f"| Quality  | {cq_qual} | {sg_qual} |")
    lines.append(f"| Other    | {cq_other} | {sg_other} |\n")

    lines.append(
        "Note: CodeQL was run with the `security-and-quality` query suite, "
        "while Semgrep was run with security-focused rule packs (`p/python`, "
        "`p/django`, `p/security-audit`, `p/owasp-top-ten`). The 'Quality' "
        "and 'Other' rows therefore reflect a configuration difference rather "
        "than a capability difference between the tools.\n"
    )

    # ---- 3. Severity (overall) ----
    lines.append("## 3. Severity Breakdown — All Findings\n")
    lines.append("| Severity | CodeQL | Semgrep |")
    lines.append("|----------|--------|---------|")
    for sev in ("High", "Medium", "Low", "Unknown"):
        lines.append(f"| {sev} | {cq_sev_all[sev]} | {sg_sev_all[sev]} |")
    lines.append("")

    # ---- 4. Severity (security-only) ----
    lines.append("## 4. Severity Breakdown — Security Findings Only\n")
    lines.append("| Severity | CodeQL | Semgrep |")
    lines.append("|----------|--------|---------|")
    for sev in ("High", "Medium", "Low", "Unknown"):
        lines.append(f"| {sev} | {cq_sev_sec[sev]} | {sg_sev_sec[sev]} |")
    lines.append("")

    lines.append(
        "Note: tool severities are normalised onto a common 3-tier scale "
        "(CodeQL's Critical/High → High; Medium/Warning → Medium; Low/Note → Low; "
        "Semgrep's Error → High; Warning → Medium; Info → Low). Comparing tools "
        "by raw severity labels would be misleading because the underlying "
        "vocabularies differ.\n"
    )

    # ---- 5. Security categories ----
    lines.append("## 5. Security Findings by Category\n")
    lines.append("| Category | CodeQL | Semgrep |")
    lines.append("|----------|--------|---------|")
    for cat in sorted(set(cq_sec_cat) | set(sg_sec_cat)):
        lines.append(f"| {cat} | {cq_sec_cat.get(cat, 0)} | {sg_sec_cat.get(cat, 0)} |")
    lines.append("")

    # ---- 6. Quality categories ----
    lines.append("## 6. Quality Findings by Category\n")
    if cq_qual_cat or sg_qual_cat:
        lines.append("| Category | CodeQL | Semgrep |")
        lines.append("|----------|--------|---------|")
        for cat in sorted(set(cq_qual_cat) | set(sg_qual_cat)):
            lines.append(f"| {cat} | {cq_qual_cat.get(cat, 0)} | {sg_qual_cat.get(cat, 0)} |")
        lines.append("")
    else:
        lines.append("_No findings classified as code quality._\n")

    # ---- 7. Duplication ----
    lines.append("## 7. Within-Tool Duplication\n")
    lines.append(
        "This measures how concentrated each tool's output is. A high `Max fan-out` "
        "value means a single rule is responsible for a disproportionate share of "
        "alerts — a likely indicator of pattern noise rather than 'many distinct "
        "problems'.\n"
    )
    lines.append("| Metric | CodeQL | Semgrep |")
    lines.append("|--------|--------|---------|")
    lines.append(f"| Total findings        | {cq_dup['total_findings']} | {sg_dup['total_findings']} |")
    lines.append(f"| Distinct rules fired  | {cq_dup['distinct_rules']}  | {sg_dup['distinct_rules']}  |")
    lines.append(f"| Avg findings per rule | {cq_dup['avg_fanout']}      | {sg_dup['avg_fanout']}      |")
    lines.append(f"| Max fan-out (one rule)| {cq_dup['max_fanout']}      | {sg_dup['max_fanout']}      |")
    lines.append(f"| Top-firing rule       | `{cq_dup['max_fanout_rule']}` | `{sg_dup['max_fanout_rule']}` |")
    lines.append("")

    lines.append("### Top 5 Most-Fired Rules — CodeQL\n")
    lines.append("| Rule | Count |")
    lines.append("|------|-------|")
    for rule_id, count in cq_dup["top_rules"]:
        lines.append(f"| `{rule_id}` | {count} |")
    lines.append("")

    lines.append("### Top 5 Most-Fired Rules — Semgrep\n")
    lines.append("| Rule | Count |")
    lines.append("|------|-------|")
    for rule_id, count in sg_dup["top_rules"]:
        lines.append(f"| `{rule_id}` | {count} |")
    lines.append("")

    # ---- 8. Cross-tool overlap ----
    lines.append("## 8. Cross-Tool Overlap (Security + Quality)\n")
    lines.append(f"- Categories+files flagged by **both** tools (lines within 5): **{both_count}**")
    lines.append(f"- Categories+files unique to **CodeQL**:  **{only_cq}**")
    lines.append(f"- Categories+files unique to **Semgrep**: **{only_sg}**\n")

    # ---- 9. Methodology ----
    lines.append("## 9. Methodology Notes\n")
    lines.append("- Each finding is tagged with a `kind` (security / quality / other) "
                 "so the comparison can be sliced by intent.")
    lines.append("- Category is inferred first from CWE tags in the SARIF metadata "
                 "(leading zeros are normalised) and, where absent, from keyword "
                 "matching on rule IDs and rule names.")
    lines.append("- Severity vocabularies are normalised onto a common 3-tier scale "
                 "(High / Medium / Low).")
    lines.append("- Cross-tool overlap is computed per (category, filename) and requires "
                 "at least one CodeQL line within 5 lines of a Semgrep line.")
    lines.append("- Within-tool duplication is computed by grouping findings by `rule_id`. "
                 "'Max fan-out' indicates the largest single-rule alert count, which is "
                 "a proxy for pattern-driven noise.")

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(" SARIF COMPARISON TOOL ")
    print("=" * 60)

    print(f"\nLoading CodeQL SARIF:\n  {CODEQL_SARIF}")
    codeql_sarif = load_sarif(CODEQL_SARIF)

    print(f"\nLoading Semgrep SARIF:\n  {SEMGREP_SARIF}")
    semgrep_sarif = load_sarif(SEMGREP_SARIF)

    print("\nParsing findings...")
    codeql_findings = parse_findings(codeql_sarif, "CodeQL")
    semgrep_findings = parse_findings(semgrep_sarif, "Semgrep")
    all_findings = codeql_findings + semgrep_findings

    def counts_by_kind(findings, kind):
        return sum(1 for f in findings if f["kind"] == kind)

    print("\nSummary:")
    print(f"  CodeQL findings:  {len(codeql_findings)}")
    print(f"  Semgrep findings: {len(semgrep_findings)}")
    print(f"  Combined:         {len(all_findings)}")

    print("\nBy kind:")
    print(f"  CodeQL  -> security: {counts_by_kind(codeql_findings,'security'):3d}, "
          f"quality: {counts_by_kind(codeql_findings,'quality'):3d}, "
          f"other: {counts_by_kind(codeql_findings,'other'):3d}")
    print(f"  Semgrep -> security: {counts_by_kind(semgrep_findings,'security'):3d}, "
          f"quality: {counts_by_kind(semgrep_findings,'quality'):3d}, "
          f"other: {counts_by_kind(semgrep_findings,'other'):3d}")

    # Severity preview
    print("\nSeverity (overall):")
    cq_sev = severity_breakdown(codeql_findings)
    sg_sev = severity_breakdown(semgrep_findings)
    for s in ("High", "Medium", "Low"):
        print(f"  {s:7s}  CodeQL={cq_sev[s]:3d}  Semgrep={sg_sev[s]:3d}")

    # Duplication preview
    print("\nDuplication:")
    cq_dup = duplication_analysis(codeql_findings)
    sg_dup = duplication_analysis(semgrep_findings)
    print(f"  CodeQL  -> {cq_dup['distinct_rules']} rules fired, "
          f"max fan-out {cq_dup['max_fanout']} ({cq_dup['max_fanout_rule']})")
    print(f"  Semgrep -> {sg_dup['distinct_rules']} rules fired, "
          f"max fan-out {sg_dup['max_fanout']} ({sg_dup['max_fanout_rule']})")

    # ---- Write outputs ----
    print("\nWriting outputs...")

    write_csv(
        OUTPUT_DIR / "all_findings.csv",
        all_findings,
        ["tool", "rule_id", "name", "category", "kind",
         "cwes", "severity", "file", "line", "message"]
    )

    overlap_rows = overlap_analysis(all_findings)

    write_csv(
        OUTPUT_DIR / "overlap_analysis.csv",
        overlap_rows,
        ["category", "file", "codeql_count",
         "semgrep_count", "tools", "overlap"]
    )

    # CSV: per-rule duplication breakdown for both tools
    dup_rows = []
    for tool_label, findings in (("CodeQL", codeql_findings), ("Semgrep", semgrep_findings)):
        per_rule = Counter(f["rule_id"] for f in findings)
        for rule_id, count in per_rule.most_common():
            # find a sample category for this rule
            sample = next((f for f in findings if f["rule_id"] == rule_id), None)
            dup_rows.append({
                "tool":      tool_label,
                "rule_id":   rule_id,
                "category":  sample["category"] if sample else "",
                "kind":      sample["kind"] if sample else "",
                "count":     count,
            })

    write_csv(
        OUTPUT_DIR / "rule_duplication.csv",
        dup_rows,
        ["tool", "rule_id", "category", "kind", "count"]
    )

    write_markdown_report(
        OUTPUT_DIR / "comparison_report.md",
        codeql_findings,
        semgrep_findings,
        overlap_rows
    )

    print("\nDone.")
    print(f"\nOutputs saved to:\n  {OUTPUT_DIR.resolve()}")

    print("\nGenerated files:")
    for f in sorted(OUTPUT_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()