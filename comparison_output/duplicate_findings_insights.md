# Within-Tool Duplicate Findings: Insights and Interpretation

_This document interprets the data in `duplicate_findings_data.md`. The data tables are computed by a script from `all_findings.csv`. The interpretation below is written by hand and reflects what was observed on this specific project. Cluster IDs (CQ-1, SG-12, and so on) refer to the rows in that data file._

---

## What "duplicate" means here

A within-tool duplicate is a case where a single tool reports the same underlying issue more than once. This is different from cross-tool overlap, where both tools independently flag the same issue (covered separately at the end).

Two findings from the same tool are treated as one duplicate cluster when they sit in the same file, within two lines of each other. This captures two situations: several rules firing on a single line, and one rule firing across the adjacent lines of a single statement. The matching is done on the full file path rather than the bare file name, because several files in PyGoat are named `Dockerfile` in different folders, and matching on the name alone would wrongly merge them.

Only security findings are considered. Code-quality and code-style findings are excluded.

## A note on verification

The data file reports clusters exactly as the proximity rule finds them, with no human judgement applied. Reading those clusters against the actual PyGoat source shows that one of them is not a genuine duplicate.

In `introduction/mitre.py`, the cluster at lines 169 and 171 (SG-8 in the data file) holds a hardcoded JWT signing secret and an insecure cookie. The two-line proximity rule groups them, but the code shows they are two genuinely different vulnerabilities that simply sit close together, not one issue reported twice. This cluster should not be counted as a duplicate.

The script therefore reports 13 Semgrep clusters (29 findings, 27 percent of Semgrep's security output). Excluding SG-8 by hand brings this to the verified figure of 12 clusters (27 findings, 25 percent). CodeQL's 7 clusters were all confirmed genuine. The verified figures are used throughout the discussion below and are the conservative ones.

---

## CodeQL duplicates

CodeQL produced 7 duplicate clusters covering 14 of its 39 security findings, which is 36 percent of its security output. The clusters are listed in Table 3 of the data file.

The pattern behind CodeQL's duplication is that it runs separate queries for separate security properties, and several of these can apply to the same line of code.

- **CQ-2 (views.py:260)** is the clearest example of two categories on one line. A single XML parser is flagged once as an XXE risk and once as an XML-bomb risk. Both are correct, but they describe two symptoms of the same misconfigured parser. One fix removes both alerts.
- **CQ-3, CQ-4, CQ-5 (views.py:291, 305, 319)** are the same story repeated on three cookie-setting lines. Each line is flagged once for a missing `Secure` flag and once for being exposed to client-side scripts. Across the three lines this produces six alerts for what a developer would address as three cookie fixes.
- **CQ-1, CQ-6, CQ-7** are the other shape of CodeQL duplication: the same rule firing on adjacent lines. CQ-1 is one cookie pattern set in two branches of a block, CQ-6 is one command built from input across two branches, and CQ-7 is the same tainted values logged on two consecutive lines. In each case the duplication reflects how the source is written rather than two genuinely separate problems.

The important point is that CodeQL's duplication is a direct consequence of its design. Each query checks a distinct property, so a single piece of vulnerable code legitimately triggers several queries. This cannot be removed by changing configuration. It can only be handled when a developer triages the results.

## Semgrep duplicates

Semgrep's verified count is 12 duplicate clusters covering 27 of its 108 security findings, which is 25 percent of its security output. (The data file lists 13; SG-8 is excluded for the reason given above.) The clusters are listed in Table 4 of the data file.

The pattern behind Semgrep's duplication is different. It comes mostly from running several rule packs at once. The four packs used in this project (`p/python`, `p/django`, `p/security-audit`, `p/owasp-top-ten`) were written independently and overlap in coverage, so the same construct is matched by more than one rule.

- **SG-12 (views.py:430-432)** is the strongest example. A single dangerous `subprocess` call with `shell=True` triggers three separate rules from three separate packs, each landing on a slightly different line of the same call. Three alerts, one fix.
- **SG-3, SG-4, SG-11** are the same effect on deserialization. The same `pickle` usage is flagged by both a framework-specific rule and a general Python rule wherever it appears.
- **SG-7 and SG-13** show it for weak cryptography, where an MD5 use is flagged both by a general "MD5 is weak" rule and by a more specific "MD5 used as a password" rule.
- **SG-9 (mitre.py:217-218)** shows it for code injection, where one `eval` on user input is caught by both a Django rule and a general Python rule.
- **SG-10 (views.py:17-19)** is a slightly different case: one rule firing on three consecutive XML import lines. The fix, switching to a safe XML library, resolves all three at once.

The important point is that Semgrep's duplication is mostly a consequence of a configuration choice, the stacking of overlapping packs for broader coverage. Unlike CodeQL's, it can be reduced by trimming the packs, at the cost of some coverage.

## The two kinds of duplication compared

Both tools duplicate a meaningful share of their security output, and proportionally CodeQL is slightly higher (36 percent against 25 percent). But the cause differs, and so does the remedy. Semgrep's redundancy comes from overlapping rule packs and can be tuned away at configuration time. CodeQL's comes from its property-by-property query design and can only be handled during triage. To a developer reading the results, both look the same: the alert count is larger than the number of distinct problems to fix. After collapsing the clusters, CodeQL's 39 findings represent 32 distinct issues and Semgrep's 108 represent 93.

---

## Cross-tool overlap

Separately from within-tool duplication, there are twelve cases where both tools independently flagged the same issue. These are listed in Table 5 of the data file. Because two different analysis methods agree on them, they are the highest-confidence findings in the dataset.

Two things stand out.

First, almost all of the overlaps are classic dataflow-to-a-dangerous-sink vulnerabilities: code injection through `eval`, command injection through `subprocess`, SQL injection, deserialization through `pickle`, SSRF, and weak cryptography through MD5. These are the cases where the dangerous operation is unmistakable, and where both a mature dataflow query and a community pattern rule reliably exist. The two outliers, a cookie issue and a Flask configuration issue, are single-line patterns that both tools match directly. In other words, the tools agree precisely where the vulnerability has a well-defined sink and diverge where detection needs more judgment.

Second, the two tools agree on the severity in only six of the twelve cases. When they disagree, CodeQL always rates the issue higher than Semgrep, and the disagreements include the SQL injection, which CodeQL marks High and Semgrep marks Medium. For a developer triaging by severity, this means the perceived urgency of an identical bug depends on which tool's label is read.

---

## Conclusion

Within-tool duplication is a real and measurable source of noise for both tools, affecting roughly a quarter to a third of their security findings. The cause is structural in each case, the stacking of overlapping rule packs for Semgrep and the property-by-property query design for CodeQL, and only the former can be addressed by configuration. The cross-tool overlaps, by contrast, are the most trustworthy findings in the study, and they cluster on the canonical sink-based vulnerabilities. The severity disagreement on half of those overlaps is a small but concrete usability problem: even when both tools agree that something is wrong, they do not always agree on how urgent it is.
