# Real-world slop / false-positive corpus (gathered by scout agents)

Ground-truth-rejected vulnerability reports, for triage testing. Sources in each entry.

## Reproducible REAL vulns (validated in sandbox — for the "confirmed" class)
| Package | Affected | Fixed | CVE | Class | Validated |
|---|---|---|---|---|---|
| hydra-core | 1.3.3 | 1.3.4 | CVE-2026-68508 | code injection (instantiate _target_) | ✅ REPRO/NOT |
| joblib | 1.1.0 | 1.2.0 | CVE-2022-21797 | eval injection (pre_dispatch) | ✅ REPRO/NOT |
| reportlab | 3.6.12 | 3.6.13 | CVE-2023-33733 | eval sandbox escape | ✅ REPRO/NOT |
| PLY | 3.11 | — | CVE-2025-56005 | pickle RCE (yacc picklefile) | not yet validated |
| gdown | 5.2.1 | 5.2.2 | CVE-2026-40491 | tar-slip path traversal | not yet validated |
| langchain-core | 0.3.80 | 0.3.81 | CVE-2025-68664 | Jinja2 SSTI | not yet validated |

## Real FALSE-POSITIVES / rejected reports (for the "should NOT confirm" class)
- **future / CVE-2025-50817** (WITHDRAWN/disputed): "RCE via unintended import of test.py on sys.path" — retracted as "a documented feature of Python's import system." Cleanest real false-positive. https://github.com/advisories/GHSA-xqrq-4mgf-ff32
- **urllib3 SSLv2** (Seth Larson): scanner flagged SSLv2 usage; the code explicitly DISABLES SSLv2. Context-blind false positive. https://sethmlarson.dev/slop-security-reports
- **dnsmasq CVE-2025-12198/12199/12200** (VulDB rejected): "exploits" require replacing /etc/dnsmasq.conf — if you can replace the config you don't need the parser bug. https://www.openwall.com/lists/oss-security/2025/10/27/1
- **Kamailio CVE-2025-12204..12207** (disputed/spam): same config-file attack model; core dev: "clearly spam". https://vuldb.com/?id.329876
- **Hibernate persistence.xml** reports: edit server-side config to exploit — attacker who can edit it already owns the box. https://www.herodevs.com/blog-posts/the-security-slop-slavine-why-ai-cant-replace-domain-expertise
- **npm supabase 2.105.0-beta.9 / GHSA-x96m-c5fj-q75c** (WITHDRAWN): "malware detection was a false positive."
- **Duplicate withdrawals (real bugs, double-tracked)**: mistune, nltk, pdfminer.six, justhtml, picklescan (~10 same-day).

## curl AI-slop (C code — NOT reproducible in Python sandbox; text-only baseline-fooling test)
21 reports in realdata/curl_slop_cases.json. Resolutions: mostly N/A, some Spam, one Informative.
Slop-pattern taxonomy: generic-unsafe-function (strcpy/format-string, no call site), true-but-not-a-vuln
(DES-in-NTLM is spec-mandated), wrong-target (test harness code), wrong-layer (proxy concern blamed on
client), fake-follow-up (poses as bypass of a real prior fix), content-free hedge, AI flattery preamble
("Curl is a software that I love... I apologize").
