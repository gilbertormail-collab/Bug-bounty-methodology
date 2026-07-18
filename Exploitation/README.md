# Web Exploitation Methodology for Bug Bounty

A personal testing methodology built from the current **PortSwigger Web Security Academy** topic list and the **HackTricks `pentesting-web`** section. Every vulnerability class gets its own self-contained playbook: what it is, where it shows up, how to test for it step by step, and when in an engagement to prioritise it.

This is written for *authorized* testing — bug bounty programs (HackerOne/Bugcrowd/company-run) and scoped pentests. Everything here assumes you have permission to test the target and are staying inside the program's defined scope and rules of engagement. That's not a disclaimer bolted on — "confirm scope" is genuinely step zero of any real methodology, because out-of-scope findings usually don't pay out and can get you banned from a program.

## How this set is organised

| File | Covers |
|---|---|
| `01-Recon-and-Mapping-Methodology.md` | Scope confirmation, passive/active recon, attack surface mapping, and a **recon-finding → vulnerability-to-test trigger table** (the practical answer to "where and when") |
| `02-Injection-Vulnerabilities.md` | SQL injection, NoSQL injection, OS command injection, XXE, SSTI, LDAP injection |
| `03-Client-Side-Vulnerabilities.md` | XSS (reflected/stored/DOM), CSRF, Clickjacking, CORS misconfiguration, prototype pollution, postMessage vulnerabilities, WebSocket vulnerabilities |
| `04-Access-Control-Auth-and-Session.md` | Broken access control/IDOR, authentication vulnerabilities, OAuth vulnerabilities, JWT attacks |
| `05-Server-Side-Request-and-Protocol-Attacks.md` | SSRF, HTTP request smuggling, HTTP Host header attacks, web cache poisoning, web cache deception |
| `06-Business-Logic-Files-and-Misc-Vulnerabilities.md` | Business logic flaws, file upload vulnerabilities, race conditions, path traversal, insecure deserialization, GraphQL/API vulnerabilities, information disclosure, open redirect, web LLM attacks |

## The standard entry format

Every vulnerability in files `02`–`06` follows the same structure so you can scan quickly mid-engagement:

- **Root cause** — the one-sentence "why this happens"
- **Where to find it** — concrete indicators in the app that raise your suspicion
- **Methodology** — numbered step-by-step testing process
- **Probes / payloads** — copy-pasteable starting points
- **Bypass notes** — what to try when the obvious payload gets filtered/WAF'd
- **Tools**
- **When to prioritize** — what should trigger you to test this *now* vs. later
- **Go deeper** — the specific PortSwigger Academy topic and HackTricks page to read in full, plus real-world research to study

## Suggested engagement workflow

1. **Scope & rules of engagement** — read the program policy fully: in-scope assets, disallowed techniques (many programs forbid automated scanners, DoS-risk testing, or social engineering), disclosure timeline, and whether the program allows testing on production data.
2. **Recon & mapping** (file 01) — build your attack surface map before you touch a single payload.
3. **Quick-win sweep** — cheap, high-signal checks across the whole surface: verbose errors, exposed `.git`/backups, default creds, missing security headers, debug endpoints. Takes an hour, regularly pays out.
4. **Systematic per-class testing** — walk your attack surface map against the trigger table in file 01. Don't blindly throw every payload at every field; let what you *found* in recon tell you what to *test*.
5. **Chain for impact** — a low/info finding (open redirect, verbose error, CORS misconfig) is often the missing link that turns another bug into something critical. Bug bounty triagers reward demonstrated impact far more than theoretical severity.
6. **Report well** — see below.

## Reporting checklist

A technically correct finding with a bad report gets down-triaged or ignored. Before submitting:

- [ ] One vulnerability per report (don't bundle unrelated findings)
- [ ] Exact reproduction steps a stranger could follow with no context — full requests/responses, not descriptions of them
- [ ] Working proof of impact, not just theoretical description (e.g., an actual read file/extracted record/XSS firing in a screenshot or short video, not "this could lead to...")
- [ ] Realistic severity/CVSS estimate, and honest about what you could *not* prove
- [ ] A suggested remediation (even one line) — it reads as more professional and often speeds up triage
- [ ] Re-check the program's scope and disallowed-technique list one more time before hitting submit

## Primary sources this is distilled from

- **PortSwigger Web Security Academy** — portswigger.net/web-security (free, the current canonical topic list is what files `02`–`06` are structured around)
- **HackTricks — Pentesting Web** — hacktricks.wiki/en/pentesting-web, especially the "Web Vulnerabilities Methodology" and "Web Vulns List / PoCs & Polyglots" pages
- **OWASP Web Security Testing Guide (WSTG)** and **OWASP Cheat Sheet Series**
- **PayloadsAllTheThings** (github.com/swisskyrepo/PayloadsAllTheThings) for payload depth per category
- **PortSwigger Research** (James Kettle et al.) for request smuggling and cache poisoning — the papers behind those two topics
- **Orange Tsai** (blog.orange.tw) for advanced SSRF and deserialization research
- **PentesterLand's "Awesome Bug Bounty Writeups"** and **HackerOne Hacktivity**, filtered by vulnerability class, for current real-world examples to calibrate against

Once recon (file 01) fingerprints the specific tech stack, HackTricks also has dedicated stack-specific pages (framework/CMS-specific tricks) that go deeper than general methodology can — worth a targeted look once you know exactly what you're up against.
