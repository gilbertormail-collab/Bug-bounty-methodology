# 01. Recon & Mapping Methodology

Everything downstream depends on this phase. The goal isn't just "find subdomains" — it's to build an attack surface map detailed enough that it tells you *which* vulnerability classes to prioritize on *which* endpoints, before you've sent a single attack payload.

---

## Phase 0 — Scope & Rules of Engagement

- Read the program policy in full. Note explicitly in-scope domains/apps/wildcards, explicitly out-of-scope assets (common: third-party-hosted support/status pages, marketing sites on shared platforms), and disallowed techniques (DoS-risk testing, automated scanners at volume, social engineering, physical testing).
- Note whether wildcard scope (`*.example.com`) is allowed — this determines whether subdomain enumeration is fair game.
- Check for a Safe Harbor statement and testing account provisioning (some programs give you test accounts; using real user data instead is often a policy violation even if technically possible).
- Keep a running notes file per target from minute one: host, first-seen date, tech, findings-in-progress. You will forget details three hours in.

## Phase 1 — Passive Recon (no packets to the target's infra beyond normal DNS/HTTP)

**Subdomain enumeration**
- Certificate transparency: `crt.sh`, `censys.io` search by SAN
- Aggregator tools: `subfinder`, `assetfinder`, `amass` (passive mode), `github-subdomains`
- DNS aggregation from multiple public sources beats any single tool — run 2–3 and merge/dedupe

**Historical & passive endpoint discovery**
- `waybackurls` / `gau` against each root domain — historical URLs frequently reveal old API versions, forgotten admin paths, and parameters that still work
- Combine with `gf` patterns to bucket URLs by likely vuln type (XSS-prone params, SSRF-prone params, SQLi-prone params) for later

**Code & secret leakage**
- GitHub/GitLab dorking for the company/product name: `org:target`, leaked `.env`, hardcoded API keys, internal hostnames in commit history or issues
- Search public package registries (npm/PyPI) for internal-looking packages the company may have accidentally published

**Passive service/asset discovery**
- Shodan / Censys for exposed services tied to the org's ASN or known IP ranges
- `BuiltWith` / Wappalyzer (via API, passively) for a first-pass tech stack read

## Phase 2 — Active Recon

**Live host & port discovery**
- Resolve the full subdomain list, then `httpx` to identify which hosts actually serve HTTP(S), status codes, titles, tech headers, redirect chains
- `naabu` / targeted `nmap` for non-standard web ports if scope allows port scanning

**Content & endpoint discovery**
- Directory/file brute-force with `ffuf` or `gobuster` using SecLists wordlists (start with a small high-signal list, escalate to bigger lists only on promising hosts — noisy scanning against everything burns time and can violate rate-limit rules)
- Virtual host discovery (same IP, different `Host:` header) — often reveals staging/internal apps not linked anywhere
- **JS bundle analysis** — download every JS file the app loads (including source maps if present) and grep them for hidden routes and secrets:
  ```
  rg -n 'sourceMappingURL|createServerReference|Next-Action|queryHash|persistedQuery|grpc-web|protobuf|new WebSocket\(|postMessage\(|api[_-]?key|secret|token' ./static ./dist ./_next ./assets
  ```
  Modern frontend builds routinely leak Next.js Server Actions, GraphQL persisted-query hashes, tRPC router/procedure names, and feature-flag strings — all of which are direct input for the access-control and API testing files later in this set.
- Check `robots.txt`, `sitemap.xml`, `/.well-known/`, and default 404 pages for structure hints
- Try common backup/leftover file patterns on discovered paths: `.bak`, `~`, `.old`, `.swp`, `.git/`, `.svn/`, `.DS_Store`

**Tech stack fingerprinting**
- HTTP response headers (`Server`, `X-Powered-By`, cookie names — `JSESSIONID` screams Java, `laravel_session` screams Laravel)
- Error pages (force a 500 if possible — stack traces are a goldmine, see the info-disclosure entry in file 06)
- Wappalyzer/`whatweb` against each live host
- Once you know the stack, go read HackTricks' stack-specific page for it (Django, Laravel, Spring, Node/Express, WordPress, etc.) — general methodology gets you 80% of the way, framework-specific quirks get you the rest

## Phase 3 — Authenticated Application Mapping

This is the step people rush and shouldn't. Time spent here directly determines how efficient Phase 4 is.

1. Register/obtain accounts at every distinct privilege level the app supports (free tier, paid tier, admin, org-owner, etc. — this is what makes the access-control testing in file 04 possible at all).
2. Browse the entire application manually through an intercepting proxy (Burp) with logging on, clicking every link, opening every settings page, triggering every workflow (signup, checkout, invite-a-user, export, delete-account) at least once per role.
3. Supplement manual coverage with authenticated spidering, but don't trust it alone — spiders miss multi-step flows and anything gated behind specific state (an empty cart, a populated cart, an in-progress onboarding wizard).
4. For every request observed, log: method, endpoint, parameters (query/body/header/cookie), auth level required, content-type, and a one-line note on what it does. A spreadsheet or Burp's own site map annotations both work — the point is that it's queryable later.
5. Identify the API paradigm(s) in use — REST, GraphQL, SOAP, gRPC-Web, tRPC, WebSocket — because each has its own testing approach (see file 06 for GraphQL/API specifics, and the tRPC note below).
6. Note every place the app: accepts a URL, accepts a file, renders user input back, uses a numeric/sequential/GUID identifier, redirects, sets a cookie, or talks to a third party (SSO, payment, webhooks). These are the seeds for the trigger table below.

## Phase 4 — Prioritization: the Quick-Win Sweep

Before deep per-class testing, run this cheap pass across every host — each check takes seconds and regularly pays out on its own:

- Verbose errors: force type errors, missing params, malformed JSON — look for stack traces/framework debug pages
- `.git/` or `.svn/` exposed (try `/.git/config` directly)
- Backup/config files at discovered paths
- Default/example credentials on anything that looks like an admin panel or internal tool
- Missing security headers (`X-Frame-Options`/`frame-ancestors`, `Content-Security-Policy`, `Strict-Transport-Security`) — feeds directly into the Clickjacking entry in file 03
- CORS headers reflecting arbitrary `Origin` with `Access-Control-Allow-Credentials: true` — feeds into file 03
- Any staging/internal subdomain from Phase 2 that's reachable without auth

## The Recon → Vulnerability Trigger Table

This is the practical "where and when" mapping. When Phase 3 mapping surfaces one of these signals, go straight to the matching methodology file/section rather than testing blindly.

| What you found in recon/mapping | Test for (file) |
|---|---|
| Any field/param that fetches a URL server-side (webhooks, avatar-from-URL, PDF/report export, link unfurling, SSO metadata URL) | SSRF (05) |
| File upload functionality | File upload RCE (06), path traversal via filename (06), XXE if XML/SVG/DOCX/XLSX accepted (02), stored XSS if filename/metadata is reflected (03) |
| XML endpoint, SOAP service, or any XML/SVG/Office-doc upload | XXE (02) |
| Sequential IDs, GUIDs, or any `user_id`/`order_id`/`file_id`-style param, especially across roles | IDOR / broken access control (04) |
| JWT in `Authorization` header or cookie | JWT attacks (04) |
| "Login with Google/Microsoft/GitHub" flow | OAuth vulnerabilities (04) |
| Search, filter, sort, or "advanced query" functionality | SQL injection, NoSQL injection (02) |
| Template/PDF/invoice/report generation, or any "preview" feature that renders user-supplied text | SSTI (02) |
| Any feature that shells out (image conversion, ping/traceroute-style diagnostic tools, video processing) | OS command injection (02) |
| `wss://` connections | WebSocket vulnerabilities (03) |
| Password reset / "forgot password" flow | Authentication vulnerabilities (04) |
| Multi-step flows with real-world state: checkout, funds transfer, coupon redemption, limited-stock purchase | Business logic (06), race conditions (06) |
| Any input reflected verbatim into the HTML response | Reflected/DOM XSS (03) |
| Any input saved and displayed later (comments, profile fields, support tickets, chat/messages) | Stored XSS (03) |
| `location.hash`, `location.search`, `postMessage`, or `document.referrer` read by JS (found via JS bundle grep) | DOM-based XSS, postMessage vulnerabilities (03) |
| Forms that change state (not just read data) | CSRF (03) — check for anti-CSRF tokens and `SameSite` cookie config |
| CORS headers present at all | CORS misconfiguration (03) |
| Redirect-style params (`?url=`, `?next=`, `?return=`, `?redirect=`) | Open redirect (06) — and check whether it also enables SSRF (05) |
| GraphQL endpoint (often `/graphql`) | GraphQL/API vulnerabilities (06) |
| `Cache-Control`, `X-Cache`, `Age`, `CDN-Cache` headers, or a CDN/reverse proxy in front of the app (Phase 2 tech fingerprint) | Web cache poisoning, web cache deception (05) |
| Load balancer/reverse proxy + app server split (common in any app behind Cloudflare/nginx/AWS ALB in front of an app server) | HTTP request smuggling, HTTP Host header attacks (05) |
| Opaque encoded blobs in cookies/params/hidden fields (Java serialized objects start `rO0`, PHP serialized data starts `O:`/`a:`, .NET ViewState is base64 XML-ish) | Insecure deserialization (06) |
| AI chatbot, AI search, or any LLM-powered feature — especially one with tool access (browsing, plugins, internal data lookup) | Web LLM attacks (06) |
| tRPC/gRPC-Web/Server Action routes found via JS bundle grep (Phase 2) | Broken function-level authorization — treat like access control (04), test each procedure at each privilege level |
| Registration/signup flow, especially with email verification or SSO account-linking | Account takeover / registration vulnerabilities — covered under Authentication (04) |

Keep this table open in a second window while you work Phase 3. As each mapping discovery lands in your notes, immediately tag it with which file/section it points to — by the time mapping is done, you'll have a prioritized, evidence-based testing queue instead of a blind checklist.

**Go deeper:** HackTricks' own recon walkthrough lives at `hacktricks.wiki/en/network-services-pentesting/pentesting-web` (the "80,443 - Pentesting Web Methodology" page) and their cross-cutting checklist at `hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology`. For API-specific mapping (REST/SOAP/GraphQL/tRPC), see their "Web API Pentesting" page — the tRPC `protectedProcedure`-without-role-check pattern they document is a very common real-world BOLA source in modern TypeScript backends.
