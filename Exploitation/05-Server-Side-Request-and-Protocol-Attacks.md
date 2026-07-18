# 05. Server-Side Request & Protocol-Level Attacks

Covers: SSRF, HTTP Request Smuggling, HTTP Host Header Attacks, Web Cache Poisoning, Web Cache Deception.

This family exploits the *infrastructure* around the application — proxies, load balancers, caches, and the server's own outbound requests — rather than the application logic directly. It requires understanding the request path (what's in front of the app: CDN, reverse proxy, load balancer) more than any other category, which is why Phase 2's tech fingerprinting matters so much here.

---

## 1. Server-Side Request Forgery (SSRF)

**Root cause:** the server makes an HTTP (or other protocol) request to a URL that's fully or partially attacker-controlled, letting the attacker use the server as a proxy to reach systems it can access but the attacker can't reach directly (internal network, cloud metadata endpoints, localhost-bound admin interfaces).

**Where to find it:** webhooks/callback URL fields, "import from URL" or "fetch avatar from URL," PDF/screenshot generation of a given URL, link-preview/unfurling features, SSO/SAML metadata URL fields, XML external entities (chains with file 02's XXE), any server-side integration that takes a user-supplied hostname or URL fragment even if not the full URL.

**Methodology:**
1. For full-URL-control cases, start with a request to your own OAST listener to confirm the server actually makes outbound requests (baseline, no target infra touched yet).
2. Probe internal targets: `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254/latest/meta-data/` (cloud instance metadata — AWS/GCP/Azure all use link-local addressing here, exact path differs by provider), internal hostnames guessed from recon (`internal-api`, `admin.internal`, etc.), and common internal ports (`:8080`, `:6379` Redis, `:9200` Elasticsearch, `:5000`, `:3000`).
3. For partial-URL-control (e.g., only a path segment or subdomain is user-controlled, or the app validates the domain but you control a path/query), test whether the validation can be bypassed by protocol/parser confusion rather than a full domain swap.
4. For blind SSRF (no response body returned, but a request is plausibly made), confirm via OOB — a DNS lookup or HTTP hit on your listener is proof even with zero visible output.
5. Escalate blind SSRF where possible: even without response bodies, differences in response time or status code between a reachable-vs-unreachable internal target can be used to port-scan the internal network blind.
6. If you get response bodies back, use SSRF to read internal-only content, hit internal APIs without their normal auth (many internal services trust "if it's an internal IP calling, it's fine"), and specifically check cloud metadata endpoints for credentials.

**Probes:**
```
http://127.0.0.1/
http://localhost/admin
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://[::1]/
http://0177.0.0.1/          (octal-encoded localhost)
http://2130706433/          (decimal-encoded localhost)
http://attacker-oast.net/   (baseline OOB confirmation)
```

**Bypass notes:** if a domain allowlist/denylist is enforced, try alternate IP encodings (decimal/octal/hex), embedding credentials-style syntax to confuse the parser (`http://allowed-host@attacker.com/`, `http://attacker.com#allowed-host`), DNS rebinding (resolve an attacker-controlled domain to an internal IP, timed around the validation-vs-request-execution gap), and open redirects on the *target's own domain* as a bounce (`http://target.com/redirect?to=http://169.254.169.254/` — if the fetcher follows redirects, an allowlist check on the initial URL alone is bypassed).

**Tools:** Burp Collaborator (or any OAST listener) for blind confirmation and internal port-scan timing; a small internal-IP/port wordlist for Intruder-driven sweeps where the program's rules allow it.

**When to prioritize:** immediately whenever Phase 3 mapping finds any URL-fetching feature — see trigger table in file 01. Consistently one of the highest-impact categories (cloud credential theft, internal network access) when it lands.

**Go deeper:** PortSwigger Academy "SSRF" topic; HackTricks `pentesting-web/ssrf-server-side-request-forgery`; Orange Tsai's SSRF bypass research (blog.orange.tw) for advanced URL-parser-confusion techniques once you've exhausted the basics above.

---

## 2. HTTP Request Smuggling

**Root cause:** a front-end (proxy/load balancer/CDN) and back-end server disagree about where one HTTP request ends and the next begins — almost always because of how they each interpret `Content-Length` vs `Transfer-Encoding` headers when both are present (or ambiguously present) in the same request.

**Where to find it:** any app behind a reverse proxy/CDN/load balancer in front of an application server (very common — check Phase 2 tech fingerprinting for a proxy layer at all). Not present at all in single-server setups with no intermediary.

**Methodology:**
1. Establish whether there even *is* a front-end/back-end split — no intermediary, no smuggling.
2. Send low-risk canary probes to detect front-end/back-end parsing disagreement before attempting anything with real side effects:
   ```
   Host: attacker.tld
   Content-Length: 7

   GET /404 HTTP/1.1
   X: Y
   ```
   and a `TRACE`-based reflection canary, and a duplicate/malformed `Content-Length` (multiple `Content-Length` headers with different values, or a `Content-Length` with a leading zero/space) — these are quick, low-side-effect ways to reveal parsing disagreement before running the full desync methodology.
3. Classify the discrepancy type based on how front-end and back-end each handle `Content-Length` (CL) vs `Transfer-Encoding` (TE):
   - **CL.TE** — front-end uses `Content-Length`, back-end uses `Transfer-Encoding`
   - **TE.CL** — front-end uses `Transfer-Encoding`, back-end uses `Content-Length`
   - **TE.TE** — both use `Transfer-Encoding`, but one can be tricked into ignoring it via header obfuscation (e.g. `Transfer-Encoding: xchunked`, extra whitespace, or a duplicate header)
4. Confirm with a timing-based technique first (safer, no impact on other users): construct a request whose smuggled remainder should cause the back-end to hang waiting for more data if the discrepancy exists.
5. Once confirmed, move to actual exploitation only within program rules — capturing another user's request (request smuggling can leak other users' data/session tokens into your own response) is powerful but also the kind of test with real cross-user impact, so be precise and stop as soon as impact is proven.

**Probe pattern (CL.TE detection skeleton):**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Tools:** `smuggler.py` (defparam) for automated CL/TE/CL.TE classification, Burp's HTTP Request Smuggler extension, Burp Repeater with "update Content-Length" disabled (essential — Burp will otherwise silently fix the exact header you're trying to desync).

**When to prioritize:** as soon as Phase 2 tech fingerprinting confirms a proxy-in-front-of-app-server architecture. High-severity when confirmed, but confirm with the low-impact timing/canary technique before doing anything with cross-user side effects.

**Go deeper:** PortSwigger Academy "Request smuggling" topic; HackTricks `pentesting-web/http-request-smuggling`; James Kettle/PortSwigger Research's original "HTTP Desync Attacks" paper (portswigger.net/research) is the foundational research this entire technique is built on and worth reading in full.

---

## 3. HTTP Host Header Attacks

**Root cause:** the application trusts the client-supplied `Host` header (or `X-Forwarded-Host`/similar) for security-relevant logic — generating absolute URLs, routing, or cache keys — without validating it against the actual set of hostnames the app is meant to serve.

**Where to find it:** password reset flows (already covered in file 04 — this *is* a Host header attack), any feature that constructs an absolute URL server-side (emails with links, OAuth redirects, SSO metadata), routing-based architectures where multiple backends sit behind one front door distinguishing by `Host`.

**Methodology:**
1. Test whether the app functions identically with an arbitrary `Host` header — if so, it's likely not validating it at all, which is the precondition for everything below.
2. Test password reset poisoning specifically (see file 04, section 2) — this is the single most common high-impact instance of this bug class.
3. Test routing-based SSRF: in architectures where a front-end routes to different back-ends based on `Host`, supplying an internal hostname as `Host` can sometimes route your request to an internal-only service.
4. Test cache poisoning via Host header if a cache sits in front of the app and doesn't include `Host` in its cache key while the origin uses it to build absolute URLs in the response (chains directly into the Web Cache Poisoning section below).
5. Try `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-URL`, and a duplicated `Host` header — different frameworks/proxies honor different override headers, and testing only the raw `Host` header misses this.

**Probe pattern:**
```
POST /forgot-password HTTP/1.1
Host: attacker.com

email=victim@example.com
```

**Tools:** Burp Repeater (manual header manipulation is really all this needs).

**When to prioritize:** always test alongside password reset (file 04) and web cache poisoning (below) — it's the enabling condition for both.

**Go deeper:** PortSwigger Academy "HTTP Host header attacks" topic; HackTricks `pentesting-web/host-header`.

---

## 4. Web Cache Poisoning

**Root cause:** a cache stores a response keyed on only *some* of the request (typically just the URL path), while the origin server's response actually varies based on something *not* included in that cache key (a header, a cookie, a query param the cache ignores) — so a malicious response generated for one request gets served to everyone else who requests that same cached URL.

**Where to find it:** any app served through a CDN/cache (`Cache-Control`, `X-Cache`, `Age`, `CDN-Cache-Control`-style headers seen in Phase 2 recon).

**Methodology:**
1. Identify unkeyed inputs — headers/params that affect the response but aren't part of the cache key. A reliable method: add a cache-busting query param to guarantee a fresh cache entry each test, then send probe headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, custom headers) one at a time and check if each one changes the response *and* whether that changed response then gets cached and re-served on a follow-up request without the header.
2. Once an unkeyed input that affects the response is found, craft a payload in that input that produces a genuinely harmful cached response — most commonly, injecting a header value that gets reflected into a `<script>` src or similar sink, achieving cached/persistent XSS served to every subsequent visitor of that URL.
3. Verify persistence by requesting the same URL from a clean session/browser (or via curl with no special headers) — if the malicious response comes back, the poisoning is confirmed live, not just theoretical.
4. Be deliberate about cleanup/impact scope — a confirmed cache poisoning PoC affects real visitors until the cache entry expires or is purged; use cache-busting params during testing and confirm on a URL variant you control rather than the site's actual high-traffic landing page where practical.

**Probe pattern:**
```
GET /?cachebuster=12345 HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

(then check if a follow-up request to the same cachebuster URL, without the header, reflects attacker.com — proving the header was unkeyed but response-affecting, and that the poisoned response got cached)
```

**Tools:** Burp's "Param Miner" extension automates unkeyed-input discovery (`Guess headers` / `Guess params` functions), which is the practical way to do this at scale rather than testing headers one by one by hand.

**When to prioritize:** whenever Phase 2 recon shows caching headers/CDN presence — see trigger table in file 01.

**Go deeper:** PortSwigger Academy "Web cache poisoning" topic; HackTricks `pentesting-web/cache-deception`; James Kettle/PortSwigger Research's "Practical Web Cache Poisoning" paper (portswigger.net/research) for the original methodology this topic is based on.

---

## 5. Web Cache Deception

**Root cause:** the opposite failure mode from poisoning — the cache is tricked into storing a response that was supposed to be *dynamic and user-specific* under a URL that *looks* static, because the cache's rules for "what's cacheable" (often based on file extension) don't match the origin's rules for "what's user-specific."

**Where to find it:** apps with authenticated, user-specific pages (account settings, order history, API keys page) served through a cache/CDN that makes caching decisions based on URL patterns like file extensions.

**Methodology:**
1. Identify a sensitive, authenticated, user-specific page.
2. Append a path segment that looks like a static asset the cache would treat as cacheable, while many web frameworks still route it to the same dynamic handler (path confusion): `/account/settings/nonexistent.css`, `/account/settings%2f..%2fnonexistent.js`, or a trailing static-looking segment depending on the framework's routing rules.
3. As the victim (your own second test account, or reason through it carefully if only one account is available), request that crafted URL while authenticated — if the framework still serves the real dynamic/sensitive content at that URL, and the cache stores it because the extension looked static, the sensitive response is now cached and will be served to the *next* visitor of that exact URL regardless of their own auth.
4. Confirm by requesting the same crafted URL unauthenticated (or as a different user) and checking whether the first victim's sensitive data comes back from cache.

**Probe pattern:**
```
As victim (authenticated):
GET /my-account/api-keys/x.css HTTP/1.1

As attacker (unauthenticated, same URL, shortly after):
GET /my-account/api-keys/x.css HTTP/1.1

(if the attacker's response contains the victim's API keys, the cache deception is confirmed)
```

**Tools:** Burp Repeater with two sessions (victim + attacker) side by side.

**When to prioritize:** alongside web cache poisoning testing — same recon trigger (CDN/cache presence), different mechanism, worth testing both whenever one applies.

**Go deeper:** PortSwigger Academy "Web cache deception" topic; HackTricks `pentesting-web/cache-deception`.
