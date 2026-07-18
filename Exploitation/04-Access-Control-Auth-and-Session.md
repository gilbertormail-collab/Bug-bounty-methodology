# 04. Access Control, Authentication, and Session

Covers: Broken Access Control / IDOR, Authentication Vulnerabilities, OAuth Vulnerabilities, JWT Attacks.

This is consistently the highest-value category in bug bounty — access control bugs are common, easy to demonstrate with undeniable impact (you're looking at someone else's data), and don't require bypassing a WAF or filter to prove. It's also the category where having multiple test accounts at different privilege levels (Phase 3 of file 01) is non-negotiable — you cannot test this properly with only one account.

---

## 1. Broken Access Control / IDOR

**Root cause:** the server checks that a request is *authenticated* but doesn't independently check that the authenticated user is *authorized* for the specific object or action being requested.

**Where to find it:** any endpoint that takes an object reference — `user_id`, `order_id`, `file_id`, `invoice_id`, `conversation_id` — in a URL, query param, body, or even a header. Sequential integers are the classic tell, but GUIDs are not immune (the object reference itself being unguessable doesn't matter if you can obtain a *valid* one belonging to another user through some other channel — a shared list, an export, another IDOR).

**Methodology:**
1. Using your lowest-privilege test account, map every endpoint that takes an object reference (this should already be flagged from Phase 3 mapping in file 01).
2. **Horizontal escalation:** as User A, request User B's object reference (obtained via a second test account) on the same endpoint/role level. Try it via the normal UI-driven flow first, then via direct API calls (an endpoint might be protected in the UI's normal flow but reachable directly).
3. **Vertical escalation:** as a low-privilege user, request endpoints/actions that should require a higher role (admin panels, admin-only API routes found via Phase 2 JS-bundle grep — those tRPC/GraphQL/Next.js Server Action names you extracted are exactly what to target here).
4. Test every HTTP method on each endpoint, not just the one the UI uses — a `GET` might be protected while `PUT`/`DELETE`/`PATCH` on the same resource isn't, or vice versa.
5. Test with the object reference in every location it might be duplicated (URL path, query string, JSON body, header) — some apps check authorization against one location and use a different one for the actual lookup.
6. Check "list"/"export"/"search" endpoints specifically — access control on a single-object endpoint is often correct while the bulk/export version of the same data leaks other users' records.
7. For multi-tenant apps (orgs/workspaces), test cross-tenant access specifically — this is IDOR's highest-impact variant and a distinct thing to check beyond same-tenant horizontal access.

**Probe pattern:**
```
Baseline (your own object, as User A):
GET /api/orders/1001

Test (User B's object, using User A's session):
GET /api/orders/1002

Also test method + reference-location variants:
DELETE /api/orders/1002
PATCH /api/users/1002/role  { "role": "admin" }
GET /api/orders?user_id=1002
```

**Bypass notes:** if numeric IDs are replaced with GUIDs specifically to block enumeration, look for any place a valid GUID belonging to another user leaks (list endpoints, exports, URLs shared in emails/notifications, referenced in front-end JS state) rather than trying to guess GUIDs.

**Tools:** Burp (manual, with two authenticated sessions open in parallel — Burp's "Autorize" extension automates re-testing every request with a lower-privileged session's cookies).

**When to prioritize:** first thing after Phase 3 mapping is done and you have multiple role-level accounts — this is usually the highest ROI category to start with.

**Go deeper:** PortSwigger Academy "Access control" topic; HackTricks `pentesting-web/authentication-bypass` and their "Web API Pentesting" page for the tRPC/BOLA pattern specifically.

---

## 2. Authentication Vulnerabilities

**Root cause:** a broad category — any weakness in how identity is established or maintained: weak lockout/rate-limiting, predictable tokens, logic flaws in multi-step auth flows, or session management gaps.

**Where to find it:** login, registration, password reset, MFA setup/verification, "remember me," session handling.

**Methodology:**
1. **Username enumeration** — compare responses (error message wording, response time, status code) between a valid and invalid username on login, registration, and password reset forms. Even a few-millisecond timing difference is enough to automate enumeration.
2. **Brute-force / rate limiting** — check whether lockout exists at all, and if it does, whether it can be bypassed: rotating `X-Forwarded-For`, alternating between slightly different valid usernames, or racing multiple attempts in parallel before the lockout counter updates (see race conditions in file 06 — this is a very common race-condition target).
3. **Password reset flaws** — check token entropy/predictability, whether the token is properly invalidated after use and after a set time, and specifically test **Host header poisoning**: intercept the reset request, set `Host:` (or add `X-Forwarded-Host:`) to an attacker-controlled domain, and check whether the reset email's link uses that attacker domain — if so, the real token gets sent to an attacker-controlled server when the victim clicks it.
4. **MFA bypass** — test whether MFA is enforced server-side or only gates the UI flow: after entering a valid password, try navigating directly to the post-login area, or replaying the pre-MFA session token/cookie against authenticated endpoints. Check whether the MFA code is validated in a way that leaks correctness (response differs for right-length-wrong-code vs wrong-length), and whether it's rate-limited (6-digit codes are brute-forceable without a lockout).
5. **Session management** — check session token entropy, whether tokens are invalidated on logout and on password change, whether multiple concurrent sessions are intentional, and cookie flags (`HttpOnly`, `Secure`, `SameSite`).
6. **Registration / account-takeover-via-signup** — test signup with an email that already exists and see if it silently links/overwrites instead of erroring (pre-hijacking pattern); for SSO-linked signup, test whether an unverified email claim from an identity provider is trusted to auto-link to an existing account. Also check for exploits such as puny-code account takeover.
7. **Multiple credentials on 1 request** — test if you can test multiple credentials in 1 request on login forms and test password reset forms to see if it will send a reset link to more than 1 email.

**Probe pattern (password reset Host header poisoning):**
```
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

email=victim@example.com
```
Then check the resulting email for whether the reset link points to `attacker.com`.

**Bypass notes:** if `X-Forwarded-Host` is ignored, try `X-Forwarded-Server`, `X-Host`, `X-Original-URL`, or altering the raw `Host` header itself — different frameworks trust different headers for URL generation.

**Tools:** Burp Intruder (enumeration/brute-force testing, respecting program rate-limit rules), a disposable mailbox you control for reset-link inspection.

**When to prioritise:** immediately for any password reset flow found in mapping (high value, low effort); MFA/session testing once you understand the app's full auth flow.

**Go deeper:** PortSwigger Academy "Authentication" topic; HackTricks `pentesting-web/reset-password` and `pentesting-web/registration-vulnerabilities` (their pre-hijacking write-up, referencing Microsoft's original research, is the best structured treatment of registration-flow account takeover).

---

## 3. OAuth Vulnerabilities

**Root cause:** OAuth is a delegation protocol with several places implementers routinely get wrong: trusting client-supplied redirect targets, not binding the authorization flow to the session that started it, or over-trusting claims from the identity provider.

**Where to find it:** any "Login with Google/Microsoft/GitHub/etc." flow, and any "connect your account" integration flow.

**Methodology:**
1. Intercept the full flow and identify: `redirect_uri`, `state`, `scope`, and where the resulting code/token gets exchanged.
2. **`redirect_uri` validation** — test whether it's validated by exact match, prefix match, or not at all. Try appending a path (`https://target.com/callback.attacker.com`), swapping to a fully attacker-controlled domain, and open-redirect chaining (if the legitimate app has an open redirect anywhere — see file 06 — check if it can be used as the `redirect_uri` to smuggle the auth code out to an attacker-controlled endpoint while still passing a naive "starts with target.com" check).
3. **`state` parameter** — check if it's present, unpredictable, and actually validated on return (missing/unchecked `state` is a CSRF-on-OAuth-flow issue, letting an attacker link their own third-party account to a victim's session).
4. **Scope manipulation** — check if requested scope can be widened in the client-side-initiated request beyond what the app's flow normally requests.
5. **Account linking by unverified email** — if the identity provider allows unverified emails in its claims and the app auto-links/creates an account based on email alone, this is an account-takeover path (register an IdP account with the victim's email before they do, or use a provider that doesn't require email verification).

**Probe pattern (redirect_uri manipulation):**
```
Original:
GET /oauth/authorize?client_id=X&redirect_uri=https://target.com/callback&state=abc&scope=profile

Test:
GET /oauth/authorize?client_id=X&redirect_uri=https://target.com.attacker.com/callback&state=abc&scope=profile
GET /oauth/authorize?client_id=X&redirect_uri=https://target.com/callback%2f..%2f..%2fattacker&state=abc&scope=profile
```

**Tools:** Burp (manual flow interception is essential here — automated scanners rarely handle multi-step OAuth flows well).

**When to prioritize:** any SSO login option found in Phase 3 mapping.

**Go deeper:** PortSwigger Academy "OAuth authentication" topic (their redirect_uri bypass lab progression covers exact-match vs partial-match vs no-validation cases); HackTricks `pentesting-web/oauth-to-account-takeover`.

---

## 4. JWT Attacks

**Root cause:** JWTs are self-contained and cryptographically signed, but implementations frequently get the *verification* step wrong — trusting header claims that should be fixed server-side config instead.

**Where to find it:** `Authorization: Bearer <jwt>` headers, or JWTs stored in cookies — check the token structure (three base64url segments separated by `.`) on any auth-related request from Phase 3 mapping.

**Methodology:**
1. Quick wins with `python3 jwt_tool.py -M at -t "https://api.example.com/api/v1/user/12"  -rh "Authorization: Bearer eyJhbG...<JWT Token>"`. Look for green lines.
2. Decode the token (header + payload) and note the `alg`, `kid`, `jku`/`jwk`, and all claims — especially anything that looks like a role/permission (`role`, `admin`, `scope`).
3. **`alg: none`** — try stripping the signature entirely and setting `alg` to `none` (and case variants: `None`, `NONE`) — some libraries historically accept this.
4. **Algorithm confusion (RS256 → HS256)** — if the app uses RS256 (asymmetric: public key verifies, private key signs), try re-signing the token as HS256 using the *public key* as the HMAC secret. If the verification library doesn't enforce which algorithm family is expected, it may use the public key (which you can often obtain from a `/jwks.json` endpoint or a certificate) as an HMAC secret and accept your forged token.
5. **Weak signing secret (HS256)** — attempt offline brute-force of the HMAC secret against a wordlist.
6. **`kid` (Key ID) injection** — if the `kid` header claim is used to look up a key (file path, DB query, or command), test path traversal (`kid: ../../../../dev/null`, paired with an empty-string-HMAC-signed token, is a classic trick against filesystem-based key lookups) or injection into whatever backend lookup `kid` drives.
7. **`jku`/`jwk` header injection** — if the token specifies where to fetch the verification key from (`jku`), test whether you can point it at a JWKS you host yourself, then sign the token with your own keypair matching that JWKS.
8. **Claim tampering after confirming a bypass** — once you have any working forgery technique, escalate by modifying claims like `role`, `sub`, `scope` to test what access you gain.

**Probe pattern (algorithm confusion, conceptual):**
```
1. Obtain the app's RSA public key (JWKS endpoint, or a cert used elsewhere in the app).
2. Craft a new token: header {"alg":"HS256","typ":"JWT"}, same/modified payload.
3. Sign using HMAC-SHA256 with the RSA public key's exact bytes/PEM as the secret.
4. Send the forged token in place of the original.
```

**Tools:** `jwt_tool` (automates most of the above checks, including alg confusion and kid injection probing), Burp's "JSON Web Token" extension for manual editing in Repeater, `hashcat`/`john` for offline HS256 secret brute-force.

**When to prioritize:** immediately whenever a JWT is spotted in Phase 3 mapping — these checks are fast and JWT misconfigurations are common enough to always be worth the few minutes it takes.

**Go deeper:** PortSwigger Academy "JWT attacks" topic; HackTricks `pentesting-web/hacking-jwt-json-web-tokens` (their `kid`-based RCE and JWE/signed-JWT confusion write-ups go further than the general alg-confusion case above).
