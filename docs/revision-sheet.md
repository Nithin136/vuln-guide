# One-Page Revision Sheet

## 8 rules that fix most vulnerabilities

1. **Never trust input.** Validate, parameterize queries, encode output, avoid shells (SQLi, command, XML, header, XSS, prompt injection).
2. **Check permission on the server, every time.** Role AND ownership (IDOR/BOLA, BFLA, privilege escalation, forced browsing).
3. **Least privilege everywhere.** IAM, RBAC, containers, Lambda roles, AI agents, database accounts.
4. **No secrets in code, images, logs or URLs.** Use a secrets manager or Keystore/Keychain; rotate if leaked.
5. **Encrypt in transit and at rest.** TLS plus certificate checks, AES-GCM, bcrypt/Argon2, keys in the OS store.
6. **Update and verify what you use.** Libraries, images, models, Helm charts: scan, pin versions, sign.
7. **Safe defaults.** Private by default, debug off, default passwords changed, limits and rate limits on.
8. **Log, alert, review.** Log logins and errors (not secrets), centralize, alert.

## Part by part

| Topic | Names to remember | Remember this |
|---|---|---|
| **1 Web (25)** | Injection: SQL, command, XML, header. XSS: reflected, stored, DOM, TikTok. Access: horizontal/vertical escalation, forced browsing, insecure redirect. Session: CSRF, session fixation, token or PII in URL, weak randomness. Other: clickjacking, directory traversal, SSRF, user enumeration, leftover debug code, vulnerable components, Log4j (CVE-2021-44228), rest-client 1.6.13 backdoor. | Never trust input. Check on the server. New session ID after login. Same error message for every login failure. |
| **2 API (13)** | BOLA (change an ID), BFLA (call an admin function), broken user authentication, mass assignment, excessive data exposure, no rate limiting, improper assets management, misconfiguration 1 and 2, SQL and command injection, XXE, weak logging. | **Is it you? Are you allowed? Is it yours?** Allow-list fields, return only needed data, rate limit. |
| **3 LLM (10)** | Prompt injection (direct and indirect), sensitive information disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, denial of service. | AI = smart but easily fooled intern. Least privilege, human approval, treat output as untrusted, no secrets in prompts. |
| **4 Android + iOS (10+10)** | Android: credentials in code, supply chain, auth/authz, input validation, insecure communication, privacy, binary protection, misconfiguration, data storage, weak crypto. iOS: ATS/communication, storage, SQLite, URL cache, URL scheme, Keychain persistence, local authentication, logs, SSL pinning, app lock. | Phone = attacker's hands. Secrets in Keystore/Keychain, HTTPS plus pinning, server makes decisions, biometrics tied to the Keychain. |
| **5 Docker + Compose (10)** | Resource limits, exposed `docker.sock`, host update, volumes/host filesystem, insecure registries, minimal base image, privileged containers, secrets in images, unsegregated network, unverified images. | **Small image, small power, small door.** Non-root, drop capabilities, separate networks, signed images. |
| **6 AWS (13)** | Dangerous dependencies, excessive logging, Lambda command injection and XXE, Cognito attributes and self-registration, reverse proxy, S3 Authenticated Users WRITE, S3 public READ, S3 traversal, SSRF (IMDSv2), subdomain takeover, weak POST policy. | Private by default, least privilege, Block Public Access, IMDSv2, delete DNS records when deleting resources. |
| **7 Desktop C/C++ (10)** | Injections, broken authentication/session, sensitive data exposure, improper cryptography, improper authorization, misconfiguration (DLL hijacking), insecure communication, poor code quality (buffer overflow), vulnerable components (Heartbleed), weak logging. | Attacker owns the computer. Server-side checks, OS key store, safe functions, compiler protections, fuzzing. |
| **8 Front-end (6 x 5)** | CSRF, direct DOM XSS (`innerHTML`), template concatenation, sanitization misuse (Angular `bypassSecurityTrust`), untrusted HTML (`dangerouslySetInnerHTML`, `v-html`), vulnerable components. Angular, React, Vue, JS, TS. | Text is safe, HTML is dangerous, templates are code. TS types vanish at runtime. DOMPurify, CSP, CSRF token. |
| **9 Kubernetes (10)** | Broken authentication, weak logging, insecure workload config, no policy enforcement, misconfigured components (API/etcd/kubelet/dashboard), no network segmentation, overly permissive RBAC, secrets (base64 is not encryption), supply chain, vulnerable components. | Lock doors, limit keys, build walls, hide secrets, check ingredients, watch cameras. Default-deny NetworkPolicy. |

## Pairs interviewers love

| Pair | Difference |
|---|---|
| **Reflected vs Stored XSS** | Reflected: a bad script in a link bounces back once. Stored: saved on the site, hits every visitor. |
| **CSRF vs XSS vs SSRF** | CSRF tricks the *victim's browser* into sending a request. XSS runs a script *in the victim's browser*. SSRF tricks the *server* into fetching URLs. |
| **BOLA vs BFLA** | BOLA: access someone else's *object* (record). BFLA: call a *function* you should not (admin). |
| **Horizontal vs Vertical escalation** | Horizontal: another user at the same level. Vertical: become admin (go up). |
| **Authentication vs Authorization** | Authentication: who are you. Authorization: what are you allowed to do. |
| **Hash vs Encrypt vs Encode** | Hash: one-way (passwords). Encrypt: two-way with a key. Encode (base64): just formatting, not security. |

## Top fixes to say out loud

| Problem | Fix |
|---|---|
| SQL injection | Parameterized queries |
| XSS | Encode output / `textContent` plus CSP |
| CSRF | Token plus SameSite cookie |
| IDOR / BOLA | Ownership check on the server |
| SSRF | Allow-list URLs plus IMDSv2 |
| Brute force | Rate limit plus MFA plus lockout |
| Containers | Non-root, drop capabilities, limits |
| Kubernetes network | Default-deny NetworkPolicy |
| Secrets | Vault / secrets manager |
| Supply chain | Scan, pin, sign |
| Buffer overflow | Bounds checks plus ASLR/DEP/canaries |
| Detection | Central logs plus alerts |
