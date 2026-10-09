# API Vulnerabilities: Explained Simply (Part 2)

Every item has: **Think of it like** → **Scenario** (step by step) → **Why it works** → **Fix** (and why it works).

## Words you will see a lot

- **API**: a **waiter** between an app and the server's kitchen. The app (customer) gives an order, the API carries it to the kitchen (server/database) and brings back the food (data).
- **Endpoint**: one specific "menu item" address, like `/api/orders` or `/api/users/5`.
- **Request / Response**: the order you send / the answer you get back.
- **JSON**: the simple text format APIs use to send data, like `{"name":"Ravi","age":22}`.
- **Token**: a secret code (like a key card) the app shows in each request to prove who you are.
- **Role**: your permission level (user, manager, admin).
- **Proxy tool (Burp Suite, Postman)**: tools that let you see and edit requests. Attackers use them, and so do testers. Remember: **the app's screen can hide things, but the API request can't be hidden.**

!!! info "Golden rule for APIs"

    *the app is only a remote control. The server must check everything again, because the attacker can skip the remote and talk directly to the server.*


---

## 1. Broken Function Level Authorization (BFLA)

!!! tip "Think of it like"

    In an office, the **"Manager Only" door has no lock**. The staff just don't know it exists because there's no sign. Any employee who tries the handle can walk in.

!!! example "Scenario"


    1. Ravi is a normal user. His app only shows `GET /api/profile`.
    2. He opens a proxy tool and notices the app also has admin URLs in its code: `DELETE /api/admin/users/7`.
    3. He sends that request with his own normal token.
    4. The server only checks "is the token valid?", not "is this person an admin?", so user #7 is deleted.

!!! warning "Why it works"

    The *button* was hidden, but the *function* was not protected. Function level means "what action can you do?" (read, delete, approve).

!!! success "Fix"

    On the server, check the **role for every endpoint** (a rule like "only admin can call `/admin/*`"). Deny by default; allow only what's listed. Hiding buttons in the app is a convenience, not security.

---

## 2. Broken Object Level Authorization (BOLA, also called IDOR)

!!! tip "Think of it like"

    A hotel gives you key card #101. At the lift, you press floor 2 and enter room **102** with your key, because the doors only check "is this a valid hotel card?" and not "is this *your* room?"

!!! example "Scenario"


    1. Priya's app shows her order using `GET /api/orders/1001`.
    2. She changes `1001` to `1002` in a proxy tool.
    3. The API returns another customer's name, address and phone number. She loops through 1003, 1004... and downloads thousands of orders.

!!! warning "Why it works"

    The API checks **who you are** (logged in), but not whether **this object (order) belongs to you**. "Object level" means each individual record. This is the **#1 API risk** and extremely common.

!!! success "Fix"

    On every request, check that the object's owner equals the logged-in user (e.g., `WHERE id=1002 AND user_id=<my id from token>`). Also use long random IDs (UUIDs) instead of 1, 2, 3, as an extra layer (it only makes guessing harder; the ownership check is the real fix).

---

## 3. Broken User Authentication

!!! tip "Think of it like"

    A building guard who accepts **any ID card, even expired, photocopied or easily guessed**, and lets a stranger try 1000 times to guess the door code.

!!! example "Scenario"


    1. The login API has no limit on attempts, and many users use weak passwords like `Welcome@123`.
    2. A hacker runs a tool that tries 10,000 common passwords on Sneha's account.
    3. It works on attempt 4,200.
    4. Also, tokens issued never expire, so even a token stolen last year still works.

!!! warning "Why it works"

    Weak passwords + unlimited tries + long-lived tokens = easy account takeover. "Authentication" simply means proving *who you are*.

!!! success "Fix"


    - Lock or slow down after several failed attempts (so brute force stops being practical).
    - Enforce strong passwords and offer MFA (a second proof, like an OTP).
    - Make tokens expire quickly (e.g., 15 minutes) and allow logout to cancel them.
    - Never put tokens or passwords in URLs.

---

## 4. Command Injection

!!! tip "Think of it like"

    You give a waiter a note: "Bring me tea." A prankster edits it to "Bring me tea **and unlock the cash drawer**." The waiter follows the entire note.

!!! example "Scenario"


    1. An API `/api/check-site?url=google.com` makes the server run `ping google.com`.
    2. The hacker sends `url=google.com; cat /etc/passwd` (`;` means "run the next command too").
    3. The server runs both commands and returns a list of its users in the response.
    4. With a bigger payload, he can download malware or open a remote shell.

!!! warning "Why it works"

    The server joined user text straight into an operating-system command and can't tell data from commands.

!!! success "Fix"

    Avoid running OS commands with user input. If you must, use safe library functions (not a shell), allow only expected formats (e.g., a valid domain pattern) and run the app with minimal permissions so damage is limited.

---

## 5. Excessive Data Exposure

!!! tip "Think of it like"

    You ask a shopkeeper, "What's the price of this phone?" and he hands you the **entire accounts book**, trusting that you'll only read the price page.

!!! example "Scenario"


    1. A mobile app's profile screen shows only name and photo.
    2. But the API returns the **whole user record**: `{"name":"Ravi","photo":"..","email":"..","phone":"..","password_hash":"..","is_admin":false}`.
    3. The developer assumed, "The app only shows what it needs." An attacker opens the request in a proxy tool and sees everything.

!!! warning "Why it works"

    The developer filtered data in the **app** instead of the **server**. Anything the API sends can be read by anyone who gets the response.

!!! success "Fix"

    Return **only the fields the screen needs** (use response models/DTOs), never the raw database row. Review responses for hidden sensitive fields like password hashes, internal IDs and tokens.

---

## 6. Improper Assets Management

!!! tip "Think of it like"

    A company renovated its building and installed a new front door with a strong lock, but the **old back door is still there, unlocked**, because everyone forgot about it.

!!! example "Scenario"


    1. The company launched `/api/v2/login` with rate limiting and MFA.
    2. The old `/api/v1/login`, with no protection, was never turned off.
    3. A hacker finds `/v1/` by simply replacing `v2` with `v1` and brute-forces passwords there.
    4. Also common: forgotten test servers like `test.company.com/api` that hold real data.

!!! warning "Why it works"

    You can't protect what you don't know exists. "Assets" means every API, version, server and environment you run.

!!! success "Fix"

    Keep an **inventory** of all APIs, versions, hosts and who owns each one. Shut down old versions, don't use production data in test systems and use API gateways so everything goes through one controlled door.

---

## 7. Insufficient Logging and Monitoring

!!! tip "Think of it like"

    A shop with **no CCTV and no alarm**. Thieves visit every night for a month and nobody realizes until the shelves are empty.

!!! example "Scenario"


    1. A hacker slowly downloads customer records using BOLA (Item 2), 50 per hour, for 3 weeks.
    2. No logs record who accessed what, and no alert fires for the unusual pattern.
    3. The company finds out only when customers see their data on the dark web.

!!! warning "Why it works"

    Attackers love being unnoticed. Without logs you can't detect, investigate or prove what happened.

!!! success "Fix"


    - Log important events: logins (success and failure), access denied, admin actions, large data downloads.
    - Send logs to a central place (SIEM) and set **alerts** (e.g., 100 failed logins in 1 minute).
    - Don't log secrets like passwords or full tokens, and protect the logs from editing.

    *(This is exactly where SOC analysts work.)*

---

## 8. Lack of Resources and Rate Limiting

!!! tip "Think of it like"

    A restaurant lets **one customer order 10,000 plates at once**. The kitchen is jammed and real customers wait forever. Or someone tries all the combinations on a lock because nobody stops him.

!!! example "Scenario"


    1. The OTP login API accepts a 4-digit OTP (only 10,000 possibilities) with no limit.
    2. A bot tries 0000 to 9999 in a minute and gets in.
    3. Another attacker sends 1 million requests, or asks for `?limit=1000000` records, and the server runs out of memory and crashes (a DoS: denial of service).

!!! warning "Why it works"

    Servers have limited CPU, memory and money. Without limits, one client can use all of it, or guess secrets by trying everything.

!!! success "Fix"


    - **Rate limit**: e.g., 5 login attempts per minute per user/IP.
    - Cap the page size (`limit` max 100), request size, upload size and timeouts.
    - Lock OTPs after a few wrong tries and make them longer (6+ digits) and short-lived.

---

## 9. Mass Assignment

!!! tip "Think of it like"

    A form has the fields Name and Email. You write extra lines by hand: "Role: Admin." The clerk copies **everything you wrote** into your record without checking which fields were allowed.

!!! example "Scenario"


    1. The signup API expects `{"name":"Kiran","email":"k@x.com"}`.
    2. The backend code copies every field it receives into the new user record (this is "mass assignment": assigning many fields at once).
    3. Kiran sends `{"name":"Kiran","email":"k@x.com","role":"admin","balance":100000}`.
    4. The server saves all of it, and Kiran is now an admin with a large balance.

!!! warning "Why it works"

    Convenient frameworks auto-bind JSON to objects, and the developer forgot that **users can add fields**.

!!! success "Fix"

    Use an **allow-list**: accept only the fields you expect (`name`, `email`) and ignore everything else. Never let clients set sensitive fields like `role`, `isAdmin`, `balance` or `id`. Use separate input models for requests.

---

## 10. Security Misconfiguration 1: Unsafe Defaults and Detailed Errors

!!! tip "Think of it like"

    A new house where the builder left the **front door on its factory default key** (everyone owns the same key) and a signboard saying what's inside.

!!! example "Scenario"


    1. A server was deployed with debug mode ON and default admin credentials (`admin/admin`).
    2. A hacker sends a broken request and gets a detailed error: the full code path, database name, library versions and part of the SQL query.
    3. Using that info, he picks the exact exploit for the old library version and logs in using `admin/admin` on a forgotten admin page.

!!! warning "Why it works"

    Defaults are made for easy setup, not safety. Errors written for developers help attackers.

!!! success "Fix"

    Change all default passwords, turn off debug mode in production, show users a generic error ("Something went wrong") and keep details only in private logs. Remove unused features, sample apps and open ports.

---

## 11. Security Misconfiguration 2: Open CORS, Missing Headers and Extra Methods

!!! tip "Think of it like"

    A club's rule says "Anyone with *any* membership card from *any* club can enter our VIP room," and the security guard doesn't mind people **who aren't on the list**.

!!! example "Scenario"


    1. The API has CORS set to `*` (allow every website). CORS is the browser rule that decides which other websites may read this API's responses.
    2. Ravi is logged in to the API's website. He visits the attacker's page.
    3. The attacker's page quietly calls the API and reads Ravi's private data, since CORS allows any website.
    4. The API also allows unnecessary methods like `PUT` or `TRACE` on public endpoints, and lacks headers such as `Strict-Transport-Security` and `X-Content-Type-Options`.

!!! warning "Why it works"

    The safety rules the browser provides were switched off by loose settings.

!!! success "Fix"

    Allow only your own trusted origins in CORS (never `*` together with login cookies), disable HTTP methods you don't use, add security headers, enforce HTTPS and review configuration automatically (config scans) every release.

---

## 12. SQL Injection

!!! tip "Think of it like"

    A clerk follows a note you hand over: "Find the file for **Ravi**." You change it to "Find the file for Ravi **and show all files**." The clerk can't tell which part is the name and which part is an instruction.

!!! example "Scenario"


    1. The API runs: `SELECT * FROM users WHERE id = [what you send]`.
    2. A normal request sends `id=5` and gets user 5.
    3. The hacker sends `id=5 OR 1=1`. Now the query is `...WHERE id = 5 OR 1=1`, and since 1=1 is always true, the database returns **all users**.
    4. With more advanced tricks (`UNION SELECT`), he can read other tables like passwords.

!!! warning "Why it works"

    The user's input was glued into the database command and became part of it.

!!! success "Fix"

    Use **parameterized queries / prepared statements**. The query shape is fixed first (`WHERE id = ?`) and your input is passed separately, so `5 OR 1=1` is treated as just a weird text value for an ID, not a command. Also give the database account minimum rights, and validate that `id` is a number.

---

## 13. XXE Injection (XML External Entity)

!!! tip "Think of it like"

    You send a letter that says: "Please **attach the contents of file X from your office cabinet** here." The office worker, being helpful, does it and sends back your letter with their private file inside.

!!! example "Scenario"


    1. An API accepts XML (a tag-based format) to upload an order.
    2. XML has a feature called an "external entity" that says "load content from this location." The hacker sends:
       `<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><order><name>&secret;</name></order>`
    3. The XML parser reads the server's `/etc/passwd` file, puts it in `<name>`, and the API's response (or error) shows it to the attacker.
    4. The same trick can also make the server call internal URLs (like SSRF).

!!! warning "Why it works"

    The XML parser's default settings allow external entities, a feature almost nobody needs.

!!! success "Fix"

    **Turn off external entities and DTDs** in the XML parser (a setting, depending on language/library). Prefer JSON when possible, keep parsers updated and validate input.

---

## Quick summary

| Family | Items | One-line defence |
|---|---|---|
| Who can do/see what (access control) | BFLA, BOLA, Mass assignment | Check role AND ownership on the server for every request |
| Login and identity | Broken user authentication | Strong passwords, MFA, expiring tokens, lockouts |
| Injection | SQL, Command, XXE | Never mix input with commands; use safe APIs/settings |
| Too much information | Excessive data exposure, Detailed errors | Send only what's needed |
| Overload and abuse | Lack of rate limiting | Limits on speed, size and attempts |
| Forgotten or loose setup | Improper assets management, Misconfiguration 1 and 2 | Inventory, safe defaults, review settings |
| Detection | Insufficient logging and monitoring | Log, centralize, alert |

!!! success "Memory trick for the top 3 mistakes"

    *"Is it **you**? (authentication) → Are you **allowed**? (function level) → Is it **yours**? (object level)"*
