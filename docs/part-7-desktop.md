# Desktop (C/C++) Vulnerabilities: Explained Simply (Part 7)

Every item has: **Think of it like** → **Scenario** (step by step) → **Why it works** → **Fix** (and why it works).

## Words you will see a lot

- **Desktop app (thick client)**: a program installed on your computer (billing software, a chat app, a PDF viewer). Unlike a website, **the code runs on the user's own PC**.
- **.exe / binary**: the finished program file. It can be opened with tools that show its text, settings and even rebuild the logic (**reverse engineering**).
- **Memory**: the computer's short-term workspace where a running program keeps its data.
- **Buffer**: a **fixed-size box in memory** that holds data, such as 10 characters for a name.
- **Buffer overflow**: putting 1,000 characters into a 10-character box so the extra spills into the next boxes.
- **DLL**: a helper file that a Windows program loads when it runs (a **library of ready-made functions**).
- **Registry / config file**: where the program keeps its settings.
- **Privilege**: how much power an account or program has. **SYSTEM/admin = highest.**
- **Hash**: a one-way scramble of a password (you can't turn it back).
- **TLS**: the lock that protects data in transit on the network (the "S" in HTTPS).
- **Logs**: the app's diary of what happened.

!!! info "Golden rule for desktop apps"

    *the attacker owns the computer the app runs on. Don't hide secrets or "security checks" inside the program; they can be found, copied and changed. The real checks must be on a server, and the code must be written safely.*


**Tools testers use (so you know the names):** `strings`, Ghidra / IDA (read the code), x64dbg (watch it run), Process Monitor (see which files/registry it touches), Wireshark (see network traffic).

---

## 1. Injections

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/78.html" target="_blank" rel="noopener noreferrer">CWE-78</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" rel="noopener noreferrer">CWE-89</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1059/" target="_blank" rel="noopener noreferrer" title="Command and Scripting Interpreter">ATT&amp;CK T1059</a></p>

!!! tip "Think of it like"

    A waiter passes your written order to the kitchen. You write "Tea" and then, on the same slip, "**and open the cash drawer**." He can't tell which part is food and which part is an instruction, so he does both.

!!! example "Scenario (command injection)"


    1. A backup tool asks for a file name and runs: `sprintf(cmd, "zip backup.zip %s", filename); system(cmd);`
    2. A normal user types `report.txt`. It works.
    3. An attacker types `report.txt & del C:\Data\*.*` (or `; rm -rf ~` on Linux). The `&`/`;` means "run another command."
    4. The computer runs the zip command **and** the delete command.

!!! example "Scenario (SQL injection)"


    1. A desktop inventory app builds a database query by joining the text typed in a search box.
    2. Typing `' OR 1=1 --` returns **every record** in the database, or lets the attacker change/delete data.

!!! warning "Why it works"

    Input is mixed straight into a command or query, so the system can't tell data from instructions.

!!! success "Fix"


    - **Avoid `system()` and shell commands.** Use library functions or APIs that take arguments separately (e.g., `CreateProcess` with separate arguments, `execve`), not one joined string.
    - **Validate input** with an allow-list (e.g., only letters, numbers, `.`).
    - For databases, use **parameterized queries / prepared statements** so input is always treated as plain data.
    - Run the app with **low privileges**, so even a successful injection can do little.

---

## 2. Broken Authentication and Session Management

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/287.html" target="_blank" rel="noopener noreferrer">CWE-287</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/613.html" target="_blank" rel="noopener noreferrer">CWE-613</a></p>

!!! tip "Think of it like"

    A shop with a **"Staff Only" door whose lock is just a sticker**. A thief peels off the sticker. Or a staff member leaves the shop with the cash register still unlocked, and the next customer uses it.

!!! example "Scenario (login check inside the app)"


    1. A billing app checks the password inside the program: `if (strcmp(password, "Admin@123") == 0) { login(); }`
    2. Arjun opens the `.exe` with `strings` and finds `Admin@123`. Or he opens it in a debugger and changes the "if password correct" check so it **always says yes** (patching the program).
    3. He's in, with no real password needed.

!!! example "Scenario (session)"


    1. A user logs in on a shared office PC and walks away. The app **never logs out** and keeps the user's token in a plain file.
    2. Anyone who sits down, or copies the file, is that user.

!!! warning "Why it works"

    Login logic that runs on the user's computer can be **read and edited by the user**. Sessions that never end are open invitations.

!!! success "Fix"


    - Do the login check **on a server**. The app sends credentials and the server decides; the app is only the messenger.
    - **Never hardcode** passwords or keys. Store user passwords **hashed** (bcrypt/Argon2) on the server.
    - Add **MFA**, account lockout after failed tries, **auto-logout on inactivity**, and a proper "log out" that destroys the session.
    - Store tokens in the OS secure store (Windows Credential Manager / DPAPI, macOS Keychain), not in plain files.

---

## 3. Sensitive Data Exposure

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/311.html" target="_blank" rel="noopener noreferrer">CWE-311</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/312.html" target="_blank" rel="noopener noreferrer">CWE-312</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1552/001/" target="_blank" rel="noopener noreferrer" title="Credentials In Files">ATT&amp;CK T1552.001</a></p>

!!! tip "Think of it like"

    Keeping customer files in an **unlocked cupboard**. If someone steals the cupboard (or just walks in), everything is readable.

!!! example "Scenario"


    1. A clinic app saves patient records in `C:\ProgramData\Clinic\patients.db`, a normal, unencrypted file.
    2. A receptionist's laptop is stolen from a car.
    3. The thief takes out the disk, plugs it into another computer and opens the file. Every patient's name, phone and medical notes are readable.
    4. Other leaks from the same app: **temporary files** left behind, data left in **memory**, secrets in the **registry**, and details in **crash dumps**.

!!! warning "Why it works"

    Data is stored in plain form, and the app doesn't clean up after itself.

!!! success "Fix"


    - **Encrypt data at rest**: encrypted database (SQLCipher), Windows DPAPI, and full-disk encryption (BitLocker/FileVault).
    - **Store less.** Don't keep what you don't need.
    - Delete temporary files, and **wipe secrets from memory** after use (`SecureZeroMemory`, `explicit_bzero`).
    - Protect data **in transit** with TLS (see Item 7).

---

## 4. Improper Cryptography Usage

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/327.html" target="_blank" rel="noopener noreferrer">CWE-327</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/321.html" target="_blank" rel="noopener noreferrer">CWE-321</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/330.html" target="_blank" rel="noopener noreferrer">CWE-330</a></p>

!!! tip "Think of it like"

    Locking a safe with a **home-made lock** and **taping the key to the safe**. It looks secured but isn't.

!!! example "Scenario"


    1. A developer "encrypts" saved passwords with a simple XOR using the key `"secret123"`, which is written in the code.
    2. An attacker runs `strings app.exe`, sees `secret123`, finds the saved-password file and **decrypts everything in minutes**.
    3. Another app uses MD5 to hash passwords: attackers use lookup tables and crack most of them instantly.
    4. Another app generates "random" session tokens with `rand()`, so attackers can **predict** the next token.

!!! warning "Why it works"

    Weak or home-made crypto, bad modes (like ECB), old algorithms (MD5, SHA-1, DES) and keys stored with the data give a **false sense of safety**.

!!! success "Fix"


    - **Never invent your own** crypto. Use trusted libraries (libsodium, OpenSSL, Windows CNG).
    - Use modern choices: **AES-256-GCM** for encryption, **bcrypt/Argon2/scrypt** for passwords, **SHA-256+** for integrity.
    - Use a **cryptographically secure random generator** (`BCryptGenRandom`, `/dev/urandom`, `RAND_bytes`), not `rand()`.
    - Keep keys in the **OS key store** (DPAPI, Keychain, TPM), not in the program or next to the data.

---

## 5. Improper Authorization

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/285.html" target="_blank" rel="noopener noreferrer">CWE-285</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/732.html" target="_blank" rel="noopener noreferrer">CWE-732</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1068/" target="_blank" rel="noopener noreferrer" title="Exploitation for Privilege Escalation">ATT&amp;CK T1068</a></p>

!!! tip "Think of it like"

    A building where **every employee's card opens every door**, including the manager's cabin and the accounts room. The card proves you work here, but nothing checks **what you're allowed to do**.

!!! example "Scenario"


    1. In an HR desktop app, normal employees don't see the "Salary Edit" menu (it's hidden in the UI).
    2. Sneha finds that the app saves her role in a local file: `role=employee`. She edits it to `role=admin`.
    3. Or she just calls the server's "edit salary" function directly. The server only checks "is this a valid user?" and not "is this user an admin?"
    4. She changes salaries.

!!! example "Scenario (local)"


    1. The app is installed in `C:\Program Files\Tool\` but the installer made the folder **writable for all users**.
    2. A normal user replaces `service.exe` with a malicious copy. The next time the app's service starts (as SYSTEM), the attacker's code runs with **full power** (privilege escalation).

!!! warning "Why it works"

    The app trusts what runs on the user's machine (hidden buttons, local files, folder permissions) instead of **checking permission on every action on the server**.

!!! success "Fix"


    - Check **who is allowed** for every action **on the server** (role and ownership), not in the UI.
    - Never store roles/permissions in files the user can edit.
    - **Least privilege**: run the app and its services with the lowest rights needed (not SYSTEM/root).
    - Set correct **file and folder permissions** at install time (only admins can write to the program folder).

---

## 6. Security Misconfiguration

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/16.html" target="_blank" rel="noopener noreferrer">CWE-16</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/427.html" target="_blank" rel="noopener noreferrer">CWE-427</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1188.html" target="_blank" rel="noopener noreferrer">CWE-1188</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1574/001/" target="_blank" rel="noopener noreferrer" title="DLL Search Order Hijacking">ATT&amp;CK T1574.001</a></p>

!!! tip "Think of it like"

    Moving into a new house and **leaving the builder's spare key under the doormat**, the default gate password unchanged, and the garden door unlocked "for now."

!!! example "Scenario"


    1. The software installs with a built-in account `admin / admin`, and nobody is forced to change it.
    2. The installer also gives **"Everyone" write permission** on the install folder.
    3. A `helper.dll` is loaded by the program without a full path, so Windows searches several folders in order. The attacker drops a fake `helper.dll` in a folder searched first (**DLL hijacking**). When the app starts, the **attacker's DLL runs** with the app's rights.
    4. The program was also built **without protections** (no ASLR/DEP/stack canaries) and with debug symbols, which makes exploiting bugs and reading the code much easier.

!!! warning "Why it works"

    Defaults are built for convenience, not safety, and nobody reviews them before release.

!!! success "Fix"


    - **Force a password change** at first use; no default or shared accounts.
    - Set proper **ACLs** (permissions) on the install folder, services and registry keys.
    - Load DLLs with **full paths** and use safe-loading settings (`SetDefaultDllDirectories`, `LoadLibraryEx` with safe flags), and put quotes around service paths.
    - Build with **security flags**: `/GS`, `/DYNAMICBASE`, `/NXCOMPAT`, `/guard:cf` (MSVC) or `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE -pie`, `-Wl,-z,relro,-z,now` (GCC/Clang). Strip debug info from release builds.
    - Turn off debug features and remove unused components.

---

## 7. Insecure Communication

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/319.html" target="_blank" rel="noopener noreferrer">CWE-319</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/295.html" target="_blank" rel="noopener noreferrer">CWE-295</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1040/" target="_blank" rel="noopener noreferrer" title="Network Sniffing">ATT&amp;CK T1040</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1557/" target="_blank" rel="noopener noreferrer" title="Adversary-in-the-Middle">ATT&amp;CK T1557</a></p>

!!! tip "Think of it like"

    Shouting your private messages across a **crowded hall** instead of whispering in a **closed room**.

!!! example "Scenario"


    1. A desktop chat app sends messages over a plain TCP connection, with no encryption.
    2. Kiran works from an office or café network. An attacker on the same network runs **Wireshark** and reads every message, plus the login details.
    3. Or the attacker sits between the app and server (**Man-in-the-Middle**) and **changes** the messages or the update file.
    4. Another app uses HTTPS but has the setting `CURLOPT_SSL_VERIFYPEER = 0` ("don't check the certificate"), so a fake server is accepted.

!!! warning "Why it works"

    Unencrypted traffic can be read and altered by anyone on the path. Turning off certificate checks removes the lock's purpose.

!!! success "Fix"


    - Use **TLS 1.2 or 1.3** for all network traffic (including updates and internal services).
    - **Verify certificates and host names**. Never disable verification "to make it work."
    - Consider **certificate pinning** for sensitive apps.
    - **Sign** update files and verify the signature before installing.

---

## 8. Poor Code Quality

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/120.html" target="_blank" rel="noopener noreferrer">CWE-120</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/787.html" target="_blank" rel="noopener noreferrer">CWE-787</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/416.html" target="_blank" rel="noopener noreferrer">CWE-416</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/134.html" target="_blank" rel="noopener noreferrer">CWE-134</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/190.html" target="_blank" rel="noopener noreferrer">CWE-190</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1203/" target="_blank" rel="noopener noreferrer" title="Exploitation for Client Execution">ATT&amp;CK T1203</a></p>

!!! tip "Think of it like"

    A **10-seat bus** where the driver lets **1,000 people** board. The extra people spill into the driver's cabin and take control of the steering wheel.

!!! example "Scenario (buffer overflow)"


    1. A C program stores a name in a 10-character box: `char name[10]; strcpy(name, input);`
    2. A user enters 200 characters. `strcpy` doesn't check size, so the extra data **overwrites nearby memory**, including the **return address** (the note that tells the program where to go next).
    3. A skilled attacker chooses those extra bytes carefully so the program jumps to **his code**.
    4. He now runs commands on the victim's computer, as the user running the app.

    **Other common bugs in C/C++:**

    - **Use-after-free**: using memory after giving it back, and the attacker places his data there.
    - **Format string bug**: `printf(userInput)` lets the attacker read or write memory using `%x`/`%n`.
    - **Integer overflow**: a size calculation wraps around, so a small buffer is allocated for a big copy.

!!! warning "Why it works"

    C and C++ **don't automatically check memory limits**; the programmer must.

!!! success "Fix"


    - Don't use unsafe functions (`strcpy`, `gets`, `sprintf`). Use `snprintf`, `std::string`, `std::vector`, `std::span`, or checked functions, and **always check sizes**.
    - Use `printf("%s", userInput)`, never `printf(userInput)`.
    - Turn on **compiler protections** (stack canaries, ASLR, DEP/NX, CFG).
    - **Test**: static analysis (Cppcheck, clang-tidy, Coverity), **sanitizers** (AddressSanitizer), **fuzzing** (AFL++, libFuzzer) and code review.
    - For new code, prefer **memory-safe languages** (Rust, C#, Go) where possible.

---

## 9. Using Components with Known Vulnerabilities

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1203/" target="_blank" rel="noopener noreferrer" title="Exploitation for Client Execution">ATT&amp;CK T1203</a></p>

!!! tip "Think of it like"

    Building a house with a **door lock whose design flaw was announced in the newspaper**, and never replacing it.

!!! example "Scenario"


    1. A PDF viewer uses an old copy of an open-source library (e.g., an old image or compression library).
    2. That version has a **published bug** that lets a crafted file run code.
    3. An attacker emails a specially made PDF. When the user opens it, the old library **runs the attacker's code**.
    4. A famous real example: **Heartbleed** (2014), a bug in OpenSSL that let attackers read secret data from memory of any program using the vulnerable version.

!!! warning "Why it works"

    Attackers don't need new tricks; they use **public lists of known bugs (CVEs)** against software that hasn't updated. In C/C++ the library is often **built into** the program, so users can't update it themselves.

!!! success "Fix"


    - Keep an **inventory of every library and version** (an SBOM).
    - **Scan** regularly (OWASP Dependency-Check, Trivy, Dependabot) and watch security advisories.
    - **Update quickly** and release patched versions of your app, with a safe **auto-update** (signed updates over TLS).
    - Remove libraries you don't use.

---

## 10. Insufficient Logging and Monitoring

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/778.html" target="_blank" rel="noopener noreferrer">CWE-778</a></p>

!!! tip "Think of it like"

    A shop with **no CCTV, no alarm, and no cash register record**. Thieves come every night for a month, and nobody knows until the shelves are empty.

!!! example "Scenario"


    1. An attacker tries 50,000 passwords against the app's login.
    2. The app **doesn't record failed logins**, and nobody watches anyway.
    3. He gets in, copies customer data over three weeks, and leaves.
    4. After the breach, the company has **no logs** to know what was stolen or who did it.

!!! warning "Why it works"

    Attacks are only caught if something is **recorded** and someone or something is **watching**.

!!! success "Fix"


    - **Log important events**: logins (success and failure), permission denied, admin actions, data export, crashes and errors, with time, user and source.
    - Send logs to a **central place** (Windows Event Log, syslog, a SIEM) so an attacker on one PC can't erase them.
    - Set **alerts** (e.g., 10 failed logins in a minute, a login at 3 a.m.).
    - **Don't log secrets** (passwords, tokens, card numbers), and protect logs from tampering.

    *(Logging and monitoring is the daily job of a SOC analyst.)*

---

## Quick summary

| Family | Items | One-line defence |
|---|---|---|
| Input becomes a command | 1 Injections | Never mix user input into commands or queries; use safe APIs |
| Who are you / what can you do | 2 Broken authentication, 5 Improper authorization | Server-side checks; least privilege; correct file permissions |
| Data protection | 3 Sensitive data exposure, 4 Improper cryptography, 7 Insecure communication | Encrypt at rest and in transit with proven libraries; keys in the OS store |
| Bugs in the code | 8 Poor code quality, 9 Components with known vulnerabilities | Safe functions, compiler protections, testing, fuzzing, fast updates |
| Setup mistakes | 6 Security misconfiguration | Safe defaults, correct permissions, secure build flags |
| Detection | 10 Insufficient logging and monitoring | Log, centralize, alert |

!!! success "Memory trick"

    *"The attacker owns the computer."* So: put the real checks on the server, keep secrets in the OS key store, write memory-safe code, keep libraries updated, and log what happens.
