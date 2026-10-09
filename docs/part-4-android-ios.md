# Android and iOS Vulnerabilities: Explained Simply (Part 4)

Every item has: **Think of it like** → **Scenario** (step by step) → **Why it works** → **Fix** (and why it works).

## Words you will see a lot

- **APK / IPA**: the installable file of an Android app / iPhone app. An APK is basically a **zip file** anyone can download and open.
- **Decompile / reverse engineer**: turning the app file back into readable code (like **un-baking a cake to find the recipe**).
- **Root / Jailbreak**: removing the phone's safety limits so the user (or malware) can see everything inside the phone.
- **Local storage**: files, settings and databases the app saves **on the phone**.
- **SharedPreferences (Android) / UserDefaults (iOS)**: simple settings files. **Plain text, not a safe place for secrets.**
- **SQLite**: a small database file inside the app.
- **Keystore (Android) / Keychain (iOS)**: the phone's **locked safe** for passwords, keys and tokens.
- **HTTP vs HTTPS (TLS)**: HTTP is a **postcard** (anyone can read it). HTTPS is a **sealed, locked envelope**.
- **MITM (Man-in-the-Middle)**: someone sitting between your phone and the server (e.g., on public Wi-Fi) reading or changing traffic.
- **Certificate**: the server's ID card that proves "I am really bank.com."
- **Hash / Encryption**: hashing scrambles data **one way** (used for passwords). Encryption scrambles it **two ways** (you can unlock it with a key).
- **Deep link / URL scheme**: a link like `myapp://pay?amount=5` that opens a specific screen in an app.
- **Manifest**: the app's **settings sheet** (Android: `AndroidManifest.xml`, iOS: `Info.plist`).
- **Logs**: notes the app writes while running, mainly for developers.

!!! info "Golden rules for mobile apps"


    1. *The phone belongs to the user, and the attacker can be the user.* Anything inside the app can be read.
    2. *Secrets belong on the server or in the Keystore/Keychain, never in the app's code or plain files.*


---

## PART A: ANDROID (Java/Kotlin)

## 1. Improper Credential Usage

!!! tip "Think of it like"

    A shopkeeper writes the **cash-box password on a sticker stuck on the box itself**. Anyone who picks the box up reads it.

!!! example "Scenario"


    1. The developer writes the payment service's API key directly in the code: `String KEY = "sk_live_1234"`.
    2. Arjun downloads the APK from the Play Store (or a mirror site), opens it with a free tool like `jadx`, and searches for "key."
    3. He finds the live key and uses it to make payments or read data on the company's account.

!!! warning "Why it works"

    The app file is public. Anything inside it, including "hidden" strings, can be read.

!!! success "Fix"


    - Keep secrets on **your server**; the app asks the server to do the secret work.
    - If the app must hold a token, get it **after login**, short-lived, and store it in the **Android Keystore**.
    - Never commit keys to GitHub. Use secret scanners.
    - If a key leaked: **rotate it** (create a new one and kill the old one).

---

## 2. Inadequate Supply Chain Security

!!! tip "Think of it like"

    You build a house with your own bricks but buy the **doors and windows from an unknown seller**. If the windows have a hidden camera, your house is watched.

!!! example "Scenario"


    1. A developer adds a free "Super Ads" library to earn money from a game app.
    2. The library quietly reads the user's contacts and uploads them to a foreign server.
    3. Users blame the game, and the developer didn't even know.
    4. Another case: the library was safe at first, then the owner pushed a malicious update and everyone who updated got infected.

!!! warning "Why it works"

    Apps use many outside libraries (SDKs), and they get the **same permissions as your app**.

!!! success "Fix"


    - Use well-known libraries from trusted sources, and review what permissions and data they use.
    - **Pin versions**, check updates before applying them, and scan dependencies (OWASP Dependency-Check, Dependabot).
    - Remove libraries you don't need.
    - Keep a list of every library (SBOM).

---

## 3. Insecure Authentication/Authorization

!!! tip "Think of it like"

    A club puts a "VIP only" sign on the door, but **the staff inside never check anyone's pass**. Only the sign says VIP.

!!! example "Scenario"


    1. In the app, a normal user doesn't see the "Admin" screen (the button is hidden).
    2. Sneha intercepts the app's traffic and sees an admin API: `POST /admin/deleteUser`.
    3. She sends it with her own normal login. The server only checks "is the token valid?" and not "is this an admin?", so the user is deleted.
    4. Another version: the app checks the password **offline on the phone**, so a hacker patches the app to always say "correct."

!!! warning "Why it works"

    The developer trusted the app (the client) to enforce rules. But the attacker controls the phone and can skip the app completely.

!!! success "Fix"


    - **All checks happen on the server**: login, role, ownership.
    - Use strong login: MFA, short-lived tokens, refresh tokens that can be revoked.
    - Don't rely on hidden buttons or on-device checks for real security.

---

## 4. Insufficient Input/Output Validation

!!! tip "Think of it like"

    A post office that **delivers any parcel** without looking, including one that explodes when opened.

!!! example "Scenario"


    1. A food app opens orders from a link: `foodapp://order?note=Extra spicy`.
    2. The attacker sends the user a link where the `note` has script code or a weird path like `../../private/file`.
    3. The app puts it straight into a WebView (a mini browser inside the app) or a database query without checking.
    4. The script runs inside the app, or the app reads a private file, or the SQLite query breaks (SQL injection).

!!! warning "Why it works"

    The app trusts data coming from links, other apps, files, the network and users.

!!! success "Fix"


    - **Validate** all input: type, length, allowed characters (use an allow-list).
    - Use **parameterized queries** for the database.
    - Encode data before showing it in a WebView, and disable JavaScript there if not needed.
    - Treat data from other apps (Intents) as untrusted.

---

## 5. Insecure Communication

!!! tip "Think of it like"

    Sending your bank details on a **postcard**. Every postman on the way can read it.

!!! example "Scenario"


    1. Kiran uses a shopping app at a railway-station Wi-Fi.
    2. The app sends login data over plain `http://`.
    3. A hacker on the same Wi-Fi runs a sniffing tool and reads Kiran's username and password.
    4. Even with HTTPS, if the app **ignores certificate errors** (to make testing easy), the hacker can present a fake certificate and still read everything.

!!! warning "Why it works"

    Unencrypted traffic can be read by anyone on the path. Switching off certificate checks removes the lock's purpose.

!!! success "Fix"


    - Use **HTTPS/TLS everywhere** and block cleartext traffic (`usesCleartextTraffic="false"`, Network Security Config).
    - **Never** disable certificate or hostname validation.
    - Use **certificate pinning** for sensitive apps (see Item 19).

---

## 6. Inadequate Privacy Controls

!!! tip "Think of it like"

    A tailor measuring your shirt size who also **notes your phone book, location, and photos**, and sells that list.

!!! example "Scenario"


    1. A flashlight app asks for contacts, location and SMS permissions.
    2. Users tap "Allow" without thinking.
    3. The app collects the data and sells it to advertisers. Or it logs personal data into files other apps can read.

!!! warning "Why it works"

    Apps gather more data than needed, and users rarely check. Mistakes in handling make leaks easy.

!!! success "Fix"


    - **Data minimization**: collect and keep only what's truly needed.
    - Request permissions **only when needed** and explain why.
    - Get clear consent, provide a privacy policy, and allow users to delete their data.
    - Don't put personal data in logs, screenshots, notifications or analytics.

---

## 7. Insufficient Binary Protections

!!! tip "Think of it like"

    A paid recipe book with **no lock and no watermark**. Anyone can copy it, change the price and resell it.

!!! example "Scenario"


    1. A paid learning app checks a "subscription active" flag in code.
    2. A pirate decompiles the APK, changes the check so it always says "true," repackages it and shares it as a free version, sometimes adding malware.
    3. Another attacker uses a tool (Frida) to change the app's behaviour while it runs.

!!! warning "Why it works"

    The app binary is on the attacker's device, and without protection it's easy to read and modify.

!!! success "Fix"


    - **Obfuscate/shrink code** (R8/ProGuard) so it's harder to read.
    - Detect **root, emulators, debuggers and tampering**, and check the app's **signature**; use Play Integrity API.
    - Keep important logic **on the server**.
    - Be realistic: these steps make attacks **harder, not impossible**.

---

## 8. Security Misconfiguration

!!! tip "Think of it like"

    Leaving the **shop's back door and cash drawer open** after closing time because "it was easier for us to work."

!!! example "Scenario"


    1. In the manifest, the developer left `android:debuggable="true"`, `android:allowBackup="true"` and exported an internal screen: `android:exported="true"`.
    2. An attacker connects a debugger and inspects the running app.
    3. Another app on the phone **calls the exported screen** directly, skipping login.
    4. A backup (`adb backup`) copies the app's private data.

!!! warning "Why it works"

    Settings meant for development or convenience stay on in the released app.

!!! success "Fix"


    - Release builds: `debuggable=false`, `allowBackup=false` (or limit what's backed up).
    - Set `exported="false"` unless another app really needs access, and protect needed ones with permissions.
    - Review the manifest and use automated scanners (MobSF) before each release.

---

## 9. Insecure Data Storage

!!! tip "Think of it like"

    Keeping your ATM PIN in a **notebook on the open desk** instead of in a locked drawer.

!!! example "Scenario"


    1. A banking app saves the PIN and token in `SharedPreferences` (a plain XML file).
    2. Someone steals the phone and roots it, or a malicious app on a rooted phone, or a backup file, opens `/data/data/com.bank/shared_prefs/...`.
    3. They read the PIN and token in plain text.
    4. Other leaks: data on the SD card, in the clipboard, in screenshots, in logs.

!!! warning "Why it works"

    Normal files aren't encrypted by the app, and several routes (root, backup, debug) can reach them.

!!! success "Fix"


    - **Don't store** secrets if you can avoid it.
    - If needed, use **encrypted storage backed by the Android Keystore** (e.g., EncryptedSharedPreferences, SQLCipher for databases).
    - Avoid external storage for private data, and block screenshots on sensitive screens (`FLAG_SECURE`).

---

## 10. Insufficient Cryptography

!!! tip "Think of it like"

    Protecting a safe with a **"secret" lock you invented at home**, or a lock everyone knows how to open.

!!! example "Scenario"


    1. An app "protects" passwords with MD5 (an old hash) and no salt.
    2. A breach leaks the hash list. Attackers look the hashes up in free online tables and get most passwords in seconds.
    3. Another app encrypts data with AES but uses a **hardcoded key** (`"mykey12345"`) in the code, so anyone who decompiles the app can decrypt everything.

!!! warning "Why it works"

    Weak or home-made crypto and bad key handling give a false sense of security.

!!! success "Fix"


    - Use **modern, well-tested algorithms**: AES-256-GCM for encryption, **bcrypt/Argon2** for passwords (the server should hash them).
    - **Never invent your own** crypto.
    - Generate keys randomly and store them in the **Keystore**, not in code.
    - Use secure random generators (`SecureRandom`).

---

## PART B: iOS

## 11. Insecure Communication (iOS)

!!! tip "Think of it like"

    Same postcard problem as Android Item 5.

!!! example "Scenario"


    1. A food-delivery app on iPhone disabled Apple's protection by adding `NSAllowsArbitraryLoads = true` in `Info.plist`, because "one API only had HTTP."
    2. Ravi orders food at a mall. His login and address travel in plain text.
    3. A hacker on the mall Wi-Fi reads them.

!!! warning "Why it works"

    iOS normally forces HTTPS through **App Transport Security (ATS)**. Turning it off removes that safety.

!!! success "Fix"


    - Keep **ATS enabled**; fix the server to support HTTPS (TLS 1.2+).
    - Never accept invalid certificates in code (don't bypass `URLSession` delegate trust checks).
    - Add pinning for sensitive apps (Item 19).

---

## 12. Insecure Data Storage (iOS)

!!! tip "Think of it like"

    The PIN-in-a-notebook problem again.

!!! example "Scenario"


    1. An app stores the user's password in `UserDefaults` (a plain `.plist` file).
    2. A person extracts an unencrypted iTunes/Finder backup, or uses a jailbroken phone, and opens the file.
    3. The password is readable. Files saved in "Documents" without protection or in screenshots/snapshots are also at risk.

!!! warning "Why it works"

    Basic app files aren't made for secrets, and backups and jailbreaks expose them.

!!! success "Fix"


    - Store passwords, tokens and keys in the **Keychain**, not `UserDefaults` or files.
    - For files, use **Data Protection** (`NSFileProtectionComplete`) so they're encrypted when the phone is locked.
    - Don't keep data you don't need, and exclude sensitive files from backups.

---

## 13. Insecure Local SQLite Database

!!! tip "Think of it like"

    A **diary kept in an unlocked cupboard**: the whole book is readable by anyone who opens the cupboard.

!!! example "Scenario"


    1. A chat app stores all messages in a normal SQLite file in the app folder.
    2. An attacker with a backup copy or a jailbroken device opens the `.sqlite` file in a free viewer.
    3. Every message, contact and token is there in plain text.

!!! warning "Why it works"

    SQLite files are not encrypted by default, and are simple to open.

!!! success "Fix"


    - Encrypt the database with **SQLCipher** (or similar), and keep the key in the Keychain.
    - Store the minimum data locally, and delete old data.
    - Also use parameterized queries to avoid SQL injection.

---

## 14. Insecure URL Cache

!!! tip "Think of it like"

    A waiter who **keeps used bills (with your card details) in a drawer** "in case you order again."

!!! example "Scenario"


    1. A banking app loads account statements over HTTPS. iOS automatically caches responses in a local file (`Cache.db`) to make things faster.
    2. The statement stays in the cache even after logout.
    3. Someone with access to the phone's files or a backup opens `Cache.db` and reads the statements.

!!! warning "Why it works"

    Caching is **on by default** and developers forget about it.

!!! success "Fix"


    - For sensitive requests, use no-cache settings (`URLCache` disabled, `NSURLRequest.CachePolicy.reloadIgnoringLocalCacheData`, or the server sends `Cache-Control: no-store`).
    - Clear the cache on logout (`URLCache.shared.removeAllCachedResponses()`).

---

## 15. Insecure URL Scheme

!!! tip "Think of it like"

    A **doorbell that does whatever the visitor says**, like "Give this person ₹5,000," with no questions.

!!! example "Scenario"


    1. A payment app registers `payapp://` so other apps can open it, e.g., `payapp://pay?to=shop&amount=500`.
    2. A malicious website or app opens `payapp://pay?to=hacker&amount=50000`.
    3. The app takes the values and starts the payment without confirming.
    4. Another risk: **another app registers the same scheme** and receives the data meant for yours.

!!! warning "Why it works"

    Custom URL schemes are **not unique**, and any app or web page can trigger them.

!!! success "Fix"


    - Treat URL input as untrusted: validate every parameter.
    - Always ask the user to **confirm** actions like payments.
    - Prefer **Universal Links** (verified links tied to your website) over custom schemes.
    - Don't pass secrets in the URL.

---

## 16. Keychain Persistence

!!! tip "Think of it like"

    You leave a rented flat but **your locker stays in the building with your stuff inside**, and the next tenant gets the locker key too.

!!! example "Scenario"


    1. Ravi logs into a banking app. The refresh token is saved in the Keychain.
    2. He uninstalls the app and later sells the phone. On iOS, **Keychain items can survive uninstall**.
    3. The next owner, or Ravi's reinstall, finds the old token still there and the app may auto-login as Ravi.

!!! warning "Why it works"

    The Keychain is separate from the app's own storage, and iOS doesn't automatically clear it.

!!! success "Fix"


    - On the **first launch after install**, check a flag in `UserDefaults` (which *is* deleted with the app). If it's missing, clear old Keychain items.
    - Clear Keychain items at **logout**.
    - Choose protective access settings like `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` so items stay on this device and need an unlocked phone.

---

## 17. Local Authentication

!!! tip "Think of it like"

    A guard checks your fingerprint, then **shouts "OK!" to the vault**. The vault trusts the shout. A thief just stands behind the guard and shouts "OK!"

!!! example "Scenario"


    1. An app uses Face ID with `LAContext.evaluatePolicy(...)`, which returns **true/false** in code.
    2. If true, the app shows the user's account.
    3. An attacker on a jailbroken phone uses a tool (Frida/Objection) to **force that function to return true**, with no face needed.
    4. The app opens.

!!! warning "Why it works"

    A simple true/false in code can be changed by someone who controls the device.

!!! success "Fix"


    - Link the secret to biometrics: store the token in the **Keychain with a biometric access control** (`SecAccessControl` with `.biometryCurrentSet`), so iOS itself only releases it after a real face/fingerprint.
    - For high-risk actions, also check on the **server** (re-enter a password/OTP).
    - Add jailbreak detection as an extra layer.

---

## 18. Sensitive Data in Log Files

!!! tip "Think of it like"

    A cook who **writes every customer's card number on the kitchen notepad** "for debugging." Anyone who walks past reads it.

!!! example "Scenario"


    1. During testing, a developer wrote `print("Login: \(username) \(password)")` or `NSLog(token)` and forgot to remove it.
    2. Sneha plugs her iPhone into a computer and reads the device console (or a crash report/third-party analytics tool picks it up).
    3. The password and token are right there.

!!! warning "Why it works"

    Logs are easy to read and often shared (crash reports, analytics, bug tickets).

!!! success "Fix"


    - **Never log** passwords, tokens, card numbers or personal info.
    - Remove or disable debug logs in release builds (wrap them in `#if DEBUG`).
    - Use privacy-aware logging (`os_log` with `.private`).
    - Scan code for `print`/`NSLog` before release.

---

## 19. SSL/TLS Pinning

!!! tip "Think of it like"

    Instead of trusting **any ID card that looks official**, you keep a photo of the *one real manager* and only trust that exact person.

!!! example "Scenario"


    1. A bank app uses HTTPS but trusts any certificate that the phone's system trusts.
    2. A hacker tricks Priya into installing a fake "root certificate" (or a company/proxy tool does) on her phone.
    3. The hacker's server shows a fake certificate for `bank.com` that the phone accepts, and reads/modifies all of Priya's traffic (MITM).

!!! warning "Why it works"

    The phone trusts a list of certificate authorities, and if that list is tampered with, any fake certificate can pass.

!!! success "Fix"


    - **Pin** the server's certificate or **public key** inside the app: the app accepts only that exact one and refuses all others.
    - Pin the **public key (SPKI)** and keep a backup pin so renewals don't break the app.
    - Remember: pinning can be bypassed on a jailbroken phone, so it's **one layer**, not the only one. (Testers do bypass it to inspect traffic.)

---

## 20. Unprotected Application Access

!!! tip "Think of it like"

    You lock your front door but **leave the cash drawer open** on the counter. Anyone who walks in while you step out can use it.

!!! example "Scenario"


    1. A wallet app only needs unlocking once, then stays open forever.
    2. Kiran hands his unlocked phone to a friend, who opens the wallet app and sends money. Or the iOS app-switcher screenshot shows his balance to anyone looking.
    3. On a jailbroken phone, the app also runs with no checks.

!!! warning "Why it works"

    The phone's lock screen isn't enough: once unlocked, any app is open to whoever is holding the phone.

!!! success "Fix"


    - Add an **app-level lock** (Face ID/Touch ID/PIN) on launch and after a short time in the background.
    - **Auto-logout** after inactivity, and ask again before high-risk actions.
    - Hide content in the app-switcher snapshot (blur or blank the screen when the app goes to the background).
    - Add jailbreak detection for high-security apps.

---

## Quick summary

| Family | Android | iOS | One-line defence |
|---|---|---|---|
| Secrets in the app | 1 Credential usage | 12 Insecure data storage | Keep secrets on the server or in Keystore/Keychain |
| Data stored on the phone | 9 Insecure data storage | 12, 13 SQLite, 14 URL cache, 18 Logs | Encrypt it, store less, never log secrets |
| Data on the network | 5 Insecure communication | 11 Insecure communication, 19 Pinning | HTTPS only; never skip certificate checks; pin |
| Trusting input | 4 Input/output validation | 15 URL scheme | Validate everything from links, apps, files |
| Login and access | 3 Authentication/authorization | 17 Local authentication, 20 Unprotected access | Server-side checks; link biometrics to the Keychain/Keystore |
| Weak crypto | 10 Insufficient cryptography | (also 12, 16) | Modern algorithms; keys in the Keystore/Keychain |
| App can be copied/changed | 7 Binary protections | 17, 20 (jailbreak) | Obfuscation, tamper and root/jailbreak detection |
| Settings and outside code | 8 Misconfiguration, 2 Supply chain, 6 Privacy | 11, 16 | Safe release settings; trusted libraries; collect less |

!!! success "Memory trick"

    *"Phone = attacker's hands. Don't hide secrets in the app, don't leave data lying around, don't trust the network, and let the server make the real decisions."*
