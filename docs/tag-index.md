# Tag index

Every vulnerability in this guide mapped to the standards employers and tools use: **CWE** (the weakness type), **MITRE ATT&CK** (how attackers use it) and an **OWASP** category where one fits. Use the search box or your browser's find (Ctrl+F) to look up a CWE or technique ID.

!!! warning "Read this before quoting a mapping"

    These are best-fit mappings. ATT&CK describes attacker behaviour, so many weaknesses have no clean technique: those show `-`. Check the linked CWE / ATT&CK page before you cite one in a report or interview.

**117** vulnerabilities, **117** with at least one tag.

## 1. Web

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Clickjacking](part-1-web.md#1-clickjacking) | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | - | - |
| 2 | [Command Injection](part-1-web.md#2-command-injection) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | [T1190](https://attack.mitre.org/techniques/T1190/), [T1059](https://attack.mitre.org/techniques/T1059/) | OWASP A03:2021 |
| 3 | [Components with Vulnerabilities](part-1-web.md#3-components-with-vulnerabilities) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP A06:2021 |
| 4 | [Cross-Site Request Forgery (CSRF)](part-1-web.md#4-cross-site-request-forgery-csrf) | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | - | OWASP A01:2021 |
| 5 | [Directory Traversal](part-1-web.md#5-directory-traversal) | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP A01:2021 |
| 6 | [DOM XSS (Cross-Site Scripting, browser side)](part-1-web.md#6-dom-xss-cross-site-scripting-browser-side) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | OWASP A03:2021 |
| 7 | [Forced Browsing](part-1-web.md#7-forced-browsing) | [CWE-425](https://cwe.mitre.org/data/definitions/425.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | - | OWASP A01:2021 |
| 8 | [Header Injection](part-1-web.md#8-header-injection) | [CWE-113](https://cwe.mitre.org/data/definitions/113.html) | - | OWASP A03:2021 |
| 9 | [Horizontal Privilege Escalation](part-1-web.md#9-horizontal-privilege-escalation) | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | - | OWASP A01:2021 |
| 10 | [Insecure URL Redirect](part-1-web.md#10-insecure-url-redirect) | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | - | OWASP A01:2021 |
| 11 | [Leftover Debug Code](part-1-web.md#11-leftover-debug-code) | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | - | OWASP A05:2021 |
| 12 | [Log4j (CVE-2021-44228, "Log4Shell")](part-1-web.md#12-log4j-cve-2021-44228-log4shell) | [CWE-917](https://cwe.mitre.org/data/definitions/917.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP A06:2021 |
| 13 | [PII Data in URL](part-1-web.md#13-pii-data-in-url) | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | - | - |
| 14 | [Reflected XSS](part-1-web.md#14-reflected-xss) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | OWASP A03:2021 |
| 15 | [Ruby rest-client 1.6.13 Backdoor](part-1-web.md#15-ruby-rest-client-1613-backdoor) | [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | OWASP A08:2021 |
| 16 | [Sensitive Server-Side Request Forgery (SSRF)](part-1-web.md#16-sensitive-server-side-request-forgery-ssrf) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | [T1190](https://attack.mitre.org/techniques/T1190/), [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | OWASP A10:2021 |
| 17 | [Session Fixation](part-1-web.md#17-session-fixation) | [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | - | OWASP A07:2021 |
| 18 | [SQL Injection](part-1-web.md#18-sql-injection) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP A03:2021 |
| 19 | [Stored XSS](part-1-web.md#19-stored-xss) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | OWASP A03:2021 |
| 20 | [TikTok XSS Vulnerability](part-1-web.md#20-tiktok-xss-vulnerability) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | - | OWASP A03:2021 |
| 21 | [Token Exposure in URL](part-1-web.md#21-token-exposure-in-url) | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | [T1528](https://attack.mitre.org/techniques/T1528/) | - |
| 22 | [User Enumeration](part-1-web.md#22-user-enumeration) | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | [T1087](https://attack.mitre.org/techniques/T1087/) | OWASP A07:2021 |
| 23 | [Vertical Privilege Escalation](part-1-web.md#23-vertical-privilege-escalation) | [CWE-269](https://cwe.mitre.org/data/definitions/269.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | - | OWASP A01:2021 |
| 24 | [Weak Randomness](part-1-web.md#24-weak-randomness) | [CWE-330](https://cwe.mitre.org/data/definitions/330.html), [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | - | OWASP A02:2021 |
| 25 | [XML Injection](part-1-web.md#25-xml-injection) | [CWE-91](https://cwe.mitre.org/data/definitions/91.html) | - | OWASP A03:2021 |

## 2. API

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Broken Function Level Authorization (BFLA)](part-2-api.md#1-broken-function-level-authorization-bfla) | [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | - | OWASP API5:2019 |
| 2 | [Broken Object Level Authorization (BOLA, also called IDOR)](part-2-api.md#2-broken-object-level-authorization-bola-also-called-idor) | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | - | OWASP API1:2019 |
| 3 | [Broken User Authentication](part-2-api.md#3-broken-user-authentication) | [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | [T1110](https://attack.mitre.org/techniques/T1110/) | OWASP API2:2019 |
| 4 | [Command Injection](part-2-api.md#4-command-injection) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | [T1190](https://attack.mitre.org/techniques/T1190/), [T1059](https://attack.mitre.org/techniques/T1059/) | OWASP API8:2019 |
| 5 | [Excessive Data Exposure](part-2-api.md#5-excessive-data-exposure) | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | - | OWASP API3:2019 |
| 6 | [Improper Assets Management](part-2-api.md#6-improper-assets-management) | - | - | OWASP API9:2019 |
| 7 | [Insufficient Logging and Monitoring](part-2-api.md#7-insufficient-logging-and-monitoring) | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | - | OWASP API10:2019 |
| 8 | [Lack of Resources and Rate Limiting](part-2-api.md#8-lack-of-resources-and-rate-limiting) | [CWE-770](https://cwe.mitre.org/data/definitions/770.html), [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | [T1499](https://attack.mitre.org/techniques/T1499/), [T1110](https://attack.mitre.org/techniques/T1110/) | OWASP API4:2019 |
| 9 | [Mass Assignment](part-2-api.md#9-mass-assignment) | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | - | OWASP API6:2019 |
| 10 | [Security Misconfiguration 1: Unsafe Defaults and Detailed Errors](part-2-api.md#10-security-misconfiguration-1-unsafe-defaults-and-detailed-errors) | [CWE-16](https://cwe.mitre.org/data/definitions/16.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | - | OWASP API7:2019 |
| 11 | [Security Misconfiguration 2: Open CORS, Missing Headers and Extra Methods](part-2-api.md#11-security-misconfiguration-2-open-cors-missing-headers-and-extra-methods) | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | - | OWASP API7:2019 |
| 12 | [SQL Injection](part-2-api.md#12-sql-injection) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP API8:2019 |
| 13 | [XXE Injection (XML External Entity)](part-2-api.md#13-xxe-injection-xml-external-entity) | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP API8:2019 |

## 3. LLM

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Prompt Injection](part-3-llm.md#1-prompt-injection) | [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) | - | OWASP LLM01:2025 |
| 2 | [Sensitive Information Disclosure](part-3-llm.md#2-sensitive-information-disclosure) | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | - | OWASP LLM02:2025 |
| 3 | [Supply Chain](part-3-llm.md#3-supply-chain) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | - | OWASP LLM03:2025 |
| 4 | [Data and Model Poisoning](part-3-llm.md#4-data-and-model-poisoning) | - | - | OWASP LLM04:2025 |
| 5 | [Improper Output Handling](part-3-llm.md#5-improper-output-handling) | [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | - | OWASP LLM05:2025 |
| 6 | [Excessive Agency](part-3-llm.md#6-excessive-agency) | - | - | OWASP LLM06:2025 |
| 7 | [System Prompt Leakage](part-3-llm.md#7-system-prompt-leakage) | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | - | OWASP LLM07:2025 |
| 8 | [Vector and Embedding Weaknesses](part-3-llm.md#8-vector-and-embedding-weaknesses) | [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | - | OWASP LLM08:2025 |
| 9 | [Misinformation](part-3-llm.md#9-misinformation) | - | - | OWASP LLM09:2025 |
| 10 | [Denial of Service (called "Unbounded Consumption" in newer lists)](part-3-llm.md#10-denial-of-service-called-unbounded-consumption-in-newer-lists) | [CWE-400](https://cwe.mitre.org/data/definitions/400.html), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | OWASP LLM10:2025 |

## 4. Android and iOS

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Improper Credential Usage](part-4-android-ios.md#1-improper-credential-usage) | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | OWASP Mobile M1:2024 |
| 2 | [Inadequate Supply Chain Security](part-4-android-ios.md#2-inadequate-supply-chain-security) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | OWASP Mobile M2:2024 |
| 3 | [Insecure Authentication/Authorization](part-4-android-ios.md#3-insecure-authenticationauthorization) | [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | - | OWASP Mobile M3:2024 |
| 4 | [Insufficient Input/Output Validation](part-4-android-ios.md#4-insufficient-inputoutput-validation) | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | - | OWASP Mobile M4:2024 |
| 5 | [Insecure Communication](part-4-android-ios.md#5-insecure-communication) | [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [T1557](https://attack.mitre.org/techniques/T1557/), [T1040](https://attack.mitre.org/techniques/T1040/) | OWASP Mobile M5:2024 |
| 6 | [Inadequate Privacy Controls](part-4-android-ios.md#6-inadequate-privacy-controls) | [CWE-359](https://cwe.mitre.org/data/definitions/359.html) | - | OWASP Mobile M6:2024 |
| 7 | [Insufficient Binary Protections](part-4-android-ios.md#7-insufficient-binary-protections) | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | - | OWASP Mobile M7:2024 |
| 8 | [Security Misconfiguration](part-4-android-ios.md#8-security-misconfiguration) | [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-926](https://cwe.mitre.org/data/definitions/926.html) | - | OWASP Mobile M8:2024 |
| 9 | [Insecure Data Storage](part-4-android-ios.md#9-insecure-data-storage) | [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | - | OWASP Mobile M9:2024 |
| 10 | [Insufficient Cryptography](part-4-android-ios.md#10-insufficient-cryptography) | [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | - | OWASP Mobile M10:2024 |
| 11 | [Insecure Communication (iOS)](part-4-android-ios.md#11-insecure-communication-ios) | [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [T1557](https://attack.mitre.org/techniques/T1557/) | OWASP Mobile M5:2024 |
| 12 | [Insecure Data Storage (iOS)](part-4-android-ios.md#12-insecure-data-storage-ios) | [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | - | OWASP Mobile M9:2024 |
| 13 | [Insecure Local SQLite Database](part-4-android-ios.md#13-insecure-local-sqlite-database) | [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-922](https://cwe.mitre.org/data/definitions/922.html) | - | OWASP Mobile M9:2024 |
| 14 | [Insecure URL Cache](part-4-android-ios.md#14-insecure-url-cache) | [CWE-525](https://cwe.mitre.org/data/definitions/525.html) | - | OWASP Mobile M9:2024 |
| 15 | [Insecure URL Scheme](part-4-android-ios.md#15-insecure-url-scheme) | [CWE-939](https://cwe.mitre.org/data/definitions/939.html) | - | OWASP Mobile M4:2024 |
| 16 | [Keychain Persistence](part-4-android-ios.md#16-keychain-persistence) | [CWE-459](https://cwe.mitre.org/data/definitions/459.html) | - | OWASP Mobile M9:2024 |
| 17 | [Local Authentication](part-4-android-ios.md#17-local-authentication) | [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-603](https://cwe.mitre.org/data/definitions/603.html) | - | OWASP Mobile M3:2024 |
| 18 | [Sensitive Data in Log Files](part-4-android-ios.md#18-sensitive-data-in-log-files) | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | - | OWASP Mobile M9:2024 |
| 19 | [SSL/TLS Pinning](part-4-android-ios.md#19-ssltls-pinning) | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [T1557](https://attack.mitre.org/techniques/T1557/) | OWASP Mobile M5:2024 |
| 20 | [Unprotected Application Access](part-4-android-ios.md#20-unprotected-application-access) | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | - | OWASP Mobile M3:2024 |

## 5. Docker

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Container Resource Limitation](part-5-docker.md#1-container-resource-limitation) | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | [T1499](https://attack.mitre.org/techniques/T1499/), [T1496](https://attack.mitre.org/techniques/T1496/) | - |
| 2 | [Exposed Docker Socket](part-5-docker.md#2-exposed-docker-socket) | [CWE-250](https://cwe.mitre.org/data/definitions/250.html), [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | [T1611](https://attack.mitre.org/techniques/T1611/), [T1610](https://attack.mitre.org/techniques/T1610/) | - |
| 3 | [Host Update](part-5-docker.md#3-host-update) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1611](https://attack.mitre.org/techniques/T1611/), [T1068](https://attack.mitre.org/techniques/T1068/) | - |
| 4 | [Improper Write Permissions for Volumes and Host Filesystem](part-5-docker.md#4-improper-write-permissions-for-volumes-and-host-filesystem) | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | [T1611](https://attack.mitre.org/techniques/T1611/) | - |
| 5 | [Insecure Container Registries](part-5-docker.md#5-insecure-container-registries) | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [T1195](https://attack.mitre.org/techniques/T1195/) | - |
| 6 | [Minimal Base Image](part-5-docker.md#6-minimal-base-image) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | - | - |
| 7 | [Privileged Containers](part-5-docker.md#7-privileged-containers) | [CWE-250](https://cwe.mitre.org/data/definitions/250.html), [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | [T1611](https://attack.mitre.org/techniques/T1611/) | - |
| 8 | [Sensitive Data Leak via Docker Images](part-5-docker.md#8-sensitive-data-leak-via-docker-images) | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | - |
| 9 | [Unsegregated Container Network](part-5-docker.md#9-unsegregated-container-network) | [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | - | - |
| 10 | [Unverified Container Images](part-5-docker.md#10-unverified-container-images) | [CWE-494](https://cwe.mitre.org/data/definitions/494.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | [T1204.003](https://attack.mitre.org/techniques/T1204/003/) | - |

## 6. AWS

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Dangerous Dependencies](part-6-aws.md#1-dangerous-dependencies) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | - |
| 2 | [Excessive Logging](part-6-aws.md#2-excessive-logging) | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | - | - |
| 3 | [Lambda Command Injection](part-6-aws.md#3-lambda-command-injection) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | [T1059](https://attack.mitre.org/techniques/T1059/) | - |
| 4 | [Lambda XXE Injection](part-6-aws.md#4-lambda-xxe-injection) | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | - |
| 5 | [Misconfigured AWS Cognito Attributes](part-6-aws.md#5-misconfigured-aws-cognito-attributes) | [CWE-915](https://cwe.mitre.org/data/definitions/915.html), [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | [T1098](https://attack.mitre.org/techniques/T1098/) | - |
| 6 | [Misconfigured AWS Cognito Profile Allows Self-Registration](part-6-aws.md#6-misconfigured-aws-cognito-profile-allows-self-registration) | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | - |
| 7 | [Misconfigured Reverse Proxy](part-6-aws.md#7-misconfigured-reverse-proxy) | [CWE-16](https://cwe.mitre.org/data/definitions/16.html) | - | - |
| 8 | [S3 Bucket: Authenticated Users Have "WRITE" Access](part-6-aws.md#8-s3-bucket-authenticated-users-have-write-access) | [CWE-732](https://cwe.mitre.org/data/definitions/732.html), [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | - |
| 9 | [S3 Bucket: Public "READ" Access](part-6-aws.md#9-s3-bucket-public-read-access) | [CWE-732](https://cwe.mitre.org/data/definitions/732.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [T1530](https://attack.mitre.org/techniques/T1530/) | - |
| 10 | [S3 Directory Traversal](part-6-aws.md#10-s3-directory-traversal) | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | [T1530](https://attack.mitre.org/techniques/T1530/) | - |
| 11 | [Server-Side Request Forgery (SSRF)](part-6-aws.md#11-server-side-request-forgery-ssrf) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | [T1552.005](https://attack.mitre.org/techniques/T1552/005/), [T1190](https://attack.mitre.org/techniques/T1190/) | - |
| 12 | [Subdomain Takeover](part-6-aws.md#12-subdomain-takeover) | - | [T1584.001](https://attack.mitre.org/techniques/T1584/001/) | - |
| 13 | [Weak S3 POST Upload Policy](part-6-aws.md#13-weak-s3-post-upload-policy) | [CWE-434](https://cwe.mitre.org/data/definitions/434.html), [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - |

## 7. Desktop

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Injections](part-7-desktop.md#1-injections) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | [T1059](https://attack.mitre.org/techniques/T1059/) | - |
| 2 | [Broken Authentication and Session Management](part-7-desktop.md#2-broken-authentication-and-session-management) | [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-613](https://cwe.mitre.org/data/definitions/613.html) | - | - |
| 3 | [Sensitive Data Exposure](part-7-desktop.md#3-sensitive-data-exposure) | [CWE-311](https://cwe.mitre.org/data/definitions/311.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | - |
| 4 | [Improper Cryptography Usage](part-7-desktop.md#4-improper-cryptography-usage) | [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html), [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | - | - |
| 5 | [Improper Authorization](part-7-desktop.md#5-improper-authorization) | [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | [T1068](https://attack.mitre.org/techniques/T1068/) | - |
| 6 | [Security Misconfiguration](part-7-desktop.md#6-security-misconfiguration) | [CWE-16](https://cwe.mitre.org/data/definitions/16.html), [CWE-427](https://cwe.mitre.org/data/definitions/427.html), [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | - |
| 7 | [Insecure Communication](part-7-desktop.md#7-insecure-communication) | [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [T1040](https://attack.mitre.org/techniques/T1040/), [T1557](https://attack.mitre.org/techniques/T1557/) | - |
| 8 | [Poor Code Quality](part-7-desktop.md#8-poor-code-quality) | [CWE-120](https://cwe.mitre.org/data/definitions/120.html), [CWE-787](https://cwe.mitre.org/data/definitions/787.html), [CWE-416](https://cwe.mitre.org/data/definitions/416.html), [CWE-134](https://cwe.mitre.org/data/definitions/134.html), [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | [T1203](https://attack.mitre.org/techniques/T1203/) | - |
| 9 | [Using Components with Known Vulnerabilities](part-7-desktop.md#9-using-components-with-known-vulnerabilities) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1203](https://attack.mitre.org/techniques/T1203/) | - |
| 10 | [Insufficient Logging and Monitoring](part-7-desktop.md#10-insufficient-logging-and-monitoring) | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | - | - |

## 8. Front-end

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Cross-Site Request Forgery (CSRF)](part-8-frontend.md#1-cross-site-request-forgery-csrf) | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | - | OWASP A01:2021 |
| 2 | [Direct DOM Manipulation XSS](part-8-frontend.md#2-direct-dom-manipulation-xss) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | OWASP A03:2021 |
| 3 | [Template Concatenation / Untrusted Template Usage XSS](part-8-frontend.md#3-template-concatenation-untrusted-template-usage-xss) | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | - | OWASP A03:2021 |
| 4 | [Sanitization Misuse XSS](part-8-frontend.md#4-sanitization-misuse-xss) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | - | OWASP A03:2021 |
| 5 | [Untrusted HTML Rendering XSS](part-8-frontend.md#5-untrusted-html-rendering-xss) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | OWASP A03:2021 |
| 6 | [Components with Known Vulnerabilities](part-8-frontend.md#6-components-with-known-vulnerabilities) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | OWASP A06:2021 |

## 9. Kubernetes

| # | Vulnerability | CWE | ATT&CK | OWASP |
|---|---|---|---|---|
| 1 | [Broken Authentication Mechanisms](part-9-kubernetes.md#1-broken-authentication-mechanisms) | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [T1078](https://attack.mitre.org/techniques/T1078/) | OWASP K8s K06 |
| 2 | [Inadequate Logging and Monitoring](part-9-kubernetes.md#2-inadequate-logging-and-monitoring) | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | - | OWASP K8s K05 |
| 3 | [Insecure Workload Configuration](part-9-kubernetes.md#3-insecure-workload-configuration) | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | [T1611](https://attack.mitre.org/techniques/T1611/) | OWASP K8s K01 |
| 4 | [Lack of Centralized Policy Enforcement](part-9-kubernetes.md#4-lack-of-centralized-policy-enforcement) | - | - | OWASP K8s K04 |
| 5 | [Misconfigured Cluster Components](part-9-kubernetes.md#5-misconfigured-cluster-components) | [CWE-16](https://cwe.mitre.org/data/definitions/16.html) | [T1190](https://attack.mitre.org/techniques/T1190/) | OWASP K8s K09 |
| 6 | [Missing Network Segmentation Controls](part-9-kubernetes.md#6-missing-network-segmentation-controls) | [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | - | OWASP K8s K07 |
| 7 | [Overly Permissive RBAC Configuration](part-9-kubernetes.md#7-overly-permissive-rbac-configuration) | [CWE-269](https://cwe.mitre.org/data/definitions/269.html), [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | [T1078](https://attack.mitre.org/techniques/T1078/) | OWASP K8s K03 |
| 8 | [Secrets Management Failure](part-9-kubernetes.md#8-secrets-management-failure) | [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [T1552.007](https://attack.mitre.org/techniques/T1552/007/) | OWASP K8s K08 |
| 9 | [Supply Chain Vulnerabilities](part-9-kubernetes.md#9-supply-chain-vulnerabilities) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1195](https://attack.mitre.org/techniques/T1195/) | OWASP K8s K02 |
| 10 | [Vulnerable Kubernetes Components (Security Audit)](part-9-kubernetes.md#10-vulnerable-kubernetes-components-security-audit) | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | [T1068](https://attack.mitre.org/techniques/T1068/) | OWASP K8s K10 |
