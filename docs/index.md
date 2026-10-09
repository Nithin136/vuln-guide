# Vulnerabilities Explained Simply

A scenario-based security reference. Every vulnerability is explained in plain language with a real-life picture, a step-by-step attack story and a practical fix.

[Download the full guide (PDF)](assets/Vulnerabilities_Explained_Simply.pdf){ .md-button .md-button--primary }
[One-page revision sheet](revision-sheet.md){ .md-button }

## How to read each vulnerability

!!! tip "Think of it like"

    A real-life picture, so the idea clicks first.

!!! example "Scenario"

    A short story with named people and numbered steps showing exactly how the attack happens.

!!! warning "Why it works"

    The root cause: the one mistake that makes the attack possible.

!!! success "Fix"

    What to change, and why that change stops the attack.

## Pick a topic

<div class="grid cards" markdown>

- **[1. Web](part-1-web.md)**

    25 items: injection, XSS, CSRF, SSRF, session and access-control problems.

- **[2. API](part-2-api.md)**

    13 items: BOLA, BFLA, mass assignment, rate limiting, XXE and more.

- **[3. LLM](part-3-llm.md)**

    10 items: prompt injection, poisoning, excessive agency, leakage.

- **[4. Android and iOS](part-4-android-ios.md)**

    20 items: insecure storage, communication, pinning, Keychain, URL schemes.

- **[5. Docker](part-5-docker.md)**

    10 items for Docker and Docker Compose, with safe Compose examples.

- **[6. AWS](part-6-aws.md)**

    13 items: S3, Lambda, Cognito, SSRF, subdomain takeover.

- **[7. Desktop (C/C++)](part-7-desktop.md)**

    10 items: buffer overflow, DLL hijacking, weak crypto, logging.

- **[8. Front-end](part-8-frontend.md)**

    6 problems across Angular, React, Vue, JavaScript and TypeScript.

- **[9. Kubernetes](part-9-kubernetes.md)**

    10 items: RBAC, secrets, network policies, workload hardening.

</div>

## Try the labs

Four in-browser simulators let you attack and fix a fake app: [SQL injection](labs/sqli.md), [XSS](labs/xss.md), [IDOR](labs/idor.md) and [command injection](labs/command-injection.md). Each one has a "what a SOC analyst would see" panel. Everything is simulated in your browser. You can also test yourself with the [quiz](quiz.md).

## Use it for interview revision

1. Read the glossary at the top of each topic first.
2. Go item by item, or use the search box to jump to a vulnerability.
3. Before an interview, read the **Quick summary** table at the end of each topic and the [revision sheet](revision-sheet.md).

!!! warning "Educational use only"

    This site explains vulnerabilities so they can be understood, detected and fixed. Only test systems you own or have written permission to test.
