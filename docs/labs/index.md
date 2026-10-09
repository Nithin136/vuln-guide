# Labs

Hands-on, in-browser simulators. Each lab follows the same four steps used across this guide: **Explain, Try it, Detect, Fix**.

!!! success "Safe by design"

    Everything runs inside your browser and is **simulated**. There is no real database, shell or server behind these labs, nothing you type is sent anywhere, and your input is never rendered as real HTML or executed. Only test systems you own or have written permission to test.

<div class="grid cards" markdown>

- **[SQL injection](sqli.md)**

    Bypass a fake login with `' OR '1'='1`, see the query your input becomes, then switch on parameterized queries.

- **[Cross-site scripting (XSS)](xss.md)**

    Compare a page that inserts raw HTML with one that encodes output, and see what the attacker's script would do.

- **[IDOR / BOLA](idor.md)**

    Change an order ID in a fake API, scan a range of IDs, then add the ownership check that stops it.

- **[Command injection](command-injection.md)**

    Add `; whoami` to a ping tool and watch a fake shell run it, then fix it without the shell.

</div>

## What each lab shows

| Step | In the lab |
|---|---|
| **Explain** | The short story and root cause from the guide, linked from each lab |
| **Try it** | Editable input and ready-made payloads |
| **Detect** | A "What a SOC analyst would see" panel: simulated log lines, patterns that matched, and an example detection idea |
| **Fix** | A switch between the vulnerable and the fixed version of the same app |
