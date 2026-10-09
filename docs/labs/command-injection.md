# Lab: Command injection

**Goal:** make a ping tool run a second command, then fix it so it cannot.

**How to use it:** try a payload on the vulnerable server, read the command it builds, then switch to the fixed server and repeat.

<div id="lab-cmd" class="lab">Loading lab... (this page needs JavaScript)</div>

## What to notice

1. The vulnerable server pastes your text into `ping -c 1 <host>`. The shell treats `;`, `&&`, `||` and `|` as separators, so your text becomes extra commands.
2. `;` always runs the next command, `&&` runs it only if the first succeeded, and `||` only if the first failed.
3. The fixed server validates the host with an allow-list pattern and runs `ping` with an **argument list** and no shell, so the separators have no special meaning.
4. For detection, the strongest evidence is a **process-creation event**: the web server user starting `whoami`, `id` or `cat`.

## The fix

```python
# Vulnerable
os.system("ping -c 1 " + host)

# Fixed: validate, then run without a shell
if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?", host):
    return 400
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5)
```

Even better, avoid shelling out at all and use a library. Run the app with the lowest privileges so any slip does little damage.

**Read more in the guide:** [Web: Command Injection](../part-1-web.md#2-command-injection), [API: Command Injection](../part-2-api.md#4-command-injection), [AWS: Lambda Command Injection](../part-6-aws.md#3-lambda-command-injection) and [Desktop: Injections](../part-7-desktop.md#1-injections).

!!! note "About this simulator"

    It is a fake shell with canned output for a few commands. No real command is ever run.
