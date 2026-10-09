# Docker and Docker Compose Vulnerabilities: Explained Simply (Part 5)

Every item has: **Think of it like** → **Scenario** (step by step) → **Why it works** → **Fix** (and why it works) → **In Compose** (how it looks in `docker-compose.yml`).

## Words you will see a lot

- **Container**: a **small sealed box** that holds one app and everything it needs. Many boxes can run on one computer.
- **Image**: the **recipe/blueprint** used to make a container (like a cake mould; the container is the cake).
- **Dockerfile**: the text file with the steps to build an image.
- **Registry (Docker Hub)**: an **app store for images**. You "pull" images from it.
- **Host**: the real computer (server) that runs the containers.
- **Volume / bind mount**: a **door** between the box and the host's folders, so the container can read or write host files.
- **Docker daemon & `docker.sock`**: the daemon is the **manager** that creates and controls all containers. `docker.sock` is the **phone line to that manager**. Whoever holds it can give the manager orders.
- **Root**: the all-powerful user (admin). Inside a container it's *also* powerful by default.
- **Base image**: the starting layer of an image (e.g., Ubuntu or Alpine).
- **Docker Compose**: one file (`docker-compose.yml`) that starts **many containers together** (web + database + cache).
- **Port**: a numbered door on a computer. `-p 8080:80` opens a door to the outside world.

!!! info "Golden rule for containers"

    *containers are **not** full walls. They share the host's engine (kernel). One weak container setting can let an attacker reach the host or the other containers.*


---

## 1. Container Resource Limitation

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/770.html" target="_blank" rel="noopener noreferrer">CWE-770</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1499/" target="_blank" rel="noopener noreferrer" title="Endpoint Denial of Service">ATT&amp;CK T1499</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1496/" target="_blank" rel="noopener noreferrer" title="Resource Hijacking">ATT&amp;CK T1496</a></p>

!!! tip "Think of it like"

    A shared flat where **one roommate runs the AC, heater and geyser all day** and the electricity trips for everyone.

!!! example "Scenario"


    1. A web container has a bug (a memory leak) or is attacked by a flood of requests.
    2. It keeps using more memory and CPU, with no limit.
    3. The server runs out of RAM and starts killing other containers, including the database. The entire application goes down (DoS, denial of service).
    4. An attacker who hacked into a container can also run a crypto-miner that uses all CPU.

!!! warning "Why it works"

    By default, a container may use as much of the host's CPU and memory as it wants.

!!! success "Fix"

    Set limits so one container can't starve the rest.

    - Docker: `docker run --memory=512m --cpus=1 --pids-limit=200 myapp`
    - Limits also cap the damage of a hacked container (a miner can't take over everything).

!!! info "In Compose"


    ```yaml
    services:
      web:
        image: myapp
        deploy:
          resources:
            limits:
              cpus: "1.0"
              memory: 512M
    ```

---

## 2. Exposed Docker Socket

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/250.html" target="_blank" rel="noopener noreferrer">CWE-250</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/269.html" target="_blank" rel="noopener noreferrer">CWE-269</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1611/" target="_blank" rel="noopener noreferrer" title="Escape to Host">ATT&amp;CK T1611</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1610/" target="_blank" rel="noopener noreferrer" title="Deploy Container">ATT&amp;CK T1610</a></p>

!!! tip "Think of it like"

    Giving a visitor **the direct phone line to the building manager**, who can unlock any door and give out master keys. Whatever the visitor says, the manager does.

!!! example "Scenario"


    1. A monitoring container is started with `-v /var/run/docker.sock:/var/run/docker.sock` so it can "see other containers."
    2. An attacker finds a bug in that container and gets in.
    3. From inside, he talks to the Docker manager through the socket and starts a **new container that mounts the host's entire disk as writable**.
    4. Now he can read passwords, add his own SSH key or fully control the host. **This is effectively root on the server.**

!!! warning "Why it works"

    Access to `docker.sock` = permission to command Docker = control of the host. Even `:ro` (read-only) doesn't help, because he still sends commands over the socket.

!!! success "Fix"


    - **Don't mount the socket** into normal containers.
    - If a tool truly needs it, use a **socket proxy** that allows only specific safe calls (read-only API), or run Docker in **rootless mode**.
    - Never expose the Docker API over the network (TCP port 2375 without TLS and authentication).

!!! info "In Compose"

    look for `volumes: - /var/run/docker.sock:/var/run/docker.sock` and remove or replace it.

---

## 3. Host Update

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1611/" target="_blank" rel="noopener noreferrer" title="Escape to Host">ATT&amp;CK T1611</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1068/" target="_blank" rel="noopener noreferrer" title="Exploitation for Privilege Escalation">ATT&amp;CK T1068</a></p>

!!! tip "Think of it like"

    Your flats are separate, but they all share **one old main gate** with a known broken lock. Fix every flat's door as much as you like, but a thief just opens the main gate.

!!! example "Scenario"


    1. The server's Linux kernel and the container tools (Docker engine, `runc`) are 2 years old.
    2. A **container escape bug** was published for that version (for example, flaws in `runc` have allowed breaking out).
    3. An attacker who gets into any container runs the public exploit and **jumps out onto the host**.
    4. Now he controls the host and every other container.

!!! warning "Why it works"

    Containers **share the host's kernel**. A kernel or runtime bug breaks the "box" for everything.

!!! success "Fix"


    - **Patch regularly**: host OS, kernel, Docker Engine and container runtime. Reboot when needed (or use live patching).
    - Use a minimal host OS built for containers where possible, and subscribe to security advisories.
    - Add a vulnerability scanner for hosts.

!!! info "In Compose"

    Compose itself can't patch the host, so this is an operations task outside the YAML file.

---

## 4. Improper Write Permissions for Volumes and Host Filesystem

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/732.html" target="_blank" rel="noopener noreferrer">CWE-732</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1611/" target="_blank" rel="noopener noreferrer" title="Escape to Host">ATT&amp;CK T1611</a></p>

!!! tip "Think of it like"

    A tenant is given a **key to the shared store room** and also lets the tenant **rewrite the building's rule book** stored there.

!!! example "Scenario"


    1. A developer mounts the host's `/etc` or even `/` into a container as writable, "to make debugging easy": `-v /:/host`.
    2. An attacker who breaks into this container edits `/host/etc/passwd` or `/host/root/.ssh/authorized_keys`.
    3. He now can log in to the host as root through SSH.
    4. A milder example: a writable shared volume lets a hacked container plant a malicious script that another container then runs.

!!! warning "Why it works"

    A mounted host folder is a **real door to the host**, and writable means the container can change it.

!!! success "Fix"


    - Mount **only the specific folder needed**, never `/`, `/etc`, `/var/run` or home folders.
    - Use **read-only** whenever possible: `-v /data:/data:ro`, and make the container's own filesystem read-only: `--read-only`.
    - Run containers as a **non-root user** so file permissions protect the host's files.

!!! info "In Compose"


    ```yaml
    services:
      web:
        read_only: true
        volumes:
          - ./config:/app/config:ro
    ```

---

## 5. Insecure Container Registries

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/319.html" target="_blank" rel="noopener noreferrer">CWE-319</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1195/" target="_blank" rel="noopener noreferrer" title="Supply Chain Compromise">ATT&amp;CK T1195</a></p>

!!! tip "Think of it like"

    Collecting your parcels from a **shop that has no ID check and no seal**, so anyone can swap your parcel with a fake one on the way.

!!! example "Scenario"


    1. The company runs its own private registry at `http://registry.company.local:5000`, plain HTTP, no login.
    2. The team configured Docker with `--insecure-registry` so it works.
    3. An attacker on the network (or anyone who can reach the registry) pushes a **tampered image with the same name** or intercepts the download.
    4. Next deployment pulls the fake image and runs the attacker's code in production.

!!! warning "Why it works"

    Without encryption and login, there's no proof that the image came from the right place or wasn't changed.

!!! success "Fix"


    - Use registries with **HTTPS/TLS** and **authentication**, with roles (who can push and who can only pull).
    - Don't use `--insecure-registry` except for local testing.
    - Use **image signing** and scanning in the registry, and keep it updated and private.

!!! info "In Compose"

    check that the `image:` lines use `registry.company.com/...` over secure registries and trusted names, with no random public sources.

---

## 6. Minimal Base Image

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a></p>

!!! tip "Think of it like"

    Packing a **full toolbox, power drills and a gas cylinder** into a small room that only needed a table. If a burglar gets in, he has all the tools right there.

!!! example "Scenario"


    1. A developer builds an app on a full `ubuntu` image (hundreds of tools: `curl`, `wget`, `bash`, compilers, package manager).
    2. The app has a small bug and the attacker gets a shell inside.
    3. He uses the tools already there (`curl` to download malware, `apt` to install more tools, `gcc` to compile exploits).
    4. Also, the big image contains **hundreds of packages**, and each one may have its own known security bugs.

!!! warning "Why it works"

    More software = **bigger attack surface** and more bugs to patch.

!!! success "Fix"


    - Use **small images**: `alpine`, `-slim` versions, or **distroless** images (only your app and its runtime, no shell).
    - Use **multi-stage builds**: build with the big image, then copy only the final app into a small image.
    - Scan images regularly (Trivy, Grype) and rebuild when base images are updated.

    ```dockerfile
    FROM golang:1.22 AS build
    ...
    FROM gcr.io/distroless/static   # tiny final image
    COPY --from=build /app /app
    ```

!!! info "In Compose"

    the `image:` or `build:` entries should point to small, maintained images.

---

## 7. Privileged Containers

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/250.html" target="_blank" rel="noopener noreferrer">CWE-250</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/269.html" target="_blank" rel="noopener noreferrer">CWE-269</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1611/" target="_blank" rel="noopener noreferrer" title="Escape to Host">ATT&amp;CK T1611</a></p>

!!! tip "Think of it like"

    Giving a **guest a master key and permission to rebuild the walls**. The "box" is still there in name, but it has no real limits.

!!! example "Scenario"


    1. A developer runs a container with `--privileged` because "some device wasn't working."
    2. That container now has almost **all powers of root on the host**: it can see host devices, mount disks and change settings.
    3. If an attacker enters it, he mounts the host's disk (`mount /dev/sda1 /mnt`) and takes over the machine.
    4. Similar danger: adding powerful capabilities like `--cap-add=SYS_ADMIN`.

!!! warning "Why it works"

    Privileged mode **switches off** the container's main safety barriers.

!!! success "Fix"


    - **Avoid `--privileged`**. Grant only the exact capability or device needed.
    - Drop everything first: `--cap-drop=ALL`, then add back only what's necessary.
    - Run as a **non-root user** (`USER appuser` in the Dockerfile) and add `--security-opt=no-new-privileges`.
    - Keep default seccomp/AppArmor protection on.

!!! info "In Compose"


    ```yaml
    services:
      web:
        user: "1000:1000"
        cap_drop: [ALL]
        security_opt: ["no-new-privileges:true"]
        # privileged: true   <-- avoid this
    ```

---

## 8. Sensitive Data Leak via Docker Images

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/798.html" target="_blank" rel="noopener noreferrer">CWE-798</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/312.html" target="_blank" rel="noopener noreferrer">CWE-312</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1552/001/" target="_blank" rel="noopener noreferrer" title="Credentials In Files">ATT&amp;CK T1552.001</a></p>

!!! tip "Think of it like"

    Mailing a **sealed box that you forgot to empty first**. It still contains your bank passbook, and anyone who receives it can open it.

!!! example "Scenario"


    1. A Dockerfile has `COPY .env /app/.env` or `ENV DB_PASSWORD=Pass@123`.
    2. The image is pushed to Docker Hub (public by mistake) or shared with a partner.
    3. A stranger runs `docker pull`, then `docker history` or opens the layers, and finds the password and API keys.
    4. Even if you delete the secret in a later step (`RUN rm .env`), **it stays in the earlier layer** of the image.

!!! warning "Why it works"

    An image is built from **layers**, and each layer keeps whatever was added. Environment variables and files are visible to anyone with the image.

!!! success "Fix"


    - Never put secrets in the Dockerfile, `ENV`, `ARG` or copied files. Use **`.dockerignore`** to exclude `.env`, `.git`, keys.
    - Use **BuildKit secrets** at build time (`RUN --mount=type=secret`) and **runtime secrets** (Docker/Compose secrets, Vault, cloud secret manager).
    - Scan images for secrets (Trivy, TruffleHog).
    - If a secret was leaked: **rotate it immediately**, because deleting the image isn't enough.

!!! info "In Compose"


    ```yaml
    services:
      web:
        secrets: [db_password]
    secrets:
      db_password:
        file: ./db_password.txt   # keep this file out of Git
    ```

---

## 9. Unsegregated Container Network

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/668.html" target="_blank" rel="noopener noreferrer">CWE-668</a></p>

!!! tip "Think of it like"

    All the building's tenants **share one big open hall with no walls or locked doors**. A thief who enters through the cafe can walk straight to the bank vault.

!!! example "Scenario"


    1. Web, database, admin tools and a random test container are all on the same default network.
    2. The web container is hacked through a bug.
    3. From inside, the attacker simply connects to `db:5432` and `redis:6379` (which need no password because "they're internal") and steals data.
    4. Also, the database port was published to the whole internet with `-p 5432:5432`.

!!! warning "Why it works"

    By default, containers on the same network can talk to each other freely.

!!! success "Fix"


    - Create **separate networks** for separate roles: e.g., `frontend` (web + proxy) and `backend` (web + database). The database is **not** on the frontend network.
    - Mark private networks `internal: true` so they have no internet access.
    - **Publish only the ports that truly need outside access.** Bind internal ones to localhost (`127.0.0.1:5432:5432`) or don't publish them.
    - Add passwords and TLS between services anyway.

!!! info "In Compose"


    ```yaml
    services:
      web:
        networks: [frontend, backend]
      db:
        networks: [backend]        # not reachable from frontend
    networks:
      frontend: {}
      backend:
        internal: true
    ```

---

## 10. Unverified Container Images

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/494.html" target="_blank" rel="noopener noreferrer">CWE-494</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/829.html" target="_blank" rel="noopener noreferrer">CWE-829</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1204/003/" target="_blank" rel="noopener noreferrer" title="Malicious Image">ATT&amp;CK T1204.003</a></p>

!!! tip "Think of it like"

    Eating **food from an unlabeled packet a stranger gave you** because it "looked like a famous brand." You can't be sure it's safe.

!!! example "Scenario"


    1. Kiran searches Docker Hub for "nginx fast" and pulls a popular-looking image from a random user.
    2. It works like nginx, but includes a hidden **crypto-miner** and a backdoor that sends data out.
    3. Or, an attacker publishes `ngnix` (a typo of nginx) hoping people mistype it (typosquatting).
    4. Another risk: using `image: myapp:latest`, where `latest` can change anytime to something different.

!!! warning "Why it works"

    Anyone can upload images, and names and tags don't prove who made them or whether they're safe.

!!! success "Fix"


    - Use **Official Images** or **Verified Publisher** images, and check the source, Dockerfile and update history.
    - **Pin by digest** (`image: nginx@sha256:abc...`) or a specific version, not `latest`, so it can't silently change.
    - Turn on **Docker Content Trust / image signing** (e.g., Cosign) and **scan** images (Trivy, Grype) before use.
    - Build your own images from trusted base images and keep them in your private registry.

!!! info "In Compose"

    `image: nginx:1.27.2` or `image: nginx@sha256:...`, instead of `image: someuser/nginx-fast:latest`.

---

## A safer example (many fixes in one file)

```yaml
services:
  web:
    image: myregistry.company.com/web:1.4.2   # trusted registry, pinned version (5, 10)
    user: "1000:1000"                          # not root (7)
    read_only: true                            # (4)
    cap_drop: [ALL]                            # (7)
    security_opt: ["no-new-privileges:true"]   # (7)
    deploy:
      resources:
        limits: { cpus: "1.0", memory: 512M }  # (1)
    networks: [frontend, backend]
    ports: ["443:8443"]                        # only needed port (9)
    secrets: [db_password]                     # (8)
  db:
    image: postgres:16.4
    networks: [backend]                        # hidden from frontend (9)
    volumes:
      - dbdata:/var/lib/postgresql/data        # named volume, not host root (4)
networks:
  frontend: {}
  backend: { internal: true }
volumes:
  dbdata: {}
secrets:
  db_password:
    file: ./db_password.txt
```

---

## Quick summary

| Family | Items | One-line defence |
|---|---|---|
| Too much power | 7 Privileged containers, 2 Exposed docker.sock | Drop capabilities, run as non-root, never mount the socket |
| Touching the host | 4 Volumes/host filesystem, 3 Host update | Mount little and read-only; patch the host |
| Overuse | 1 Resource limitation | Set CPU, memory and process limits |
| What's inside the image | 6 Minimal base image, 8 Sensitive data in images | Small images; no secrets in layers |
| Where images come from | 5 Insecure registries, 10 Unverified images | TLS and login on registries; official, pinned, signed, scanned images |
| Open doors between containers | 9 Unsegregated network | Separate networks; publish only needed ports |

!!! success "Memory trick"

    *"Small image, small power, small door."* Use small images, give containers small privileges (non-root, no extra capabilities), and open small doors (few ports, few mounts, separated networks).
