# Kubernetes Vulnerabilities: Explained Simply (Part 9)

Every item has: **Think of it like** → **Scenario** (step by step) → **Why it works** → **Fix** (and why it works).

## Words you will see a lot

- **Kubernetes (K8s)**: a **manager for containers**. You say "I want 5 copies of my web app running," and Kubernetes starts them, restarts them when they crash and spreads them over many computers.
- **Cluster**: the whole group of computers managed together, like **one big apartment complex**.
- **Node**: one computer (server) in the cluster, like **one building**.
- **Pod**: the smallest unit, **one flat** holding one or more containers.
- **Namespace**: a **section of the complex** (team-a, team-b, production, test) to keep things separate.
- **API server**: the **front office** of the cluster. Every command goes through it. Whoever controls it controls the cluster.
- **kubectl**: the command-line **remote control** used to talk to the API server.
- **kubelet**: the **caretaker on each node** that actually starts and watches the pods.
- **etcd**: the cluster's **main record book** (database). It holds everything, including secrets.
- **RBAC (Role-Based Access Control)**: the **permission system**: which user or program can do what. A **Role** lists the allowed actions, and a **RoleBinding** gives that Role to someone.
- **Service account**: an **identity for a program** (a pod) so it can talk to the API server.
- **Secret**: where Kubernetes stores passwords, tokens and keys.
- **NetworkPolicy**: the **walls and doors between pods**. It says who may talk to whom.
- **Admission controller**: the **gatekeeper** that checks every new pod or object **before** the cluster accepts it.
- **Helm chart**: a **ready-made installation package** for an app on Kubernetes.

!!! info "Golden rule for Kubernetes"

    *By default, Kubernetes is built to be **easy to use and flexible**, not locked down. Most real attacks come from **settings left open**: too many permissions, no walls between pods, secrets lying around, and nobody watching.*


**Tools testers/defenders use (so you know the names):** `kubectl`, **kube-bench** (checks the CIS security benchmark), **kube-hunter** (looks for weaknesses), **Kubescape** and **Trivy** (scan configs and images), **Falco** (detects suspicious behaviour while running).

---

## 1. Broken Authentication Mechanisms

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/287.html" target="_blank" rel="noopener noreferrer">CWE-287</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1078/" target="_blank" rel="noopener noreferrer" title="Valid Accounts">ATT&amp;CK T1078</a> <span class="vtag owasp">OWASP K8s K06</span></p>

!!! tip "Think of it like"

    A building where the **front office accepts anyone who says "Hi, I'm staff,"** or where one **master key was copied long ago and never changed**.

!!! example "Scenario"


    1. A cluster's API server (or kubelet) has **anonymous access enabled**, so requests with no login are treated as the user `system:anonymous`.
    2. A stranger runs `curl https://<cluster>:6443/api/v1/namespaces/default/pods` and gets a list of all pods, and in some setups can even run commands.
    3. Another case: an admin's `kubeconfig` file (the file with the cluster address and credentials) is accidentally pushed to GitHub. It contains a **long-lived admin certificate that never expires and can't easily be revoked**.
    4. Anyone who finds it is the cluster admin.

!!! warning "Why it works"

    Weak or missing login checks, and credentials that live too long and are shared too widely.

!!! success "Fix"


    - **Disable anonymous access** (`--anonymous-auth=false` on the API server and kubelet), and don't expose the kubelet's insecure read-only port.
    - Use **SSO with MFA** (OIDC, such as Azure AD/Okta/Google) for humans instead of shared certificates or static tokens.
    - Use **short-lived tokens** (bound service account tokens) and rotate credentials. Never commit `kubeconfig` files to Git, and scan repos for them.
    - On cloud services (EKS/AKS/GKE), use the cloud's IAM integration.

---

## 2. Inadequate Logging and Monitoring

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/778.html" target="_blank" rel="noopener noreferrer">CWE-778</a> <span class="vtag owasp">OWASP K8s K05</span></p>

!!! tip "Think of it like"

    An apartment complex with **no CCTV and no visitor register**. A thief walks through the flats for weeks, and nobody knows until the residents complain.

!!! example "Scenario"


    1. An attacker breaks into one pod through a web bug.
    2. He runs `kubectl exec` into other pods, reads Secrets, and starts a crypto-miner.
    3. **Audit logging is not turned on**, and nobody watches the pods' behaviour.
    4. The first sign is a **huge cloud bill** a month later, and the team can't tell what was stolen or how he got in.

!!! warning "Why it works"

    Attackers can only be caught if something **records** actions and something **watches** for odd behaviour. Many self-managed clusters don't enable audit logs by default.

!!! success "Fix"


    - Turn on **Kubernetes audit logging** with a sensible policy: who did what, when, from where. Log Secret access at `Metadata` level, so the logs don't store the secret values themselves.
    - Send logs from the API server, nodes and pods to a **central place (SIEM)** the attacker can't reach, and keep them for a long time.
    - Use **runtime detection** (Falco): alert when a shell starts inside a pod, a sensitive file is read, or a pod makes odd network connections.
    - Set **alerts** for: failed logins, `exec` into pods, new ClusterRoleBindings, privileged pods.

    *(This is the SOC analyst's job area.)*

---

## 3. Insecure Workload Configuration

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/250.html" target="_blank" rel="noopener noreferrer">CWE-250</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1611/" target="_blank" rel="noopener noreferrer" title="Escape to Host">ATT&amp;CK T1611</a> <span class="vtag owasp">OWASP K8s K01</span></p>

!!! tip "Think of it like"

    Giving each tenant **master keys, permission to knock down walls, and no electricity limit**, then hoping they are all careful.

!!! example "Scenario"


    1. A developer writes a pod spec with `privileged: true`, runs as **root**, mounts the node's folder with `hostPath: /`, and sets **no resource limits**.
    2. A bug in the app lets an attacker get a shell inside this pod.
    3. Because the pod is privileged and has the node's disk mounted, the attacker **steps out onto the node itself**, reads the kubelet credentials and Secrets of other pods on that node, and moves further.
    4. Even without those, no resource limits means a crypto-miner can eat the node's CPU and starve other apps.

!!! warning "Why it works"

    Kubernetes will run whatever you tell it to, including **dangerous settings**: privileged mode, root user, host access, writable filesystems.

!!! success "Fix"

    Set a **secure `securityContext`** on every pod:

    ```yaml
    spec:
      automountServiceAccountToken: false      # unless the pod needs the API
      securityContext:
        runAsNonRoot: true
        seccompProfile: { type: RuntimeDefault }
      containers:
      - name: app
        image: myregistry/app:1.4.2            # pinned version, not :latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: { drop: ["ALL"] }
        resources:
          requests: { cpu: "100m", memory: "128Mi" }
          limits:   { cpu: "500m", memory: "256Mi" }
    ```

    - Avoid `privileged`, `hostPath`, `hostNetwork`, `hostPID`.
    - Enforce the built-in **Pod Security Standards** (`restricted` level) on namespaces so unsafe pods are rejected (see Item 4).

---

## 4. Lack of Centralized Policy Enforcement

<p class="vuln-tags"><span class="vtag owasp">OWASP K8s K04</span></p>

!!! tip "Think of it like"

    A big company where **every manager can hire anyone, give any access and buy anything** with no company-wide rules or approval desk. One careless manager breaks safety for everyone.

!!! example "Scenario"


    1. The company has 30 developers and 10 teams deploying to the same cluster.
    2. There is **no common rule** checking new deployments. Team A is careful. Team B copies a YAML from the internet with `privileged: true` and an image from a random Docker Hub user.
    3. Nothing stops it, and the unsafe pod runs in **production**.
    4. Security reviews catch some problems only months later, and only by luck.

!!! warning "Why it works"

    Individual rules and "please remember" documents don't scale. Without automatic enforcement, **the weakest team sets the security level** for the whole cluster.

!!! success "Fix"

    Add an **admission control layer** that automatically **blocks** or **fixes** bad configurations before they run:

    - **Pod Security Admission** (built into Kubernetes): enforce `baseline`/`restricted` per namespace.
    - **Policy engines**: **OPA Gatekeeper** or **Kyverno** (or the built-in ValidatingAdmissionPolicy) with rules like "no privileged pods," "images only from our registry," "no `latest` tag," "resource limits required," "must run as non-root."
    - Run the same policy checks in **CI/CD** so developers see problems early.
    - Start in **audit/warn mode**, then switch to **enforce**.

---

## 5. Misconfigured Cluster Components

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/16.html" target="_blank" rel="noopener noreferrer">CWE-16</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1190/" target="_blank" rel="noopener noreferrer" title="Exploit Public-Facing Application">ATT&amp;CK T1190</a> <span class="vtag owasp">OWASP K8s K09</span></p>

!!! tip "Think of it like"

    The building's **main control room has its door propped open, the record book lies on the reception desk, and the CCTV monitor shows the passwords to anyone who passes by.**

!!! example "Scenario"


    1. **The Kubernetes Dashboard** (a web admin panel) is exposed to the internet **without login**. This kind of exposed console has been publicly reported in real incidents, where attackers used it to start **crypto-mining pods** in a company's cluster.
    2. In another case, **etcd** (port 2379) is reachable without TLS or authentication. The attacker connects and reads **the entire cluster's data, including every Secret**.
    3. The **kubelet API** (port 10250) allows anonymous requests, so the attacker runs commands inside pods.

!!! warning "Why it works"

    Control-plane parts (API server, etcd, kubelet, dashboard) are extremely powerful, and one **open port or missing authentication** hands over the cluster.

!!! success "Fix"


    - Keep the **API server private** (private endpoint, VPN, or restricted IP ranges), and use **firewalls/security groups** to protect etcd, kubelet and node ports.
    - Require **TLS and client certificates** for etcd, and **enable encryption at rest** for Secrets.
    - **Don't expose the Dashboard** (or require strong auth and read-only access) and disable what you don't use.
    - Follow the **CIS Kubernetes Benchmark** and check it regularly with **kube-bench**.
    - On managed services (EKS/AKS/GKE) the provider handles much of this, but **you still own your settings**.

---

## 6. Missing Network Segmentation Controls

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/668.html" target="_blank" rel="noopener noreferrer">CWE-668</a> <span class="vtag owasp">OWASP K8s K07</span></p>

!!! tip "Think of it like"

    All tenants **share one big open hall** with no walls, so a thief who enters through the cafe can walk straight into the bank vault.

!!! example "Scenario"


    1. Pods in a cluster are in different namespaces: `frontend`, `payments`, `database`.
    2. By default, **every pod can talk to every other pod**, in any namespace.
    3. An attacker hacks the public `frontend` pod through a bug.
    4. From there, he connects straight to the `database` pod, which trusts any connection coming from inside the cluster, and dumps the data. He also calls the cloud **metadata address** (`169.254.169.254`) to try to steal the node's cloud credentials.

!!! warning "Why it works"

    Kubernetes networking is **flat and open by default**. Namespaces are labels for organizing, **not firewalls**.

!!! success "Fix"

    Use **NetworkPolicies** with **"default deny,"** then allow only the needed paths (the network plugin must support them, e.g., Calico or Cilium):

    ```yaml
    # 1) Deny all traffic to and from pods in this namespace
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata: { name: default-deny-all, namespace: payments }
    spec:
      podSelector: {}
      policyTypes: ["Ingress", "Egress"]
    ---
    # 2) Then allow only what's needed (frontend -> api on 8080)
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata: { name: allow-frontend-to-api, namespace: payments }
    spec:
      podSelector: { matchLabels: { app: api } }
      ingress:
      - from:
        - namespaceSelector: { matchLabels: { name: frontend } }
        ports: [{ port: 8080 }]
    ```

    - Restrict **egress** too (block pods from reaching the metadata endpoint and the internet unless needed).
    - Optionally use a **service mesh** for encrypted pod-to-pod traffic (mTLS).

---

## 7. Overly Permissive RBAC Configuration

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/269.html" target="_blank" rel="noopener noreferrer">CWE-269</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/250.html" target="_blank" rel="noopener noreferrer">CWE-250</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1078/" target="_blank" rel="noopener noreferrer" title="Valid Accounts">ATT&amp;CK T1078</a> <span class="vtag owasp">OWASP K8s K03</span></p>

!!! tip "Think of it like"

    Giving a **trainee the master key to every room "just for testing,"** and then forgetting about it. When his bag is stolen, the thief has the master key.

!!! example "Scenario"


    1. To fix a permission error quickly, a developer is given **`cluster-admin`** (full power over everything).
    2. A CI/CD service account is also given `cluster-admin`, and its token is stored in the build server.
    3. An attacker breaks into the build server and **takes the token**. Now he can read every Secret in every namespace, start pods anywhere and delete workloads.
    4. Smaller examples that are also dangerous: roles with wildcards (`resources: ["*"], verbs: ["*"]`), permission to **create pods** (can be used to run a privileged pod), to **read Secrets**, or to `exec` into pods.

!!! warning "Why it works"

    RBAC is only as safe as the permissions you hand out, and **a single over-powered account is the shortest path to full takeover**.

!!! success "Fix"


    - **Least privilege**: give each person/service account only the exact verbs and resources they need, in the **namespace** they need (use `Role`/`RoleBinding` instead of `ClusterRole`/`ClusterRoleBinding` where possible).
    - **Avoid wildcards** (`*`) and avoid `cluster-admin` except for a few break-glass admins.
    - **Don't use the `default` service account** for apps, and turn off automatic token mounting if the pod doesn't call the API (`automountServiceAccountToken: false`).
    - Regularly **review** with `kubectl auth can-i --list`, and tools like KubiScan/rbac-tool, and remove unused bindings.

    ```yaml
    # Example: a Role that can only read pods in one namespace
    kind: Role
    apiVersion: rbac.authorization.k8s.io/v1
    metadata: { namespace: team-a, name: pod-reader }
    rules:
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list"]
    ```

---

## 8. Secrets Management Failure

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/312.html" target="_blank" rel="noopener noreferrer">CWE-312</a> <a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/798.html" target="_blank" rel="noopener noreferrer">CWE-798</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1552/007/" target="_blank" rel="noopener noreferrer" title="Container API">ATT&amp;CK T1552.007</a> <span class="vtag owasp">OWASP K8s K08</span></p>

!!! tip "Think of it like"

    Writing all your **passwords on sticky notes**, putting them in a drawer that anyone in the office can open, and also taping a copy on the notice board (Git).

!!! example "Scenario"


    1. A developer writes the database password in a Kubernetes YAML file and **commits it to GitHub**.
    2. Kubernetes Secrets look "encrypted," but by default they're only **base64-encoded** (a way of writing text, not a lock). Anyone can run `echo cGFzczEyMw== | base64 -d` and read it.
    3. Secrets are also stored **unencrypted in etcd** by default, and many service accounts have permission to read all Secrets.
    4. The password is also passed as an **environment variable**, which shows up in logs, crash dumps and `kubectl describe`.

!!! warning "Why it works"

    Base64 is **not encryption**, and secrets get copied into many places: Git, images, env vars, logs and etcd backups.

!!! success "Fix"


    - **Never put secrets in Git or in images.** Use a secrets manager: **HashiCorp Vault**, **AWS Secrets Manager / Azure Key Vault / GCP Secret Manager** (with the External Secrets Operator or the CSI Secrets Store driver). For GitOps, use **Sealed Secrets** or **SOPS** to store only encrypted values.
    - **Enable encryption at rest for etcd** (EncryptionConfiguration, ideally with a **KMS** key).
    - Restrict who can `get/list` Secrets with RBAC.
    - Prefer **mounting secrets as files** over environment variables.
    - **Rotate** secrets regularly, and run secret scanners (gitleaks, TruffleHog) on repos.
    - If a secret leaked: **change it immediately**.

---

## 9. Supply Chain Vulnerabilities

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1195/" target="_blank" rel="noopener noreferrer" title="Supply Chain Compromise">ATT&amp;CK T1195</a> <span class="vtag owasp">OWASP K8s K02</span></p>

!!! tip "Think of it like"

    Cooking a restaurant meal with **ingredients from unknown suppliers and ready-made sauces you never checked.** If one is poisoned, every customer gets sick.

!!! example "Scenario"


    1. A team installs a popular-looking **Helm chart** from a random public repo, and it pulls an image from an unknown account.
    2. The image has a **hidden crypto-miner and a backdoor** that connects out to the attacker.
    3. In another case, an attacker breaks into the **CI/CD pipeline** (or a base image) and inserts malicious code into the company's own image. The cluster trusts it because it came from "our registry."
    4. Or the app is built on an **old base image** full of known vulnerabilities.

!!! warning "Why it works"

    The cluster will run **any image from anywhere** unless you stop it, and every dependency (base image, packages, Helm charts, CI tools) is something an attacker can tamper with.

!!! success "Fix"


    - **Scan images** for known vulnerabilities (Trivy, Grype) in CI and in the registry, and rebuild often from updated, **minimal base images**.
    - **Sign images** (Cosign/Sigstore) and have an admission policy (Kyverno `verifyImages`, Gatekeeper, Connaisseur) that **only allows signed images from your trusted registry**.
    - **Pin images by digest or exact version**, not `latest`.
    - **Review Helm charts and manifests** before installing; use charts from trusted maintainers.
    - Protect the **CI/CD pipeline** with least privilege and MFA, and generate an **SBOM** (list of everything in the image).

---

## 10. Vulnerable Kubernetes Components (Security Audit)

<p class="vuln-tags"><a class="vtag cwe" href="https://cwe.mitre.org/data/definitions/1395.html" target="_blank" rel="noopener noreferrer">CWE-1395</a> <a class="vtag atk" href="https://attack.mitre.org/techniques/T1068/" target="_blank" rel="noopener noreferrer" title="Exploitation for Privilege Escalation">ATT&amp;CK T1068</a> <span class="vtag owasp">OWASP K8s K10</span></p>

!!! tip "Think of it like"

    A building whose **fire alarm, lifts and main gate haven't been serviced in years**, and nobody has ever inspected them. Each one has a known fault listed in the newspaper.

!!! example "Scenario"


    1. A company runs Kubernetes **1.19**, which no longer gets security patches, plus an old container runtime (containerd/runc) and an old ingress controller.
    2. A new vulnerability is published with a **ready-made exploit** for these versions (for example, bugs that allow **container escape** or **taking over via the ingress controller**).
    3. An attacker who gets into any pod runs the public exploit and **escapes to the node**, then takes over the cluster.
    4. Nobody noticed because **no security audit** had been done since the cluster was built.

!!! warning "Why it works"

    Kubernetes and its add-ons (runtime, ingress, network plugin, dashboard) are software with bugs. Old versions have **publicly known** bugs, and attackers scan for them.

!!! success "Fix"


    - **Upgrade regularly**: stay on a **supported Kubernetes version** (the project supports only the latest few releases), and patch nodes, container runtime, ingress controller and CNI plugin.
    - Subscribe to **Kubernetes security announcements** and your cloud provider's advisories.
    - Run **regular security audits**: **kube-bench** (CIS benchmark), **kube-hunter** and **Kubescape** (find weaknesses), **Trivy Operator** (continuous scanning), and **penetration tests**.
    - Keep an **inventory** of everything installed (add-ons, operators, Helm releases) and remove what you don't use.

---

## Quick summary

| Family | Items | One-line defence |
|---|---|---|
| Who can get in | 1 Broken authentication, 7 Overly permissive RBAC | SSO + MFA, no anonymous access, least privilege |
| What pods can do | 3 Insecure workload configuration, 4 Lack of policy enforcement | Secure `securityContext` + admission policies (PSA, Kyverno, Gatekeeper) |
| Open doors and walls | 5 Misconfigured cluster components, 6 Missing network segmentation | Private API/etcd/kubelet; default-deny NetworkPolicies |
| Secrets and trust | 8 Secrets management failure, 9 Supply chain | Secrets manager + encryption at rest; scan and sign images |
| Staying healthy | 10 Vulnerable components, 2 Inadequate logging and monitoring | Upgrade often, audit regularly (kube-bench), log and alert (Falco, SIEM) |

!!! success "Memory trick"

    *"Lock the doors, limit the keys, build walls, hide the secrets, check the ingredients, and watch the cameras."*

    - Lock the doors → control plane and authentication (1, 5)
    - Limit the keys → RBAC and pod privileges (3, 7)
    - Build walls → NetworkPolicies and policy enforcement (4, 6)
    - Hide the secrets → secrets management (8)
    - Check the ingredients → supply chain and updates (9, 10)
    - Watch the cameras → logging and monitoring (2)
