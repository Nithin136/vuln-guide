# Vulnerabilities Explained Simply

A scenario-based security reference covering 100+ vulnerabilities across Web, API, LLM, Android and iOS, Docker, AWS, Desktop (C/C++), Front-end and Kubernetes. Every item has an everyday analogy, a step-by-step attack scenario, the root cause and a practical fix.

**Live site:** https://nithin136.github.io/vuln-guide/ (after you deploy, see below)
**PDF:** `docs/assets/Vulnerabilities_Explained_Simply.pdf`

> Educational use only. Test only systems you own or have written permission to test.

## Run it locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
mkdocs serve                     # open http://127.0.0.1:8000
```

## Deploy to GitHub Pages

```bash
git init
git add .
git commit -m "Phase 1: vulnerability guide site"
git branch -M main
git remote add origin https://github.com/Nithin136/vuln-guide.git
git push -u origin main
```

Then on GitHub: **Settings -> Pages -> Build and deployment -> Source: GitHub Actions**.
The workflow in `.github/workflows/deploy.yml` builds with `mkdocs build --strict` (broken links fail the build) and publishes the site.

If you use a different repo name, update `site_url`, `repo_url` and `repo_name` in `mkdocs.yml`.

## Structure

```
vuln-guide/
├── mkdocs.yml                  site config, theme, navigation
├── requirements.txt            pinned dependencies
├── docs/
│   ├── index.md                home page
│   ├── part-1-web.md ... part-9-kubernetes.md
│   ├── revision-sheet.md
│   └── assets/                 the PDF
└── .github/
    ├── workflows/deploy.yml    build and deploy
    └── dependabot.yml          weekly dependency and action updates
```

## Roadmap

- [x] **Phase 1:** searchable site from the 9 guide parts, deployed with GitHub Actions
- [ ] **Phase 2:** CWE / MITRE ATT&CK tags, quiz page
- [ ] **Phase 3:** in-browser attack simulators (SQLi login bypass, XSS encode vs raw, IDOR)
- [ ] **Phase 4:** local Docker lab (vulnerable and patched app) with Wazuh / Suricata detection rules

## Writing style

Each vulnerability uses the same four boxes: **Think of it like** (tip), **Scenario** (example), **Why it works** (warning), **Fix** (success). Keep that structure when you add new items.
