# Git Collaboration & Contribution Workflow

> **Strict Rule:** `main` is the protected production branch. **Direct pushes to `main` are strictly forbidden.** Every change requires an isolated feature branch, conventional commits, and a Pull Request reviewed and approved by repository owner **Vinit Surve**.

---

## 1. Branch Strategy & Naming Conventions

All development occurs on short-lived, task-focused feature branches created from the latest `main`:

```bash
# Branch Naming Standard:
<contributor>-<feature-name>

# Examples for Vinit (Browser Extension & Shared Architecture):
vinit-browser-extension-foundation
vinit-url-reputation-engine
vinit-navigation-interstitial
vinit-redirect-protection
vinit-community-reporting

# Examples for Shubham (WhatsApp Bot):
shubham-whatsapp-webhook
shubham-text-scam-classifier
shubham-bot-consent-flow
```

---

## 2. Standard Task Workflow (Step-by-Step)

### Step 1: Synchronize with Upstream Main
```bash
git status
git checkout main
git pull origin main
```

### Step 2: Create a Fresh Feature Branch
```bash
git checkout -b vinit-feature-name
```

### Step 3: Implement & Validate Locally
- Verify TypeScript types: `npm run typecheck`
- Run linting: `npm run lint`
- Run test suite: `npm run test`
- Inspect working tree diffs:
  ```bash
  git status
  git diff
  git diff --check   # Checks for trailing whitespace and merge markers
  ```

### Step 4: Verify Zero Leaked Secrets or Bloat
**Strict Pre-Commit Verification:**
- Ensure no `.env`, `.pem`, `.key`, or API credentials are staged.
- Ensure no `node_modules/`, `.next/`, or `dist/` directories are tracked.

### Step 5: Commit with Conventional Commits
```bash
git add <specific_files>
git commit -m "feat: implement k-anonymity threat prefix lookup in service worker"
```

Allowed commit types:
- `feat:` (New functional capability)
- `fix:` (Bug fix)
- `security:` (Security hardening, SSRF defense, CSP update)
- `docs:` (Documentation, architecture, threat model)
- `test:` (Unit, integration, or browser tests)
- `refactor:` (Code restructuring with no behavior change)

### Step 6: Push Feature Branch to Remote
```bash
git push -u origin vinit-feature-name
```
*Never force-push (`-f`) to shared branches.*

### Step 7: Open a Pull Request Targeting `main`
Provide a structured PR description:
```markdown
## Summary
Concise explanation of what this PR accomplishes.

## Changes
- Component A: Description of change
- Component B: Description of change

## Security Considerations
- Input validation implemented
- Minimal permission justification
- Memory safety and error handling

## Testing Performed
- [x] Legitimate domain pass-through tested
- [x] Known phishing domain block tested
- [x] Offline behavior verified

## Known Limitations
- Description of any deferred edge-cases
```

### Step 8: Review & Merge Authority
- **Vinit Surve** is the repository owner and merge authority.
- Changes are merged only after automated tests pass and manual code review is complete.
- After merge:
  ```bash
  git checkout main
  git pull origin main
  git branch -D vinit-feature-name
  ```
