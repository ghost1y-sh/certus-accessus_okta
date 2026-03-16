# certus-accessus_okta

> AI-powered Okta access certification. Audit who has access to what, flag anomalies using Claude, and produce a remediation-ready CSV for your IT team — all without making a single change to your Okta organization.

>NOTE: REQUIRES TIER 3 OR ABOVE CLAUDE API ACCOUNT, OR YOU WILL HIT RATE LIMITS.

credit: github.com/ghost1y-sh && dt_ta

```
  ██████╗███████╗██████╗ ████████╗██╗   ██╗███████╗
 ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝
 ██║     █████╗  ██████╔╝   ██║   ██║   ██║███████╗
 ██║     ██╔══╝  ██╔══██╗   ██║   ██║   ██║╚════██║
 ╚██████╗███████╗██║  ██║   ██║   ╚██████╔╝███████║
  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
 █████╗  ██████╗ ██████╗███████╗███████╗███████╗██╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝
███████║██║     ██║     █████╗  ███████╗███████╗██║   ██║███████╗
██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║██║   ██║╚════██║
██║  ██║╚██████╗╚██████╗███████╗███████║███████║╚██████╔╝███████║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝
```

---

## ⚠️ READ ONLY

**certus-accessus_okta makes no changes to your Okta organization.**

Every API call to Okta is a GET request. No users are modified, no access is revoked, no policies are changed. All remediation is performed manually by your IT team based on the tool's output. This is by design — SOC 2 and ISO 27001 require human sign-off on access removals.

---

## What it does

certus-accessus_okta answers the question every security team needs to answer periodically: **does the right person have the right access, for the right reason, for the right amount of time?**

It pulls your full Okta application access inventory, enriches each assignment with department, title, access duration, and last-used date, then sends each application's user list to Claude for AI-powered analysis. Claude returns a verdict for every user — **Keep**, **Review**, or **Revoke** — with a one-sentence reasoning. The results are output to terminal, JSON, and a CSV file structured for manager review and SOC 2 evidence.

---

## Features

- **Full access inventory** — every active app, every assigned user, how long they've had access, and when they last used it
- **AI-powered verdicts** — Claude analyzes department/title fit, usage patterns, and access duration to flag anomalies
- **Department-aware analysis** — Claude sees the full distribution of users per app before analyzing individuals, enabling pattern-based detection
- **Three output formats** — terminal (color-coded, actionable), JSON (audit evidence), CSV (manager review workflow)
- **`--anonymize` flag** — replaces emails with anonymous IDs in Claude prompts so Anthropic's API never receives email addresses
- **`--save-okta` / `--from-file`** — save Okta collection output to a file and reuse it for subsequent analysis runs without hitting the Okta API again
- **`--debug` flag** — writes raw Claude API responses to `claude_debug.log` for troubleshooting
- **Graceful degradation** — runs in data-only mode without an Anthropic API key, producing a raw access inventory
- **Rate limit aware** — handles Okta's per-endpoint rate limits with automatic backoff, safe for large orgs
- **Streaming API calls** — uses the Anthropic streaming API to prevent connection timeouts on long-running analysis
- **Enterprise-safe** — read-only, PII redaction flag, explicit data isolation between Okta and Claude

---

## How it works — full data flow

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR MACHINE                              │
│                                                             │
│  ┌─────────────┐     GET only      ┌─────────────────────┐ │
│  │ connector.py│ ◄────────────────►│   Okta REST API     │ │
│  └──────┬──────┘                   └─────────────────────┘ │
│         │ raw API responses                                  │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ collector.py│  builds structured Python dicts in memory  │
│  │             │  optionally saved to okta_data.json        │
│  └──────┬──────┘                                            │
│         │ app/user dicts (no tokens, no Okta IDs sent out) │
│         ▼                                                   │
│  ┌─────────────┐   text prompt     ┌─────────────────────┐ │
│  │ analyzer.py │ ────────────────► │  Anthropic API      │ │
│  │  (streaming)│ ◄──────────────── │  (Claude)           │ │
│  └──────┬──────┘   JSON verdicts   └─────────────────────┘ │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                            │
│  │ reporter.py │ ──► terminal + report.json + report.csv   │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

**Claude never communicates with Okta.** Claude never receives raw API responses, Okta session tokens, internal object IDs, or anything not explicitly included in the structured text prompt built by `analyzer.py`.

**Okta never communicates with Claude.** The Okta API token stays on your machine. It is never sent to Anthropic's servers.

**What Claude receives:** a structured text prompt containing app name, sign-on type, department distribution, and per-user lines with login or anonymous ID, department, title, account status, days since assignment, and last access date.

**What goes to Anthropic's servers:** only the text prompt described above. Use `--anonymize` to ensure no email addresses are included. See the Security & Privacy section below.

---

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/ghost1y-sh/certus-accessus_okta.git
cd certus-accessus_okta
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Configuration

Credentials are loaded from a `.env` file. Never pass tokens as command-line arguments — they would be visible in shell history and process lists.

```
OKTA_DOMAIN=yourorg.okta.com
OKTA_TOKEN=your-okta-api-token
ANTHROPIC_API_KEY=your-anthropic-api-key
```

**Okta token** — minimum required role is **Read-Only Administrator**. Generate at: Okta Admin Console → Security → API → Tokens → Create Token. Revoke after the audit is complete.

**Anthropic API key** — available at console.anthropic.com. If not set, the tool runs in data-only mode — full access inventory without AI verdicts. For enterprise use, use your organization's API key under your enterprise agreement.

---

## Usage

### Verify connection before scanning

```bash
python3 main.py --verify
```

Confirms the Okta token is valid and prints the actual admin role level. Run this first when setting up for a new org.

### Recommended workflow for large orgs

Large orgs (500+ users, 100+ apps) benefit from separating the Okta collection step from the Claude analysis step. This lets you fix analysis issues without re-pulling from Okta.

**Step 1 — Collect Okta data and save to file:**
```bash
python3 main.py --save-okta okta_data.json --dry-run
```

Pulls all users, apps, assignments, and access logs from Okta. Saves to `okta_data.json`. Skips Claude analysis. Fast, no API cost.

**Step 2 — Run analysis from saved file:**
```bash
python3 main.py --from-file okta_data.json --anonymize --output report_$(date +%Y%m%d)
```

Skips Okta entirely. Loads from file, runs Claude analysis, produces report. Repeat as needed without hitting Okta again.

### Full run with output saved (small orgs)

```bash
python3 main.py --output report_$(date +%Y%m%d)
```

Produces `report_YYYYMMDD.json` and `report_YYYYMMDD.csv`.

### Full run with email anonymization (recommended for enterprise)

```bash
python3 main.py --anonymize --output report_$(date +%Y%m%d)
```

Replaces all email addresses with anonymous IDs before sending to Claude. Verdicts are mapped back to real emails in the output.

### Skip system log queries (faster, less accurate)

```bash
python3 main.py --no-access-log --output report
```

Skips the per-app system log queries that determine last app access. Faster for large orgs but `last_app_access` will show as Unknown. Claude will note this in its reasoning.

### Debug Claude API responses

```bash
python3 main.py --from-file okta_data.json --debug --output report
```

Writes raw Claude API response details to `claude_debug.log` — stop_reason, content blocks, token usage, and response preview. Use when troubleshooting empty or malformed responses.

### Analyze a single app

```bash
python3 main.py --from-file okta_data.json --app "GitHub" --output github_report
```

Filters to apps whose name contains the string. Case-insensitive. Useful for targeted investigation.

### Filter to one department

```bash
python3 main.py --from-file okta_data.json --dept "Finance" --output finance_report
```

Shows only Finance users across all apps. Useful for department-level access reviews.

### Show only Revoke verdicts

```bash
python3 main.py --from-file okta_data.json --failing-only --output report
```

Suppresses Keep and Review in terminal output.

### Show all verdicts including Keep

```bash
python3 main.py --from-file okta_data.json --show-all --output report
```

By default Keep verdicts are hidden — on a large org most users will be Keep and showing them all makes the report unreadable.

### Redact emails in output files

```bash
python3 main.py --from-file okta_data.json --redact --output report
```

Partially masks email addresses in terminal output and output files.

```
alice.admin@corp.com → ali*****@corp.com
```

### All flags

| Flag | Description |
|---|---|
| `--domain` | Okta domain. Overrides `.env` if set. |
| `--output` | Base filename for output (produces `.json` and `.csv`) |
| `--save-okta` | Save Okta collection output to a JSON file for reuse |
| `--from-file` | Skip Okta collection and load from a saved file |
| `--debug` | Write raw Claude API responses to `claude_debug.log` |
| `--redact` | Partially redact email addresses in output files |
| `--anonymize` | Replace emails with anonymous IDs in Claude prompts |
| `--show-all` | Show Keep verdicts in terminal (hidden by default) |
| `--failing-only` | Show only Revoke verdicts in terminal |
| `--no-access-log` | Skip system log queries — faster but less accurate |
| `--app` | Filter to apps matching this string (case-insensitive) |
| `--dept` | Filter to users in this department (case-insensitive) |
| `--dry-run` | Collect data, skip Claude analysis |
| `--verify` | Test connection and print token permission level |

---

## AI analysis — how Claude makes decisions

### What Claude receives per app

For each application, Claude receives a structured prompt containing:

- Application name and sign-on type
- Department distribution across all assigned users (e.g., "Engineering: 45, Finance: 1")
- Per-user lines with: login or anonymous ID, department, title, account status, days since assignment, last app access date, and Okta last login date

The department distribution is critical — it gives Claude pattern context before analyzing individuals. A Finance user in GitHub Enterprise stands out immediately when Claude sees that 47 of 48 other users are in Engineering.

### Verdict logic

**Keep** — access is clearly appropriate for the user's role, regardless of usage frequency. Usage is not penalized if the role fit is strong.

**Review** — access is ambiguous and requires human judgment. Used when the department could be unusual but has a plausible business reason, the user's title is vague, it is a service or bot account, or the user is in the wrong department but has been actively using the app.

**Revoke** — used only when **both** of the following are true:
1. The access appears inappropriate for the user's department and title with no plausible cross-functional justification
2. AND usage data confirms the access is unused or stale: never accessed, not accessed in 180+ days, or the user's Okta account is suspended or deprovisioned

**Claude never Revokes based on usage alone.** Role mismatch is always required as the primary signal.

**Claude errs toward Review rather than Revoke when uncertain.** A false Revoke that removes legitimate access is disruptive and erodes trust. Human review is the safety net.

### Streaming API

Claude API calls use streaming to keep connections alive during long-running analysis. Without streaming, network connections can drop silently on responses that take more than a few seconds, producing empty responses. Streaming eliminates this by receiving tokens as they are generated rather than waiting for a complete response.

### Risk levels

- **High** — Revoke verdict, or any anomaly on a sensitive app (security tools, infrastructure, source code, finance systems, admin consoles)
- **Medium** — Review verdict on a moderately sensitive app, or Revoke on a low-sensitivity app
- **Low** — Review verdict on a low-sensitivity app

### Cost

certus-accessus_okta uses Claude Sonnet by default. For a typical enterprise org with 240 active apps:

| Org size | Apps | Estimated cost per run |
|---|---|---|
| Small (100 users) | ~50 apps | ~$0.60 |
| Medium (500 users) | ~120 apps | ~$1.44 |
| Large (1100 users) | ~240 apps | ~$2.88 |
| Enterprise (5000 users) | ~500 apps | ~$6.00 |

Prompt caching reduces cost further — the system prompt is cached after the first call and subsequent calls are charged at 10% of normal input token cost.

**Note:** Large orgs with many apps assigned to hundreds of users will cost more due to the volume of Claude calls required. Using `--save-okta` and `--from-file` ensures you only pay for collection once and can re-run analysis as needed.

---

## Output formats

### Terminal

Color-coded verdict display, sorted by severity. Apps with Revoke verdicts appear first. Keep verdicts are hidden by default.

```
GitHub Enterprise — 48 user(s) assigned
  3 revoke  2 review

  ✗ Revoke  alice@corp.com  (Finance / AP Specialist)
           [High risk]  Clear dept mismatch, never accessed in 425 days
           Assigned: 425d ago  |  Last app access: Not in last 180 days

  ⚠ Review  carol@corp.com  (HR / HR Business Partner)
           [Medium risk]  Unusual access pattern — verify with manager
           Assigned: 62d ago  |  Last app access: 2026-01-14

  ✓ Keep    bob@corp.com  (Engineering / Senior Engineer)
           [Low risk]  Appropriate access, active user
           Assigned: 180d ago  |  Last app access: 2026-03-12
```

### JSON

Full audit report including all metadata, all apps, all users, and all verdicts. Suitable for integration with ticketing systems, SIEM, or audit evidence archives.

### CSV

Manager review workflow document. Columns:

| Column | Description |
|---|---|
| `app_name` | Application name |
| `app_sign_on` | Sign-on mode (SAML, OIDC, etc.) |
| `user_login` | User email / Okta login |
| `user_name` | Display name |
| `department` | Department from Okta directory |
| `title` | Job title from Okta directory |
| `status` | Okta account status |
| `assigned_date` | Date access was provisioned |
| `days_assigned` | Days since provisioned |
| `last_app_access` | Last time user accessed this specific app |
| `okta_last_login` | Last Okta login (any app) |
| `ai_verdict` | Keep / Review / Revoke |
| `ai_risk` | Low / Medium / High |
| `ai_reasoning` | One-sentence explanation |
| `reviewed_by` | **Blank — IT team fills in** |
| `action_taken` | **Blank — IT team fills in** |
| `review_date` | **Blank — IT team fills in** |

The last three columns are intentionally blank. The IT director filters by `ai_verdict = Revoke`, works through each row, records who reviewed it and what was done. The completed CSV is SOC 2 access review evidence.

---

## Remediation workflow

certus-accessus_okta produces findings. Remediation is entirely manual and owned by your IT team.

```
Tool run
    ↓
CSV exported
    ↓
IT director filters by ai_verdict = Revoke
    ↓
Each Revoke reviewed — verify with department head if needed
    ↓
Approved revocations executed manually in Okta Admin Console
    ↓
reviewed_by + action_taken + review_date filled in CSV
    ↓
Completed CSV stored as access review audit evidence
```

This workflow satisfies the periodic access review requirement under SOC 2 (CC6.3), ISO 27001 (A.9.2.5), and NIST SP 800-53 (AC-2).

---

## Security & Privacy

**Credential handling**
- Okta API token and Anthropic API key are loaded exclusively from `.env` — never from CLI arguments
- Tokens are never written to disk beyond `.env`, never logged to stdout, never included in JSON or CSV output
- `.env` is listed in `.gitignore` and must never be committed

**Token scoping**
- Okta: Read-Only Administrator is the minimum required role
- All Okta calls are GET requests — no write operations under any circumstances
- Recommended: create a dedicated `certus-accessus-audit` API token and revoke it after the audit

**Data isolation**
- Claude never communicates with Okta — see the data flow diagram above
- Okta API responses are never forwarded to Anthropic
- What Anthropic receives: structured text only — app names, user logins or anonymous IDs, departments, titles, and access dates
- Okta internal IDs, session tokens, and raw API responses never leave your machine

**Minimizing PII exposure to Anthropic**
- By default, user email addresses are included in Claude prompts to make verdicts traceable
- Use `--anonymize` to replace all emails with anonymous IDs (user_001, user_002...) before sending to the Claude API
- Verdicts are mapped back to real emails in the final output — Anthropic's API never receives a single email address in this mode
- Recommended for orgs with strict DPA requirements or concerns about API request logging retention

**Saved Okta data (`--save-okta`)**
- The `okta_data.json` file produced by `--save-okta` contains user emails, departments, titles, and access data
- Treat this file with the same care as any other PII-containing export
- Add `*.json` to `.gitignore` to prevent accidental commits
- Delete after the audit is complete

**Enterprise data handling**
- For production use, ensure your Anthropic enterprise agreement covers the data being processed
- Under a Claude for Work / Business subscription, customer data is not used for model training
- Use `--anonymize` to eliminate email addresses from API calls entirely
- Use `--redact` to partially mask emails in output files before sharing externally

**Rate limiting**
- All Okta API calls respect `X-Rate-Limit-Remaining` headers with automatic backoff
- System log queries use a more conservative threshold due to Okta's stricter limits on that endpoint
- Safe to run against large orgs without impacting Okta service availability

---

## Companion tools

certus-accessus_okta is part of a suite of identity security tools:

- **[adscythe](https://github.com/ghost1y-sh/adscythe)** — Active Directory security audit: Kerberoasting, AS-REP roasting, stale accounts, privileged group exposure
- **[oktascythe](https://github.com/ghost1y-sh/oktascythe)** — Okta account-level security audit: MFA gaps, stale users, admin SPN exposure, password policy
- **[oktascythe_v2](https://github.com/ghost1y-sh/oktascythe_v2)** — Okta identity security posture scoring against NIST, CIS, and SOC 2 frameworks
- **certus-accessus_okta** — AI-powered Okta access certification and entitlement review

---

## Disclaimer

certus-accessus_okta is intended for authorized security assessments and access certification reviews of Okta organizations you own or have explicit written permission to audit. Unauthorized use against organizations you do not have permission to access may violate computer fraud laws. The author assumes no liability for misuse.

This tool produces recommendations, not decisions. All access revocation actions must be reviewed and approved by authorized personnel before being executed. The tool authors assume no liability for access decisions made based on AI-generated verdicts.