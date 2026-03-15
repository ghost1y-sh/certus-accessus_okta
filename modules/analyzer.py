#!/usr/bin/env python3
"""

modules/analyzer.py
Claude API integration for access certification analysis.

Sends per-app prompts to Claude and returns enriched app dicts
with AI verdicts attached to each user.

Verdict options:  Keep | Review | Revoke
Risk options:     Low  | Medium | High

If ANTHROPIC_API_KEY is not set, runs in data-only mode;
apps are returned unchanged with no verdicts attached.

With --anonymize, emails are replaced with anonymous IDs (user_001, user_002...)
before being sent to the Claude API. Verdicts are mapped back to real emails
in the output. Anthropic's API never receives email addresses in this mode.

"""

import os
import json
import time
import anthropic
from dotenv import load_dotenv

load_dotenv()

VALID_VERDICTS = {"Keep", "Review", "Revoke"}
VALID_RISKS    = {"Low", "Medium", "High"}

#Max users per Claude call; large apps are split into batches
USER_BATCH_SIZE = 75

#Seconds to wait between batches on large apps
#Tier 1 API accounts are limited to 8K output tokens/min
#75 users × ~50 tokens per verdict = ~3750 tokens per batch
#One batch every 30s keeps us safely under the limit
BATCH_SLEEP = 30

SYSTEM_PROMPT = """
You are a senior identity security analyst performing an access certification
review for an enterprise Okta organization. Your role is to evaluate whether
each user's application access is appropriate and flag risks for remediation.

## Your task
For each application you receive, analyze every assigned user and return a
verdict on whether their access should be kept, reviewed by a human, or revoked.

## Data you will receive per user
- Email / login (may be anonymized as user_001, user_002... for privacy)
- Department and job title (sourced from HR via Okta directory)
- How many days ago they were assigned access
- When they last authenticated to this specific application (or not in last 180 days)
- Their overall Okta last login (indicates if they are an active user)
- Account status (ACTIVE, STAGED, SUSPENDED, DEPROVISIONED)

## Verdict definitions

### Keep
Access is clearly appropriate. Use this when:
- The user's department and title align with the expected user base for this app
- The user has accessed the app recently (within 90 days)
- OR access is newly provisioned (within 30 days) and hasn't been used yet

### Review
Access is ambiguous and requires human judgment. Use this when:
- The department seems unusual but could be legitimate
  (e.g., an HR person in a developer tool; could be for hiring pipelines)
- The user hasn't accessed the app in 91-365 days
- The user's title is vague or doesn't clearly indicate their function
- It is a service account or bot account (non-human identity)
- The user is in the wrong department BUT has been actively using the app
  (active use suggests a business reason worth investigating before revoking)

### Revoke
Access should be removed. Use this when BOTH are true:
1. The access appears inappropriate for the user's department and title
   (no plausible business justification)
2. AND one of these usage signals confirms the access is unused or stale:
   - App has never been accessed or not in last 180 days
   - Access has existed for more than 90 days with zero usage
   - User's Okta status is SUSPENDED or DEPROVISIONED
   - User's Okta last login is Never (likely offboarded)

Never Revoke based on usage alone; always require a role mismatch first.
Never Revoke based on role mismatch alone; always consider whether there
could be a legitimate cross-functional reason.
Err toward Review rather than Revoke when uncertain; a false Revoke that
removes legitimate access is disruptive and erodes trust in the tool.

## Risk levels
- High: Revoke verdict OR sensitive app (security tools, infrastructure,
  source code, finance systems, admin consoles) with any anomaly
- Medium: Review verdict on moderately sensitive app, or Revoke on
  low-sensitivity app
- Low: Review verdict on low-sensitivity app, or Keep with minor concern

## Important guidelines
- Consider the PATTERN across all users; if 95% are Engineering and one is
  Finance, that Finance user warrants scrutiny even if usage looks normal
- Service accounts (bot@, svc-, system@, non-human names) should always
  be flagged as Review regardless of usage patterns
- Never use department name alone to Revoke; always consider title and usage
- Be concise in reasoning; one sentence maximum, actionable and specific

## Output format
Return ONLY a valid JSON array. No preamble, no explanation, no markdown fences.
Each object must have exactly these four fields:
[
  {
    "login": "user@company.com",
    "verdict": "Keep" | "Review" | "Revoke",
    "risk": "Low" | "Medium" | "High",
    "reasoning": "Single sentence explaining the verdict."
  }
]
"""


class OktaAnalyzer:
    def __init__(self):
        load_dotenv()
        api_key      = os.environ.get("ANTHROPIC_API_KEY")
        self.enabled = bool(api_key)

        if self.enabled:
            self.client = anthropic.Anthropic(api_key=api_key)
            print(f"[+] Claude API connected; analysis enabled\n")
        else:
            print(f"[!] ANTHROPIC_API_KEY not set; running in data-only mode\n")
            self.client = None

    def analyze_all(self, apps, anonymize=False):
        """
        Analyze all apps. Calls analyze_app() for each.
        Returns the enriched apps list with verdicts attached.
        Skips apps with no assigned users.
        """
        if not self.enabled:
            return apps

        total    = len(apps)
        analyzed = 0

        for i, app in enumerate(apps, 1):
            if not app.get("users"):
                continue

            print(f"  [{i}/{total}] Analyzing: {app['name']} ({len(app['users'])} users)...")
            app = self.analyze_app(app, anonymize=anonymize)
            analyzed += 1

        print(f"\n[+] Analysis complete; {analyzed} apps analyzed\n")
        return apps

    def analyze_app(self, app, anonymize=False):
        """
        Send a single app to Claude for analysis.
        Attaches verdict, risk, and reasoning to each user in the app.
        Large apps (>USER_BATCH_SIZE users) are split into batches.
        Falls back to Review/Unknown on any error.
        """
        if not self.enabled:
            return app

        #Split large apps into batches
        if len(app["users"]) > USER_BATCH_SIZE:
            return self._analyze_large_app(app, anonymize=anonymize)

        prompt, user_map = self._build_prompt(app, anonymize=anonymize)

        try:
            response = self.client.messages.create(
                model      = "claude-sonnet-4-6",
                max_tokens = 4096,
                system     = [
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"}  #prompt caching
                    }
                ],
                messages   = [
                    {"role": "user", "content": prompt}
                ]
            )

            #Handle empty response with a retry before falling back
            if not response.content or not response.content[0].text.strip():
                print(f"\n[!] Empty response for {app['name']} — retrying after 30s...")
                time.sleep(30)
                response = self.client.messages.create(
                    model      = "claude-sonnet-4-6",
                    max_tokens = 4096,
                    system     = [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                    messages   = [{"role": "user", "content": prompt}]
                )

            raw_text = response.content[0].text.strip() if response.content else ""
            verdicts = self._parse_response(raw_text, app)
            app      = self._attach_verdicts(app, verdicts, user_map=user_map)

        except anthropic.RateLimitError:
            print(f"\n[!] Rate limit hit on {app['name']}; waiting 60s...")
            time.sleep(60)
            #Retry once
            try:
                response = self.client.messages.create(
                    model      = "claude-sonnet-4-6",
                    max_tokens = 4096,
                    system     = [
                        {
                            "type": "text",
                            "text": SYSTEM_PROMPT,
                            "cache_control": {"type": "ephemeral"}
                        }
                    ],
                    messages   = [
                        {"role": "user", "content": prompt}
                    ]
                )

                #Handle empty response on retry path too
                if not response.content or not response.content[0].text.strip():
                    print(f"\n[!] Empty response on retry for {app['name']} — retrying after 30s...")
                    time.sleep(30)
                    response = self.client.messages.create(
                        model      = "claude-sonnet-4-6",
                        max_tokens = 4096,
                        system     = [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                        messages   = [{"role": "user", "content": prompt}]
                    )

                raw_text = response.content[0].text.strip() if response.content else ""
                verdicts = self._parse_response(raw_text, app)
                app      = self._attach_verdicts(app, verdicts, user_map=user_map)
            except Exception as e:
                print(f"\n[-] Retry failed for {app['name']}: {e}")
                app = self._attach_fallback(app)

        except Exception as e:
            print(f"\n[-] Analysis failed for {app['name']}: {e}")
            app = self._attach_fallback(app)

        return app

    def _analyze_large_app(self, app, anonymize=False):
        """
        For apps with more than USER_BATCH_SIZE users, split into
        batches and merge verdicts back into the app dict.
        Each batch is a separate Claude call with a sleep between
        batches to respect Tier 1 output token limits (8K/min).
        """
        all_users       = app["users"]
        batches         = [
            all_users[i:i+USER_BATCH_SIZE]
            for i in range(0, len(all_users), USER_BATCH_SIZE)
        ]
        verdicted_users = []

        for j, batch in enumerate(batches):
            print(f"      batch {j+1}/{len(batches)} ({len(batch)} users)...")

            #Sleep between batches to stay under Tier 1 output token limit
            if j > 0:
                time.sleep(BATCH_SLEEP)

            batch_app = {
                "id":           app["id"],
                "name":         app["name"],
                "sign_on_mode": app["sign_on_mode"],
                "users":        batch,
            }
            batch_app = self.analyze_app(batch_app, anonymize=anonymize)
            verdicted_users.extend(batch_app["users"])

        app["users"] = verdicted_users
        return app

    def _build_prompt(self, app, anonymize=False):
        """
        Build the per-app prompt with department distribution
        and individual user context.
        With anonymize=True, emails are replaced with user_001, user_002...
        Returns (prompt_string, user_map) where user_map maps anon_id -> real login.
        user_map is empty when anonymize=False.
        """
        lines = [
            f"## Application: {app['name']}",
            f"Sign-on type: {app['sign_on_mode']}",
            f"Total users assigned: {len(app['users'])}",
            "",
            "## Department distribution of assigned users:",
        ]

        #Department breakdown; gives Claude pattern context upfront
        dept_counts = {}
        for u in app["users"]:
            dept = u.get("department", "Unknown")
            dept_counts[dept] = dept_counts.get(dept, 0) + 1

        for dept, count in sorted(dept_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {dept}: {count} user(s)")

        lines.append("")
        lines.append("## Individual user assignments:")

        user_map = {}
        for i, u in enumerate(app["users"]):
            if anonymize:
                display_id           = f"user_{i+1:03d}"
                user_map[display_id] = u["login"]
            else:
                display_id = u["login"]

            lines.append(
                f"- {display_id} | "
                f"Dept: {u.get('department', 'Unknown')} | "
                f"Title: {u.get('title', 'Unknown')} | "
                f"Status: {u.get('status', 'Unknown')} | "
                f"Assigned: {u.get('days_assigned', '?')} days ago | "
                f"Last used this app: {u.get('last_app_access', 'Unknown')} | "
                f"Okta last login: {u.get('last_login', 'Unknown')}"
            )

        lines.append("")
        lines.append(
            "Analyze each user and return a JSON array with your verdicts."
        )

        return "\n".join(lines), user_map

    def _parse_response(self, raw_text, app):
        """
        Parse Claude's JSON response into a list of verdict dicts.
        Strips markdown fences if Claude added them despite instructions.
        Falls back to Review for any user Claude missed or malformed.
        """
        #Strip markdown fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        if not raw_text:
            print(f"\n[-] Empty response for {app['name']}; falling back to Review")
            return []

        try:
            verdicts = json.loads(raw_text)
        except json.JSONDecodeError as e:
            print(f"\n[-] JSON parse error for {app['name']}: {e}")
            return []

        #Validate and sanitize each verdict
        clean = []
        for v in verdicts:
            verdict   = v.get("verdict", "Review")
            risk      = v.get("risk", "Medium")
            login     = v.get("login", "")
            reasoning = v.get("reasoning", "Could not analyze.")

            #Enforce valid values
            if verdict not in VALID_VERDICTS:
                verdict = "Review"
            if risk not in VALID_RISKS:
                risk = "Medium"

            clean.append({
                "login":     login,
                "verdict":   verdict,
                "risk":      risk,
                "reasoning": reasoning,
            })

        return clean

    def _attach_verdicts(self, app, verdicts, user_map=None):
        """
        Match Claude's verdicts back to users by login.
        If anonymize was used, remaps anon IDs back to real emails first.
        Any user not matched gets a fallback Review verdict.
        """
        #Remap anon IDs back to real logins if anonymize was used
        if user_map:
            for v in verdicts:
                if v.get("login") in user_map:
                    v["login"] = user_map[v["login"]]

        verdict_map = {v["login"]: v for v in verdicts}

        for user in app["users"]:
            login = user.get("login", "")
            if login in verdict_map:
                v = verdict_map[login]
                user["verdict"]   = v["verdict"]
                user["risk"]      = v["risk"]
                user["reasoning"] = v["reasoning"]
            else:
                #Claude missed this user; default to Review
                user["verdict"]   = "Review"
                user["risk"]      = "Medium"
                user["reasoning"] = "Not analyzed; flagged for manual review."

        return app

    def _attach_fallback(self, app):
        """
        If the entire API call failed, mark all users in this app
        as Review so nothing gets silently missed.
        """
        for user in app["users"]:
            user["verdict"]   = "Review"
            user["risk"]      = "Medium"
            user["reasoning"] = "Analysis failed; flagged for manual review."
        return app