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

Multi-app grouping: small apps are batched together into single Claude calls
to dramatically reduce total API calls and runtime. Apps are grouped by
combined user count up to MAX_USERS_PER_CALL. Large apps run solo with
internal batching.

Tier 3 constants: 160K OTPM, 2K RPM.

"""

import os
import json
import time
import anthropic
from dotenv import load_dotenv

load_dotenv()

VALID_VERDICTS = {"Keep", "Review", "Revoke"}
VALID_RISKS    = {"Low", "Medium", "High"}

#Max combined users per grouped Claude call
#Tier 3: 160K OTPM / ~75 tokens per verdict = ~2100 users max
#800 is a safe target leaving headroom for verbose responses
MAX_USERS_PER_CALL  = 800

#Apps with more users than this run solo with internal batching
LARGE_APP_THRESHOLD = 600

#Batch size for internal batching of large apps
LARGE_APP_BATCH     = 150

#Retry config; keep retries low to avoid runaway API cost
MAX_RETRIES  = 1
RETRY_DELAYS = [30]

#Pace all Claude calls; 1s is safe at Tier 3 (2K RPM)
CALL_SLEEP = 1


SYSTEM_PROMPT = """
You are a senior identity security analyst performing an access certification
review for an enterprise Okta organization. Your role is to evaluate whether
each user's application access is appropriate and flag risks for remediation.

## Your task
You will receive one or more applications. For each application, analyze every
assigned user and return verdicts on whether their access should be kept,
reviewed by a human, or revoked.

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
- Consider the PATTERN across all users within each app
- Service accounts (bot@, svc-, system@, non-human names) should always
  be flagged as Review regardless of usage patterns
- Never use department name alone to Revoke; always consider title and usage
- Be concise in reasoning; one sentence maximum, actionable and specific

## Output format
Return ONLY a valid JSON object. No preamble, no explanation, no markdown fences.
Keys are exact application names. Values are arrays of verdict objects.

{
  "AppName": [
    {
      "login": "user@company.com",
      "verdict": "Keep" | "Review" | "Revoke",
      "risk": "Low" | "Medium" | "High",
      "reasoning": "Single sentence explaining the verdict."
    }
  ],
  "AnotherAppName": [
    ...
  ]
}
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

    def _call_claude(self, prompt, debug=False):
        """
        Make a single Claude API call using streaming to prevent
        network timeouts on long responses.
        Retries once on failure then falls back.
        """
        for attempt in range(MAX_RETRIES + 1):
            try:
                time.sleep(CALL_SLEEP)

                with self.client.messages.stream(
                    model      = "claude-sonnet-4-6",
                    max_tokens = 64000,
                    system     = [
                        {
                            "type": "text",
                            "text": SYSTEM_PROMPT,
                            "cache_control": {"type": "ephemeral"}
                        }
                    ],
                    messages   = [{"role": "user", "content": prompt}]
                ) as stream:
                    message = stream.get_final_message()

                text = message.content[0].text.strip() if message.content else ""

                if debug:
                    with open("claude_debug.log", "a") as log:
                        log.write(f"\n{'='*60}\n")
                        log.write(f"attempt: {attempt+1}\n")
                        log.write(f"stop_reason: {message.stop_reason}\n")
                        log.write(f"content blocks: {len(message.content)}\n")
                        log.write(f"usage: {message.usage}\n")
                        if message.content:
                            log.write(f"text length: {len(message.content[0].text)}\n")
                            log.write(f"text preview: {message.content[0].text[:500]}\n")
                        else:
                            log.write(f"NO CONTENT BLOCKS RETURNED\n")
                        log.write(f"{'='*60}\n")

                if not text:
                    if attempt < MAX_RETRIES:
                        delay = RETRY_DELAYS[attempt]
                        print(f"\n[!] Empty response (attempt {attempt+1}/{MAX_RETRIES+1}); retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                    else:
                        print(f"\n[-] Empty response after {MAX_RETRIES} retries; falling back.")
                        return ""

                return text

            except anthropic.RateLimitError:
                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    print(f"\n[!] Rate limit hit (attempt {attempt+1}/{MAX_RETRIES+1}); retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    print(f"\n[-] Rate limit persists; falling back.")
                    return ""

            except Exception as e:
                print(f"\n[-] API error (attempt {attempt+1}/{MAX_RETRIES+1}): {e}")
                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    time.sleep(delay)
                    continue
                return ""

        return ""

    def analyze_all(self, apps, anonymize=False, debug=False):
        """
        Main analysis entry point.

        Strategy:
        - Apps with 0 users are skipped
        - Apps with >LARGE_APP_THRESHOLD users run solo with internal batching
        - All other apps are grouped by combined user count up to
          MAX_USERS_PER_CALL and analyzed together in one Claude call

        This dramatically reduces total API calls vs one-app-per-call.
        """
        if not self.enabled:
            return apps

        print(f"[*] Warming up Claude API connection...\n")
        self._call_claude("ping", debug=debug)

        #Split into large apps (solo) and small apps (grouped)
        large_apps = [a for a in apps if len(a.get("users", [])) > LARGE_APP_THRESHOLD]
        small_apps = [a for a in apps if 0 < len(a.get("users", [])) <= LARGE_APP_THRESHOLD]
        empty_apps = [a for a in apps if not a.get("users")]

        print(f"[*] App breakdown:")
        print(f"    {len(large_apps)} large apps (>{LARGE_APP_THRESHOLD} users) — solo calls with batching")
        print(f"    {len(small_apps)} small apps (1-{LARGE_APP_THRESHOLD} users) — grouped calls")
        print(f"    {len(empty_apps)} empty apps — skipped\n")

        #Group small apps by combined user count up to MAX_USERS_PER_CALL
        groups  = []
        current = []
        count   = 0

        for app in small_apps:
            n = len(app["users"])
            if count + n > MAX_USERS_PER_CALL and current:
                groups.append(current)
                current = [app]
                count   = n
            else:
                current.append(app)
                count += n

        if current:
            groups.append(current)

        total_calls = len(groups) + len(large_apps)
        print(f"[*] Total Claude calls: {total_calls} ({len(groups)} grouped + {len(large_apps)} large)\n")

        #Process grouped small apps
        for g, group in enumerate(groups, 1):
            names       = ", ".join(a["name"] for a in group)
            total_users = sum(len(a["users"]) for a in group)
            print(f"  [group {g}/{len(groups)}] {len(group)} apps, {total_users} users: {names[:80]}...")

            prompt, user_maps = self._build_multi_prompt(group, anonymize=anonymize)
            raw_text          = self._call_claude(prompt, debug=debug)

            if raw_text:
                self._attach_multi_verdicts(group, raw_text, user_maps)
            else:
                for app in group:
                    self._attach_fallback(app)

        #Process large apps solo with internal batching
        for i, app in enumerate(large_apps, 1):
            print(f"  [large {i}/{len(large_apps)}] {app['name']} ({len(app['users'])} users)...")
            self._analyze_large_app(app, anonymize=anonymize, debug=debug)

        print(f"\n[+] Analysis complete.\n")
        return apps

    def _build_multi_prompt(self, apps, anonymize=False):
        """
        Build a single prompt covering multiple apps.
        Returns (prompt_string, user_maps) where user_maps is a dict of
        app_name -> {anon_id: real_login} for anonymize remapping.
        """
        lines     = ["Analyze the following applications and return verdicts for all users.\n"]
        user_maps = {}

        for app in apps:
            app_name            = app["name"]
            user_maps[app_name] = {}

            dept_counts = {}
            for u in app["users"]:
                dept = u.get("department", "Unknown")
                dept_counts[dept] = dept_counts.get(dept, 0) + 1

            lines.append(f"## Application: {app_name}")
            lines.append(f"Sign-on type: {app.get('sign_on_mode', 'UNKNOWN')}")
            lines.append(f"Total users: {len(app['users'])}")
            lines.append("Department distribution:")
            for dept, count in sorted(dept_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {dept}: {count}")
            lines.append("Users:")

            for i, u in enumerate(app["users"]):
                if anonymize:
                    display_id                      = f"user_{i+1:03d}"
                    user_maps[app_name][display_id] = u["login"]
                else:
                    display_id = u["login"]

                lines.append(
                    f"- {display_id} | "
                    f"Dept: {u.get('department', 'Unknown')} | "
                    f"Title: {u.get('title', 'Unknown')} | "
                    f"Status: {u.get('status', 'Unknown')} | "
                    f"Assigned: {u.get('days_assigned', '?')}d ago | "
                    f"Last app access: {u.get('last_app_access', 'Unknown')} | "
                    f"Okta login: {u.get('last_login', 'Unknown')}"
                )

            lines.append("")

        lines.append(
            "Return a JSON object keyed by exact application name. "
            "Each value is an array of verdict objects for that app's users."
        )

        return "\n".join(lines), user_maps

    def _attach_multi_verdicts(self, apps, raw_text, user_maps):
        """
        Parse a multi-app response and attach verdicts to each app's users.
        Handles markdown fences, validates verdicts, falls back gracefully.
        """
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError as e:
            print(f"\n[-] JSON parse error on grouped response: {e}")
            for app in apps:
                self._attach_fallback(app)
            return

        for app in apps:
            app_name = app["name"]
            verdicts = result.get(app_name, [])
            user_map = user_maps.get(app_name, {})

            if not verdicts:
                print(f"\n[-] No verdicts returned for {app_name}; falling back.")
                self._attach_fallback(app)
                continue

            #Remap anon IDs if anonymize was used
            if user_map:
                for v in verdicts:
                    if v.get("login") in user_map:
                        v["login"] = user_map[v["login"]]

            verdict_map = {}
            for v in verdicts:
                verdict   = v.get("verdict", "Review")
                risk      = v.get("risk", "Medium")
                login     = v.get("login", "")
                reasoning = v.get("reasoning", "Could not analyze.")

                if verdict not in VALID_VERDICTS:
                    verdict = "Review"
                if risk not in VALID_RISKS:
                    risk = "Medium"

                verdict_map[login] = {
                    "verdict":   verdict,
                    "risk":      risk,
                    "reasoning": reasoning,
                }

            for user in app["users"]:
                login = user.get("login", "")
                if login in verdict_map:
                    v = verdict_map[login]
                    user["verdict"]   = v["verdict"]
                    user["risk"]      = v["risk"]
                    user["reasoning"] = v["reasoning"]
                else:
                    user["verdict"]   = "Review"
                    user["risk"]      = "Medium"
                    user["reasoning"] = "Not analyzed; flagged for manual review."

    def _analyze_large_app(self, app, anonymize=False, debug=False):
        """
        Large apps (>LARGE_APP_THRESHOLD users) are split into batches
        of LARGE_APP_BATCH users. Each batch is a solo Claude call.
        Verdicts are merged back into the app dict.
        """
        all_users       = app["users"]
        batches         = [
            all_users[i:i+LARGE_APP_BATCH]
            for i in range(0, len(all_users), LARGE_APP_BATCH)
        ]
        verdicted_users = []

        for j, batch in enumerate(batches):
            print(f"      batch {j+1}/{len(batches)} ({len(batch)} users)...")

            batch_app = {
                "id":           app["id"],
                "name":         app["name"],
                "sign_on_mode": app["sign_on_mode"],
                "users":        batch,
            }

            prompt, user_map = self._build_single_prompt(batch_app, anonymize=anonymize)
            raw_text         = self._call_claude(prompt, debug=debug)

            if raw_text:
                verdicts  = self._parse_single_response(raw_text, batch_app)
                batch_app = self._attach_verdicts(batch_app, verdicts, user_map=user_map)
            else:
                batch_app = self._attach_fallback(batch_app)

            verdicted_users.extend(batch_app["users"])

        app["users"] = verdicted_users

    def _build_single_prompt(self, app, anonymize=False):
        """
        Build a single-app prompt for large app batching.
        Uses the same JSON object output format for consistency.
        Returns (prompt_string, user_map).
        """
        lines = [
            f"## Application: {app['name']}",
            f"Sign-on type: {app.get('sign_on_mode', 'UNKNOWN')}",
            f"Total users assigned: {len(app['users'])}",
            "",
            "## Department distribution:",
        ]

        dept_counts = {}
        for u in app["users"]:
            dept = u.get("department", "Unknown")
            dept_counts[dept] = dept_counts.get(dept, 0) + 1

        for dept, count in sorted(dept_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {dept}: {count} user(s)")

        lines.append("")
        lines.append("## Users:")

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
                f"Assigned: {u.get('days_assigned', '?')}d ago | "
                f"Last app access: {u.get('last_app_access', 'Unknown')} | "
                f"Okta login: {u.get('last_login', 'Unknown')}"
            )

        lines.append("")
        lines.append(
            "Return a JSON object keyed by the application name. "
            "The value is an array of verdict objects for each user."
        )

        return "\n".join(lines), user_map

    def _parse_single_response(self, raw_text, app):
        """
        Parse a single-app response that uses the multi-app JSON object format.
        Falls back to trying plain array format for compatibility.
        """
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        if not raw_text:
            return []

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as e:
            print(f"\n[-] JSON parse error for {app['name']}: {e}")
            return []

        #Handle both {"AppName": [...]} and plain [...] formats
        if isinstance(parsed, dict):
            verdicts = parsed.get(app["name"], None)
            if verdicts is None and parsed:
                verdicts = list(parsed.values())[0]
            if verdicts is None:
                return []
        elif isinstance(parsed, list):
            verdicts = parsed
        else:
            return []

        clean = []
        for v in verdicts:
            verdict   = v.get("verdict", "Review")
            risk      = v.get("risk", "Medium")
            login     = v.get("login", "")
            reasoning = v.get("reasoning", "Could not analyze.")

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
        Match verdicts back to users by login.
        Remaps anon IDs if anonymize was used.
        """
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
                user["verdict"]   = "Review"
                user["risk"]      = "Medium"
                user["reasoning"] = "Not analyzed; flagged for manual review."

        return app

    def _attach_fallback(self, app):
        """
        If a call fails entirely, mark all users as Review.
        Nothing gets silently missed.
        """
        for user in app["users"]:
            user["verdict"]   = "Review"
            user["risk"]      = "Medium"
            user["reasoning"] = "Analysis failed; flagged for manual review."
        return app