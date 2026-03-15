#!/usr/bin/env python3
"""

modules/reporter.py
Report formatting for certus-accessus_okta.

Three output formats:
1. Terminal — color-coded, verdict-sorted, actionable
2. JSON     — full audit evidence
3. CSV      — manager review workflow document

In data-only mode (no AI verdicts), terminal and CSV still work
but verdict columns are omitted or marked as N/A.

"""

import csv
import json
import time
from datetime import datetime


def slow_print(text, delay=0.02):
    for line in text.split("\n"):
        print(line)
        time.sleep(delay)


class Color:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    ORANGE = "\033[38;5;208m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    DIM    = "\033[2m"


VERDICT_COLORS = {
    "Revoke": Color.RED,
    "Review": Color.YELLOW,
    "Keep":   Color.GREEN,
}

VERDICT_ICONS = {
    "Revoke": "✗",
    "Review": "⚠",
    "Keep":   "✓",
}

RISK_COLORS = {
    "High":   Color.RED,
    "Medium": Color.YELLOW,
    "Low":    Color.GREEN,
}

#Sort order for verdicts in display
VERDICT_ORDER = ["Revoke", "Review", "Keep"]


class Reporter:
    def __init__(self, apps, domain, ai_enabled=True):
        self.apps       = apps
        self.domain     = domain
        self.ai_enabled = ai_enabled
        self.timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_report(self, show_all=False, failing_only=False):
        """
        Print the full terminal report.
        show_all=True  — show Keep verdicts too
        failing_only   — show only Revoke verdicts
        """
        self._print_header()
        time.sleep(2)

        #Sort apps by number of Revoke verdicts descending
        sorted_apps = sorted(
            self.apps,
            key=lambda a: sum(
                1 for u in a.get("users", [])
                if u.get("verdict") == "Revoke"
            ),
            reverse=True
        )

        for app in sorted_apps:
            users = app.get("users", [])
            if not users:
                continue

            #Determine which users to show
            if failing_only:
                display_users = [u for u in users if u.get("verdict") == "Revoke"]
            elif not show_all:
                display_users = [u for u in users if u.get("verdict") in ("Revoke", "Review")]
            else:
                display_users = users

            if not display_users:
                continue

            self._print_app(app, display_users)
            time.sleep(0.5)

        self._print_summary()

    def _print_header(self):
        slow_print(f"\n{Color.BOLD}{'═' * 56}{Color.RESET}")
        slow_print(f"{Color.BOLD}  CERTUS-ACCESSUS REPORT: {self.domain.upper()}{Color.RESET}")
        slow_print(f"  {self.timestamp}")
        if not self.ai_enabled:
            slow_print(f"  {Color.YELLOW}[data-only mode — no AI verdicts]{Color.RESET}")
        slow_print(f"{Color.BOLD}{'═' * 56}{Color.RESET}\n")

    def _print_app(self, app, display_users):
        """
        Print a single app block with its users sorted by verdict.
        """
        total_users   = len(app.get("users", []))
        revoke_count  = sum(1 for u in app["users"] if u.get("verdict") == "Revoke")
        review_count  = sum(1 for u in app["users"] if u.get("verdict") == "Review")

        #App header
        app_color = Color.RED if revoke_count > 0 else Color.YELLOW if review_count > 0 else Color.GREEN
        slow_print(
            f"{app_color}{Color.BOLD}{app['name']}{Color.RESET}"
            f"{Color.DIM} — {total_users} user(s) assigned{Color.RESET}"
        )

        if revoke_count or review_count:
            slow_print(
                f"{Color.DIM}  "
                f"{Color.RED}{revoke_count} revoke{Color.RESET}{Color.DIM}  "
                f"{Color.YELLOW}{review_count} review{Color.RESET}"
            )

        #Sort users: Revoke → Review → Keep
        sorted_users = sorted(
            display_users,
            key=lambda u: VERDICT_ORDER.index(u.get("verdict", "Review"))
            if u.get("verdict") in VERDICT_ORDER else 99
        )

        for user in sorted_users:
            self._print_user(user)

        slow_print("")

    def _print_user(self, user):
        """
        Print a single user line with verdict, risk, and reasoning.
        """
        verdict   = user.get("verdict", "N/A")
        risk      = user.get("risk", "")
        reasoning = user.get("reasoning", "")
        login     = user.get("login", "unknown")
        dept      = user.get("department", "Unknown")
        title     = user.get("title", "Unknown")
        days      = user.get("days_assigned", "?")
        last_app  = user.get("last_app_access", "Unknown")

        color = VERDICT_COLORS.get(verdict, Color.RESET)
        icon  = VERDICT_ICONS.get(verdict, "?")
        risk_color = RISK_COLORS.get(risk, Color.RESET)

        if self.ai_enabled and verdict != "N/A":
            slow_print(
                f"  {color}{icon} {verdict:<7}{Color.RESET}"
                f"  {Color.BOLD}{login}{Color.RESET}"
                f"  {Color.DIM}({dept} / {title}){Color.RESET}"
            )
            if risk:
                slow_print(
                    f"           {risk_color}[{risk} risk]{Color.RESET}"
                    f"  {Color.DIM}{reasoning}{Color.RESET}"
                )
            slow_print(
                f"           {Color.DIM}Assigned: {days}d ago  |  "
                f"Last app access: {last_app}{Color.RESET}"
            )
        else:
            #Data-only mode
            slow_print(
                f"  {Color.DIM}→{Color.RESET}  {Color.BOLD}{login}{Color.RESET}"
                f"  {Color.DIM}({dept} / {title})  "
                f"Assigned: {days}d ago  |  Last app access: {last_app}{Color.RESET}"
            )

    def _print_summary(self):
        """
        Print the summary block with counts and percentages.
        """
        all_users = [u for app in self.apps for u in app.get("users", [])]
        total     = len(all_users)

        revoke_count = sum(1 for u in all_users if u.get("verdict") == "Revoke")
        review_count = sum(1 for u in all_users if u.get("verdict") == "Review")
        keep_count   = sum(1 for u in all_users if u.get("verdict") == "Keep")
        high_count   = sum(1 for u in all_users if u.get("risk") == "High")
        medium_count = sum(1 for u in all_users if u.get("risk") == "Medium")

        apps_analyzed = sum(1 for a in self.apps if a.get("users"))

        def pct(n):
            return f"{(n / total * 100):.0f}%" if total > 0 else "0%"

        slow_print(f"{Color.BOLD}{'═' * 56}{Color.RESET}")
        slow_print(f"{Color.BOLD}  SUMMARY{Color.RESET}\n")
        slow_print(f"  {'Apps analyzed:':<24} {apps_analyzed:,}")
        slow_print(f"  {'Users reviewed:':<24} {total:,}")
        slow_print("")

        if self.ai_enabled:
            slow_print(f"  {Color.GREEN}{'Keep:':<24}{Color.RESET} {keep_count:,}  ({pct(keep_count)})")
            time.sleep(1)
            slow_print(f"  {Color.YELLOW}{'Review:':<24}{Color.RESET} {review_count:,}  ({pct(review_count)})")
            time.sleep(1)
            slow_print(f"  {Color.RED}{'Revoke:':<24}{Color.RESET} {revoke_count:,}  ({pct(revoke_count)})")
            time.sleep(1)
            slow_print("")
            slow_print(f"  {Color.RED}{'High risk items:':<24}{Color.RESET} {high_count:,}")
            slow_print(f"  {Color.YELLOW}{'Medium risk items:':<24}{Color.RESET} {medium_count:,}")

        slow_print(f"{Color.BOLD}{'═' * 56}{Color.RESET}\n")

    def save_json(self, filepath):
        """
        Save full audit report as JSON.
        Includes metadata, all apps, all users, all verdicts.
        """
        report = {
            "metadata": {
                "domain":     self.domain,
                "generated":  self.timestamp,
                "tool":       "certus-accessus_okta v1.0",
                "ai_enabled": self.ai_enabled,
            },
            "summary": self._build_summary_dict(),
            "apps":    self.apps,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"{Color.GREEN}[+] JSON report saved to: {filepath}{Color.RESET}")

    def save_csv(self, filepath):
        """
        Save access review CSV for manager workflow.
        Last three columns (reviewed_by, action_taken, review_date)
        are blank — for the IT team to complete during remediation.
        """
        fieldnames = [
            "app_name",
            "app_sign_on",
            "user_login",
            "user_name",
            "department",
            "title",
            "status",
            "assigned_date",
            "days_assigned",
            "last_app_access",
            "okta_last_login",
            "ai_verdict",
            "ai_risk",
            "ai_reasoning",
            "reviewed_by",      #blank — IT team fills in
            "action_taken",     #blank — IT team fills in
            "review_date",      #blank — IT team fills in
        ]

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for app in self.apps:
                for user in app.get("users", []):
                    writer.writerow({
                        "app_name":        app.get("name", ""),
                        "app_sign_on":     app.get("sign_on_mode", ""),
                        "user_login":      user.get("login", ""),
                        "user_name":       user.get("name", ""),
                        "department":      user.get("department", ""),
                        "title":           user.get("title", ""),
                        "status":          user.get("status", ""),
                        "assigned_date":   user.get("assigned_date", ""),
                        "days_assigned":   user.get("days_assigned", ""),
                        "last_app_access": user.get("last_app_access", ""),
                        "okta_last_login": user.get("last_login", ""),
                        "ai_verdict":      user.get("verdict", "N/A"),
                        "ai_risk":         user.get("risk", "N/A"),
                        "ai_reasoning":    user.get("reasoning", ""),
                        "reviewed_by":     "",
                        "action_taken":    "",
                        "review_date":     "",
                    })

        print(f"{Color.GREEN}[+] CSV report saved to: {filepath}{Color.RESET}")

    def _build_summary_dict(self):
        """
        Build summary statistics dict for JSON output.
        """
        all_users = [u for app in self.apps for u in app.get("users", [])]
        total     = len(all_users)

        return {
            "apps_analyzed":  sum(1 for a in self.apps if a.get("users")),
            "users_reviewed": total,
            "keep":           sum(1 for u in all_users if u.get("verdict") == "Keep"),
            "review":         sum(1 for u in all_users if u.get("verdict") == "Review"),
            "revoke":         sum(1 for u in all_users if u.get("verdict") == "Revoke"),
            "high_risk":      sum(1 for u in all_users if u.get("risk") == "High"),
            "medium_risk":    sum(1 for u in all_users if u.get("risk") == "Medium"),
            "low_risk":       sum(1 for u in all_users if u.get("risk") == "Low"),
        }