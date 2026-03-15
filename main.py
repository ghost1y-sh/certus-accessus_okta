#!/usr/bin/env python3
"""

main.py
Entry point for certus-accessus_okta.

READ ONLY; no changes are made to your Okta organization.
All remediation must be performed manually by your IT and Security teams.

"""

import argparse
import sys
import time
import json
from modules.connector import OktaConnector
from modules.collector import OktaCollector
from modules.analyzer  import OktaAnalyzer
from modules.reporter  import Reporter, Color
from modules.utils import load_credentials, redact_apps

def parse_args():
    parser = argparse.ArgumentParser(
        description="certus-accessus_okta; AI-powered Okta access certification"
    )
    parser.add_argument(
        "--domain",
        default=None,
        help="Okta domain. Overrides .env if set."
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Base name for output files (e.g. 'report' → report.json + report.csv)."
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Partially redact email addresses in output."
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show Keep verdicts in terminal output (hidden by default)."
    )
    parser.add_argument(
        "--failing-only",
        action="store_true",
        help="Show only Revoke verdicts in terminal output."
    )
    parser.add_argument(
        "--no-access-log",
        action="store_true",
        help="Skip system log queries. Faster but last_app_access will be Unknown."
    )
    parser.add_argument(
        "--app",
        default=None,
        help="Analyze only apps whose name contains this string (case-insensitive)."
    )
    parser.add_argument(
        "--dept",
        default=None,
        help="Filter to users in this department only (case-insensitive)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect data but skip Claude analysis. Produces raw access inventory."
    )
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="Replace emails with anonymous IDs in Claude prompts. Recommended for orgs with strict PII policies."
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Test connection and token scope only. Does not run a full scan."
    )
    parser.add_argument(
        "--save-okta",
        default=None,
        help="Save Okta collection output to this JSON file for reuse with --from-file."
    )
    parser.add_argument(
        "--from-file",
        default=None,
        help="Skip Okta collection entirely and load from a previously saved --save-okta file."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Write raw Claude API responses to claude_debug.log for troubleshooting."
    )
    return parser.parse_args()


def verify_connection(connector, domain):
    print(f"\n[*] Verifying connection to {domain}...\n")
    if not connector.test_connection():
        sys.exit(1)

    #Get the current user's roles to determine actual permission level
    me = connector.get("/users/me")
    uid = me.get("id")

    role_level = "Read-Only Administrator"  #default assumption

    if uid:
        roles = connector.get_all(f"/users/{uid}/roles")
        role_types = {r.get("type") for r in roles}

        if "SUPER_ADMIN" in role_types:
            role_level = "Super Administrator"
        elif "ORG_ADMIN" in role_types:
            role_level = "Org Administrator"
        elif "APP_ADMIN" in role_types:
            role_level = "App Administrator"
        elif "READ_ONLY_ADMIN" in role_types:
            role_level = "Read-Only Administrator"
        else:
            role_level = f"Custom/Unknown role; types: {', '.join(role_types) or 'none detected'}"

    #Warn if not at least Read-Only Admin
    if "Read-Only" not in role_level and "Administrator" not in role_level:
        print(f"{Color.YELLOW}[!] Token may lack sufficient permissions for a full scan.{Color.RESET}")

    print(f"{Color.GREEN}[+] Token permission level: {role_level}{Color.RESET}")
    print(f"{Color.GREEN}[+] Domain reachable: {domain}{Color.RESET}")
    print(f"{Color.GREEN}[+] Ready to run full access certification scan.{Color.RESET}\n")


def filter_apps(apps, app_filter=None, dept_filter=None):
    """
    Apply --app and --dept filters to the collected app list.
    """
    if app_filter:
        apps = [
            a for a in apps
            if app_filter.lower() in a.get("name", "").lower()
        ]
        print(f"[*] App filter '{app_filter}'; {len(apps)} app(s) matched\n")

    if dept_filter:
        for app in apps:
            app["users"] = [
                u for u in app.get("users", [])
                if dept_filter.lower() in u.get("department", "").lower()
            ]
        #Remove apps with no matching users
        apps = [a for a in apps if a.get("users")]
        print(f"[*] Dept filter '{dept_filter}' applied\n")

    return apps


def main():
    args = parse_args()

    domain, token = load_credentials()
    if args.domain:
        domain = args.domain.strip().rstrip("/")

    #Banner
    print(f"""
{Color.RED}  ██████╗███████╗██████╗ ████████╗██╗   ██╗███████╗{Color.RESET}
{Color.RED} ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║   ██║██╔════╝{Color.RESET}
{Color.RED} ██║     █████╗  ██████╔╝   ██║   ██║   ██║███████╗{Color.RESET}
{Color.RED} ██║     ██╔══╝  ██╔══██╗   ██║   ██║   ██║╚════██║{Color.RESET}
{Color.RED} ╚██████╗███████╗██║  ██║   ██║   ╚██████╔╝███████║{Color.RESET}
{Color.RED}  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝{Color.RESET}
{Color.ORANGE} █████╗  ██████╗ ██████╗███████╗███████╗███████╗██╗   ██╗███████╗{Color.RESET}
{Color.ORANGE}██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝{Color.RESET}
{Color.ORANGE}███████║██║     ██║     █████╗  ███████╗███████╗██║   ██║███████╗{Color.RESET}
{Color.ORANGE}██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║██║   ██║╚════██║{Color.RESET}
{Color.ORANGE}██║  ██║╚██████╗╚██████╗███████╗███████║███████║╚██████╔╝███████║{Color.RESET}
{Color.ORANGE}╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝{Color.RESET}

  {Color.BOLD}certus-accessus_okta v1.0{Color.RESET}
  {Color.BOLD}AI-Powered Okta Access Certification{Color.RESET}
  {Color.BOLD}github.com/ghost1y-sh{Color.RESET}

  {Color.YELLOW}READ ONLY; no changes will be made to your Okta organization.{Color.RESET}
  {Color.YELLOW}All remediation must be performed manually by your IT and Security teams.{Color.RESET}
    """)

    #Connect — skip entirely if loading from file
    connector = None
    if not args.from_file:
        print(f"[*] Connecting to {domain}...")
        connector = OktaConnector(domain, token)
        if not connector.test_connection():
            sys.exit(1)
        print(f"{Color.GREEN}[+] Connection verified.{Color.RESET}\n")

        if args.verify:
            verify_connection(connector, domain)
            sys.exit(0)

    #Collect — either from Okta API or from saved file
    if args.from_file:
        print(f"{Color.YELLOW}[*] Loading Okta data from file: {args.from_file}{Color.RESET}\n")
        with open(args.from_file, "r") as f:
            apps = json.load(f)
        print(f"{Color.GREEN}[+] Loaded {len(apps):,} apps from file.{Color.RESET}\n")
    else:
        collector = OktaCollector(connector)
        apps      = collector.collect_all(
            skip_access_log=args.no_access_log
        )
        if args.save_okta:
            with open(args.save_okta, "w") as f:
                json.dump(apps, f, indent=2, default=str)
            print(f"{Color.GREEN}[+] Okta data saved to: {args.save_okta}{Color.RESET}\n")

    #Apply filters
    if args.app or args.dept:
        apps = filter_apps(apps, args.app, args.dept)

    if not apps:
        print(f"{Color.YELLOW}[!] No apps matched the given filters.{Color.RESET}")
        sys.exit(0)

    #Analyze
    analyzer = OktaAnalyzer()
    if args.dry_run:
        print(f"{Color.YELLOW}[*] Dry run; skipping Claude analysis.{Color.RESET}\n")
        ai_enabled = False
    else:
        if args.anonymize:
            print(f"{Color.YELLOW}[*] Anonymize mode — emails replaced with IDs in Claude prompts.{Color.RESET}\n")
        if args.debug:
            print(f"{Color.YELLOW}[*] Debug mode — raw Claude responses written to claude_debug.log{Color.RESET}\n")
        ai_enabled = analyzer.enabled
        if ai_enabled:
            print(f"[*] Running AI analysis...\n")
            apps = analyzer.analyze_all(apps, anonymize=args.anonymize, debug=args.debug)

    #Redact if requested
    if args.redact:
        print(f"{Color.YELLOW}[*] Redacting PII from output...{Color.RESET}\n")
        apps = redact_apps(apps)

    #Report
    reporter = Reporter(apps, domain=domain, ai_enabled=ai_enabled)
    reporter.print_report(
        show_all     = args.show_all,
        failing_only = args.failing_only,
    )

    #Save outputs
    if args.output:
        reporter.save_json(f"{args.output}.json")
        reporter.save_csv(f"{args.output}.csv")

    #Done
    print(f"\n{Color.RED}[*] Scan complete.{Color.RESET}")
    for i in range(3):
        print(". ")
        time.sleep(1)
    print(f"{Color.GREEN}[✓] Done.{Color.RESET}\n")


if __name__ == "__main__":
    main()