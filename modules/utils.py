#!/usr/bin/env python3

"""

modules/utils.py

Credential loading, PII redaction, and shared helpers.
Security-first: Token never touches CLI args or stdout

"""

import os
import re
import getpass
from dotenv import load_dotenv


def load_credentials():
    """
    Load OKTA_DOMAIN and OKTA_TOKEN from .env file.
    Falls back to interactive prompt for token if not in .env.
    Never accepts token as a CLI argument.
    Returns (domain, token) tuple.
    """
    load_dotenv()

    domain = os.environ.get("OKTA_DOMAIN")
    token  = os.environ.get("OKTA_TOKEN")

    if not domain:
        domain = getpass.getpass("[>] Paste your Okta Login Link: ")
        #raise SystemExit("[-] OKTA_DOMAIN not set. Add it to your .env file.")

    if not domain:
        raise SystemExit("[-] No domain provided. Exiting.")

    if not token:
        print("[!] OKTA_TOKEN not found in .env.")
        token = getpass.getpass("[>] Paste your Okta API token: ")

    if not token:
        raise SystemExit("[-] No token provided. Exiting.")

    # Strip accidental whitespace
    domain = domain.strip().rstrip("/")
    token  = token.strip()

    return domain, token

def redact_email(text):
    """
    Partial email redaction. Keeps first 3 chars of local part, full domain visible.
    alice.admin@hearthlock.org -> ali*****@hearthlock.org
    """
    def _redact(match):
        local, domain_part = match.group(0).split("@", 1)
        keep = min(3, len(local))
        return f"{local[:keep]}*****@{domain_part}"

    return re.sub(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", _redact, str(text))

def redact_item(item, fields=None):
    """
    Redact PII fields in a findings item dict.
    Only redacts email/login fields. Names left visible for remediation.
    """
    EMAIL_FIELDS = fields or {"login", "email"}
    redacted = {}
    for k, v in item.items():
        if k in EMAIL_FIELDS:
            redacted[k] = redact_email(str(v))
        else:
            redacted[k] = v
    return redacted

def redact_findings(findings):
    """
    Walk all findings and redact PII in every item.
    Call this before printing or saving if --redact is set.
    """
    redacted = {}
    for key, finding in findings.items():
        redacted_items = [redact_item(item) for item in finding.get("items", [])]
        redacted[key] = {**finding, "items": redacted_items}
    return redacted

def redact_apps(apps):
    """
    Walk all apps and redact email addresses from user login fields.
    Used when --redact flag is set.
    Names are not redacted — needed for remediation.
    """
    redacted = []
    for app in apps:
        redacted_users = []
        for user in app.get("users", []):
            redacted_user = dict(user)
            if "login" in redacted_user:
                redacted_user["login"] = redact_email(str(redacted_user["login"]))
            redacted_users.append(redacted_user)
        redacted_app = dict(app)
        redacted_app["users"] = redacted_users
        redacted.append(redacted_app)
    return redacted

def format_datetime(dt_string):
    """
    Normalize Okta's ISO 8601 timestamps to YYYY-MM-DD.
    Returns 'Never' for None or empty.
    """
    if not dt_string:
        return "Never"
    try:
        # Okta returns: 2024-01-15T10:30:00.000Z
        return dt_string[:10]
    except Exception:
        return str(dt_string)