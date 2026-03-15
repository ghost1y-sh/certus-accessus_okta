#!/usr/bin/env python3
"""

modules/collector.py
Collects all Okta data needed for access certification.

One structured pass through the Okta API:
1. All users; profile, department, title, last login
2. All active apps; name, sign-on mode
3. Per-app user assignments; who has access and since when
4. Per-app access logs; when each user last used each app

Output: a list of app objects, each containing enriched user objects.
This is the data structure passed directly to analyzer.py.

"""

import time
from datetime import datetime, timezone, timedelta
from modules.utils import format_datetime


#Apps to skip; Okta internal apps that aren't real user-facing integrations
OKTA_INTERNAL_APPS = {
    "okta_enduser",
    "okta_admin_console",
    "Okta Dashboard",
    "Okta Admin Console",
    "Okta Browser Plugin",
}

#How far back to query the system log for app access events
ACCESS_LOG_DAYS = 180

#Batch size for app processing; pause between batches to respect rate limits
BATCH_SIZE  = 20
BATCH_SLEEP = 2


class OktaCollector:
    def __init__(self, connector):
        self.connector = connector
        self.users     = {}   #user_id -> user profile dict
        self.apps      = []   #list of enriched app dicts

    def collect_all(self, skip_access_log=False):
        """
        Main entry point. Runs all collection steps in order.
        Returns a list of app dicts ready for analyzer.py.

        skip_access_log=True skips system log queries; faster but
        last_app_access will be 'Unknown' for all users.
        """
        print(f"[*] Collecting users...")
        self._collect_users()
        print(f"    done; {len(self.users):,} users loaded\n")

        print(f"[*] Collecting apps...")
        self._collect_apps()
        print(f"    done; {len(self.apps):,} apps loaded\n")

        print(f"[*] Collecting app assignments...")
        self._collect_app_assignments()
        print()

        if not skip_access_log:
            print(f"[*] Collecting app access logs...")
            self._collect_access_logs()
            print()
        else:
            print(f"[!] Skipping access log collection (--no-access-log)\n")

        return self.apps

    #------------------------------------------------------------------ #
    # STEP 1; Users                                                     #
    #------------------------------------------------------------------ #
    def _collect_users(self):
        """
        Fetch all users and build a lookup dict keyed by user ID.
        We fetch all statuses so we catch staged/deprovisioned users
        who may still have app assignments.
        """
        raw_users = self.connector.get_all("/users")

        for u in raw_users:
            uid     = u.get("id")
            profile = u.get("profile", {})

            self.users[uid] = {
                "id":         uid,
                "login":      profile.get("login", "unknown"),
                "name":       f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
                "department": profile.get("department", "Unknown"),
                "title":      profile.get("title", "Unknown"),
                "status":     u.get("status", "UNKNOWN"),
                "last_login": format_datetime(u.get("lastLogin")),
                "created":    format_datetime(u.get("created")),
            }

    #------------------------------------------------------------------ #
    # STEP 2; Apps                                                      #
    #------------------------------------------------------------------ #
    def _collect_apps(self):
        """
        Fetch all active app integrations and filter out Okta internals.
        Stores minimal app metadata; assignments added in step 3.
        """
        raw_apps = self.connector.get_all(
            "/apps", params={"filter": 'status eq "ACTIVE"'}
        )

        for app in raw_apps:
            name = app.get("label", "") or app.get("name", "")

           #Skip Okta internal apps
            if name in OKTA_INTERNAL_APPS:
                continue
            if app.get("name") in OKTA_INTERNAL_APPS:
                continue

            self.apps.append({
                "id":           app.get("id"),
                "name":         name,
                "sign_on_mode": app.get("signOnMode", "UNKNOWN"),
                "users":        [],   #populated in step 3
            })

    #------------------------------------------------------------------ #
    # STEP 3; App Assignments                                           #
    #------------------------------------------------------------------ #
    def _collect_app_assignments(self):
        """
        For each app, fetch the list of assigned users and enrich
        each user with their profile data from the users dict.

        Calculates days_assigned from the assignment created date.
        Processes apps in batches to respect rate limits.
        """
        total    = len(self.apps)
        now      = datetime.now(timezone.utc)

        for i, app in enumerate(self.apps, 1):
           #Progress indicator
            bar   = self._progress_bar(i, total)
            print(f"\r    {bar} {i}/{total} apps", end="", flush=True)

           #Fetch users assigned to this app
            assigned = self.connector.get_all(f"/apps/{app['id']}/users")

            for assignment in assigned:
                uid = assignment.get("id")
                if not uid or uid not in self.users:
                    continue

                user_profile = self.users[uid]

               #Calculate how long they've had access
                created_str   = assignment.get("created")
                days_assigned = self._days_since(created_str, now)
                assigned_date = format_datetime(created_str)

                app["users"].append({
                    **user_profile,         #copy all profile fields
                    "assigned_date":   assigned_date,
                    "days_assigned":   days_assigned,
                    "last_app_access": "Unknown",  #populated in step 4
                })

           #Batch sleep every BATCH_SIZE apps
            if i % BATCH_SIZE == 0 and i < total:
                time.sleep(BATCH_SLEEP)

    #------------------------------------------------------------------ #
    # STEP 4; Access Logs                                               #
    #------------------------------------------------------------------ #
    def _collect_access_logs(self):
        """
        Query the system log for app-specific authentication events.
        Uses app.user.sso.initiated events filtered by app ID.

        Okta doesn't have a clean "last accessed app X" endpoint so
        we derive it from the system log. We look back ACCESS_LOG_DAYS
        days; anything older is treated as "Never" for our purposes.

        This is the most expensive step rate-limit wise; uses get_logs()
        which has a higher sleep threshold than get_all().
        """
        total = len(self.apps)
        since = (
            datetime.now(timezone.utc) - timedelta(days=ACCESS_LOG_DAYS)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for i, app in enumerate(self.apps, 1):
           #Skip apps with no assigned users
            if not app["users"]:
                continue

            bar = self._progress_bar(i, total)
            print(f"\r    {bar} {i}/{total} apps", end="", flush=True)

           #Query system log for SSO events for this app
            events = self.connector.get_logs(params={
                "filter": (
                    f'eventType eq "app.user.sso.initiated" '
                    f'and target.id eq "{app["id"]}"'
                ),
                "since": since,
            })

           #Build a map of user_id -> most recent access date
            last_access_by_user = {}
            for event in events:
               #The actor is the user who authenticated
                actor    = event.get("actor", {})
                uid      = actor.get("id")
                pub_time = event.get("published")
                if not uid or not pub_time:
                    continue
               #Keep the most recent event per user
                if uid not in last_access_by_user or pub_time > last_access_by_user[uid]:
                    last_access_by_user[uid] = pub_time

           #Attach last_app_access back to each user in this app
            for user in app["users"]:
                uid = user.get("id")
                if uid in last_access_by_user:
                    user["last_app_access"] = format_datetime(
                        last_access_by_user[uid]
                    )
                else:
                   #Not found in logs; either never used or older than 180 days
                    user["last_app_access"] = f"Not in last {ACCESS_LOG_DAYS} days"

           #Batch sleep
            if i % BATCH_SIZE == 0 and i < total:
                time.sleep(BATCH_SLEEP)

    #------------------------------------------------------------------ #
    # Helpers                                                            #
    #------------------------------------------------------------------ #
    def _days_since(self, date_str, now):
        """
        Calculate number of days between a date string and now.
        Returns 0 if date is unparseable.
        """
        if not date_str:
            return 0
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return (now - dt).days
        except Exception:
            return 0

    def _progress_bar(self, current, total, width=20):
        """
        Simple ASCII progress bar.
        [##########----------] 10/20
        """
        filled = int((current / total) * width)
        empty  = width - filled
        return f"[{'█' * filled}{'░' * empty}]"