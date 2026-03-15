#!/usr/bin/env python3
"""

modules/connector.py
Okta API client. Handles auth, pagination, and rate limiting.
All API communication goes through this class.

"""

import time
import requests

class OktaConnector:
    def __init__(self, domain, token):
        self.domain   = domain
        self.token    = token
        self.base_url = f"https://{domain}/api/v1"
        self.headers  = {
            "Authorization": f"SSWS {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    def test_connection(self):
        """
        Verify the token is valid and the domain is reachable.
        Hits /users/me. 

        Requires at least Read-Only Admin.
        
        Returns True on success, False on failure.
        """
        try:
            resp = self._get_raw("/users/me")
            if resp.status_code == 200:
                data = resp.json()
                login = data.get("profile", {}).get("login", "unknown")
                print(f"[+] Connected as: {login}")
                return True
            elif resp.status_code == 401:
                print(f"[-] Invalid token. Check OKTA_TOKEN in .env")
                return False
            elif resp.status_code == 403:
                print(f"[-] Token lacks required permissions. Need Read-Only Admin or higher")
                return False
            else:
                print(f"[-] Unexpected response: {resp.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"[-] Could not connect to {self.domain}. Check OKTA_DOMAIN in .env")
            return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
        
    def _get_raw(self, endpoint):
        """
        Single raw GET: returns the full response object.
        Used internally for test_connection and single-item fetches.
        """
        url = f"{self.base_url}{endpoint}"
        resp = requests.get(url, headers=self.headers)
        self._check_rate_limit(resp)
        return resp

    def get(self, endpoint, params=None):
        """
        Single GET: returns parsed JSON or empty dict on error.
        Use for endpoints that return a single object.
        """
        url  = f"{self.base_url}{endpoint}"
        resp = requests.get(url, headers=self.headers, params=params or {})
        self._check_rate_limit(resp)
        if resp.status_code == 200:
            return resp.json()
        return {}
    
    def get_all(self, endpoint, params=None):
        """
        Paginated GET: walks all pages via Okta's Link header.
        Returns a flat list of all results across all pages.
        Okta returns max 200 items per page.
        """
        results = []
        url     = f"{self.base_url}{endpoint}"
        p       = {"limit": 200, **(params or {})}

        while url:
            resp = requests.get(url, headers=self.headers, params=p)
            self._check_rate_limit(resp)

            if resp.status_code in (403, 405):
                print(f"[-] {endpoint} not available on this plan; skipping.")
                break
            if resp.status_code != 200:
                print(f"[-] API error on {endpoint}: {resp.status_code} {resp.text[:200]}")
                break

            results.extend(resp.json())

            #Okta signals next page via Link header
            #Link: <https://...>; rel="next"
            url = self._next_page(resp)
            p   = {}  #params only on first request, URL encodes them after

        return results

    def get_logs(self, params=None):
        """
        Paginated GET for /logs endpoint.
        Uses a higher rate limit threshold than get_all() because
        Okta applies stricter limits to system log queries.
        Sleeps earlier to avoid hammering the log endpoint.
        """
        results = []
        url     = f"{self.base_url}/logs"
        p       = {"limit": 100, **(params or {})}

        while url:
            resp = requests.get(url, headers=self.headers, params=p)
            self._check_rate_limit(resp, threshold=10)

            if resp.status_code in (403, 405):
                print(f"[-] /logs not available; skipping.")
                break
            if resp.status_code != 200:
                print(f"[-] Log query failed: {resp.status_code} {resp.text[:200]}")
                break

            batch = resp.json()
            if not batch:
                break

            results.extend(batch)
            url = self._next_page(resp)
            p   = {}

        return results

    def _next_page(self, resp):
        """
        Parse Okta's Link header to get the next page URL.
        Returns None if there are no more pages.
        """
        link_header = resp.headers.get("Link", "")
        for part in link_header.split(","):
            if 'rel="next"' in part:
                #extract URL from: <https://...>; rel="next"
                url = part.strip().split(";")[0].strip()
                return url.lstrip("<").rstrip(">")
        return None
    
    def _check_rate_limit(self, resp, threshold=2):
        """
        Check Okta's rate limit headers and sleep if we're close to the limit.
        Okta resets limits every 60 seconds.
        Headers: X-Rate-Limit-Remaining, X-Rate-Limit-Reset
        threshold: sleep when remaining requests falls to this level.
                   Default 2 for normal endpoints, use 10 for /logs.
        """
        remaining = resp.headers.get("X-Rate-Limit-Remaining")
        reset     = resp.headers.get("X-Rate-Limit-Reset")

        if remaining is None:
            return

        remaining = int(remaining)

        if remaining <= threshold:
            if reset:
                #Reset is a Unix timestamp; sleep until then + 1s buffer
                sleep_secs = max(1, int(reset) - int(time.time()) + 1)
                print(f"[!] Rate limit nearly exceeded. waiting {sleep_secs}s...")
                time.sleep(sleep_secs)
            else:
                print(f"[!] Rate limit nearly exceeded. waiting 10s...")
                time.sleep(10)
