#!/usr/bin/env python3
"""
Reddit Auto-Poster for HECI Spy research.
Posts to multiple subreddits using Reddit's API (no external packages).

Usage:
  1. Go to https://www.reddit.com/prefs/apps
  2. Click "create app" -> choose "script"
  3. Fill in the CLIENT_ID, SECRET, USERNAME, PASSWORD below
  4. Run: python reddit_poster.py
"""

import urllib.request, urllib.parse, json, sys, base64, time

# ============================================================================
# CONFIGURE THESE (fill from https://www.reddit.com/prefs/apps)
# ============================================================================
CLIENT_ID = ""       # The string under "personal use script"
SECRET = ""          # The secret key
USERNAME = ""        # Your Reddit username
PASSWORD = ""        # Your Reddit password

USER_AGENT = "HECISpyResearch/1.0 (by /u/" + USERNAME + ")"

SUBREDDITS = [
    "netsec",
    "ReverseEngineering",
    "hacking",
]

POST_TITLE = "I reverse-engineered Intel's HECI protocol and built a Python tool that talks to the ME directly"

POST_CONTENT = """Every Intel laptop has a Management Engine - a hidden coprocessor that runs independently of the CPU. It has its own OS (ARC EM), network stack, and encrypted filesystem. Intel's official tools to talk to it are locked behind NDAs.

I reverse-engineered the HECI/MKHI protocol from the Windows driver and built a zero-dependency Python script that connects to the ME directly.

What I found:

- MKHI v3.1 confirmed (first public documentation on CSME 16.x hardware)
- 8 internal partitions with versions + encryption status decoded live
- GEN.1B leaks a dynamic memory value that changes every run (memory leak)
- SPI flash is completely blocked on production firmware (all read/write/erase hang)
- Consumer SKU has 0 remote management exposure (AMT disabled)

The tool is one file, zero dependencies:
https://github.com/Jatinkapilaq1/intel-me-research

Just run: python heci_spy.py (Windows admin required)

Full 21-slide presentation with all evidence:
https://jatinkapilaq1.github.io/intel-me-research/evidence/PRESENTATION.html

30-second demo video in the repo. Report saves with #HECISpy.

No NDAs, no corporate tools, no expensive hardware. Just Python and a laptop."""

# ============================================================================
# DON'T CHANGE BELOW THIS LINE
# ============================================================================

def get_token():
    auth = base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "username": USERNAME,
        "password": PASSWORD,
    }).encode()
    req = urllib.request.Request(
        "https://www.reddit.com/api/v1/access_token",
        data=data,
        headers={
            "Authorization": f"Basic {auth}",
            "User-Agent": USER_AGENT,
        },
    )
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())["access_token"]

def post_to_reddit(token, subreddit, title, content):
    data = urllib.parse.urlencode({
        "api_type": "json",
        "kind": "self",
        "sr": subreddit,
        "title": title,
        "text": content,
    }).encode()
    req = urllib.request.Request(
        f"https://oauth.reddit.com/api/submit",
        data=data,
        headers={
            "Authorization": f"bearer {token}",
            "User-Agent": USER_AGENT,
        },
    )
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    if result.get("json", {}).get("errors"):
        return False, result["json"]["errors"]
    url = result["json"]["data"]["url"]
    return True, url

def main():
    # Validate config
    if not CLIENT_ID or not SECRET or USERNAME == "" or PASSWORD == "":
        print("[-] Fill in CLIENT_ID, SECRET, USERNAME, PASSWORD at the top of this script first.")
        print("    Get them from: https://www.reddit.com/prefs/apps")
        sys.exit(1)

    print("[*] Getting Reddit API token...")
    try:
        token = get_token()
        print("[+] Token obtained successfully")
    except Exception as e:
        print(f"[-] Failed to get token: {e}")
        print("    Check your CLIENT_ID, SECRET, USERNAME, PASSWORD are correct.")
        sys.exit(1)

    for sub in SUBREDDITS:
        print(f"[*] Posting to r/{sub}...")
        try:
            success, result = post_to_reddit(token, sub, POST_TITLE, POST_CONTENT)
            if success:
                print(f"  [+] Posted: {result}")
            else:
                print(f"  [-] Failed: {result}")
        except Exception as e:
            print(f"  [-] Error: {e}")

        # Rate limit: 1 post per 10 minutes between subreddits
        if sub != SUBREDDITS[-1]:
            print("  [*] Waiting 10 minutes before next post (Reddit rate limit)...")
            time.sleep(600)

    print("\n[+] Done! Check your Reddit account.")

if __name__ == "__main__":
    main()
