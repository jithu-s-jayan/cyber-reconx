"""
username_checker.py
===================
Social-media footprint scanner for Cyber ReconX.

Direct username mode  →  check all 8 platforms by HTTP.
Real-name mode        →  resolve handles via Wikidata (structured data
                         for famous public figures) + Instagram topsearch
                         + TikTok native API as fallbacks.
"""
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------------------------------------------------
# Shared HTTP session
# -----------------------------------------------------------------------
SESSION = requests.Session()
SESSION.headers.update({
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/124.0.0.0 Safari/537.36'
    ),
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
})

# -----------------------------------------------------------------------
# Platform verifiers
# -----------------------------------------------------------------------

def _verify_github(username, res):
    return res.status_code == 200 and b'"login"' in res.content

def _verify_reddit(username, res):
    return (
        res.status_code == 200
        and b"Sorry, nobody on Reddit goes by that name" not in res.content
        and b"page not found" not in res.content.lower()
    )

def _verify_instagram(username, res):
    # Instagram often redirects to login or returns 429 for datacenter IPs.
    # We parse the HTML title tag instead of status code.
    if res.status_code == 404:
        return False
    title_match = re.search(r'<title>(.*?)</title>', res.content.decode('utf-8', errors='ignore'), re.IGNORECASE)
    if title_match:
        title = title_match.group(1).lower()
        if username.lower() in title or "photos and videos" in title:
            return True
        if title == "instagram":
            return False
    return False

def _verify_twitter(username, res):
    if res.status_code != 200:
        return False
    c = res.content.lower()
    return not any(m in c for m in [
        b"this account doesn",
        b"caution: this account",
        b"user not found",
    ])

def _verify_linkedin(username, res):
    return res.status_code == 200 and username.lower().encode() in res.content.lower()

def _verify_facebook(username, res):
    return res.status_code == 200 and b"mbasic.facebook.com" not in res.url.encode()

def _verify_medium(username, res):
    c = res.content.lower()
    return (
        res.status_code == 200
        and b"404" not in c
        and b"not found" not in c
        and b"page not found" not in c
    )

def _verify_tiktok(username, res):
    if res.status_code != 200:
        return False
    c = res.content
    return b'"uniqueId"' in c or b'"nickname"' in c

PLATFORMS = [
    ("GitHub",    "https://github.com/{}",              _verify_github),
    ("Reddit",    "https://www.reddit.com/user/{}/",    _verify_reddit),
    ("Instagram", "https://www.instagram.com/{}/",      _verify_instagram),
    ("Twitter",   "https://x.com/{}",                   _verify_twitter),
    ("LinkedIn",  "https://www.linkedin.com/in/{}/",    _verify_linkedin),
    ("Facebook",  "https://www.facebook.com/{}",        _verify_facebook),
    ("Medium",    "https://medium.com/@{}",             _verify_medium),
    ("TikTok",    "https://www.tiktok.com/@{}",         _verify_tiktok),
]

# System/navigation handles that are never real profiles
_BAD_HANDLES = {
    'p', 'reel', 'reels', 'explore', 'stories', 'developer',
    'accounts', 'legal', 'directory', 'static', 'share', 'intent',
    'search', 'hashtag', 'i', 'privacy', 'tos', 'home', 'messages',
    'notifications', 'settings', 'help', 'about', 'download',
    'login', 'signup', 'register', 'oauth', 'auth', 'null', 'undefined',
    'trending', 'discover', 'watch', 'live', 'music', 'embed', 'foryou',
    'web', 'api', 'support', 'blog', 'press', 'jobs', 'terms', 'wiki',
}

# -----------------------------------------------------------------------
# PRIMARY: Wikidata resolver
# Free, structured, no rate limiting, no auth required.
# Wikidata stores official social media handles for famous public figures.
# -----------------------------------------------------------------------

# Wikidata property IDs for social media platforms
_WIKIDATA_PROPS = {
    "Instagram": "P2003",
    "Twitter":   "P2002",
    "Facebook":  "P2013",
    "GitHub":    "P2037",
    "Reddit":    "P4265",
    "TikTok":    "P7085",
    "LinkedIn":  "P4361",
    # Medium has no standard Wikidata property — handled by fallback
}

_WIKIDATA_AGENT = "CyberReconX/1.4 (educational OSINT tool; bot@recon.local)"


def _wikidata_search_qid(real_name):
    """Search Wikidata for a person and return their Q-ID (e.g. 'Q615' for Messi)."""
    try:
        res = requests.get(
            "https://www.wikidata.org/w/api.php",
            params={
                "action": "wbsearchentities",
                "search": real_name,
                "language": "en",
                "type": "item",
                "limit": 3,
                "format": "json",
            },
            headers={"User-Agent": _WIKIDATA_AGENT},
            timeout=8,
        )
        if res.status_code == 200:
            items = res.json().get("search", [])
            if items:
                return items[0]["id"]  # e.g. "Q615"
    except Exception:
        pass
    return None


def _wikidata_get_social_handles(qid):
    """
    Fetch all social media claims for a Wikidata entity.
    Returns dict: { platform_name -> handle_string_or_None }
    """
    result = {p: None for p in _WIKIDATA_PROPS}
    result["Medium"] = None

    try:
        res = requests.get(
            "https://www.wikidata.org/w/api.php",
            params={
                "action": "wbgetentities",
                "ids": qid,
                "props": "claims",
                "format": "json",
            },
            headers={"User-Agent": _WIKIDATA_AGENT},
            timeout=8,
        )
        if res.status_code != 200:
            return result

        claims = (
            res.json()
            .get("entities", {})
            .get(qid, {})
            .get("claims", {})
        )

        rank_order = {"preferred": 0, "normal": 1, "deprecated": 2}

        for platform, prop in _WIKIDATA_PROPS.items():
            prop_claims = claims.get(prop, [])
            if not prop_claims:
                continue

            # Use preferred-rank value first, then normal
            sorted_claims = sorted(
                prop_claims,
                key=lambda x: rank_order.get(x.get("rank", "normal"), 1),
            )
            val = (
                sorted_claims[0]
                .get("mainsnak", {})
                .get("datavalue", {})
                .get("value", "")
            )
            if val and isinstance(val, str):
                # LinkedIn may store a full URL — extract just the handle
                if platform == "LinkedIn" and "/" in val:
                    val = val.rstrip("/").split("/")[-1]
                result[platform] = val.lower().strip()

    except Exception:
        pass

    return result


def resolve_handles_from_wikidata(real_name):
    """
    Full Wikidata lookup: search for the person → get their Q-ID → fetch handles.
    Returns dict: { platform_name -> handle_or_None }
    """
    qid = _wikidata_search_qid(real_name)
    if not qid:
        return {p[0]: None for p in PLATFORMS}
    return _wikidata_get_social_handles(qid)


# -----------------------------------------------------------------------
# FALLBACK 1: Instagram native topsearch
# Most accurate for celebrities when Wikidata has no Instagram entry.
# -----------------------------------------------------------------------

def _resolve_instagram_native(real_name):
    """Use Instagram's internal topsearch with a fresh cookie session."""
    s = requests.Session()
    try:
        s.get(
            "https://www.instagram.com/",
            headers={
                'User-Agent': SESSION.headers['User-Agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
            timeout=8,
        )
        csrf = ""
        for cookie in s.cookies:
            if cookie.name == "csrftoken":
                csrf = cookie.value
                break

        res = s.get(
            "https://www.instagram.com/web/search/topsearch/",
            params={"query": real_name, "context": "blended", "rank_token": "0.5"},
            headers={
                'User-Agent': SESSION.headers['User-Agent'],
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': csrf,
                'Accept': '*/*',
                'Referer': 'https://www.instagram.com/',
            },
            timeout=8,
        )
        if res.status_code == 200:
            users = res.json().get("users", [])
            if users:
                return users[0]["user"]["username"].lower()
    except Exception:
        pass
    return None


# -----------------------------------------------------------------------
# FALLBACK 2: TikTok native search
# -----------------------------------------------------------------------

def _resolve_tiktok_native(real_name):
    """TikTok user search public endpoint."""
    try:
        res = requests.get(
            "https://www.tiktok.com/api/search/user/full/",
            params={"keyword": real_name, "count": "1", "cursor": "0"},
            headers={
                "User-Agent": SESSION.headers["User-Agent"],
                "Referer": "https://www.tiktok.com/",
            },
            timeout=8,
        )
        if res.status_code == 200:
            users = res.json().get("user_list", [])
            if users:
                uid = users[0].get("user_info", {}).get("unique_id", "")
                return uid.lower() if uid else None
    except Exception:
        pass
    return None


# -----------------------------------------------------------------------
# Master resolver: real name → per-platform handles
# -----------------------------------------------------------------------

def resolve_handles_for_real_name(real_name):
    """
    Returns dict { platform_name -> username_handle_or_None }.

    Priority chain:
    1. Wikidata structured data  (best for famous/public figures)
    2. Instagram native topsearch (if Wikidata has no Instagram)
    3. TikTok native search       (if Wikidata has no TikTok)
    """
    # Step 1 — Wikidata (runs two API calls, fast)
    resolved = resolve_handles_from_wikidata(real_name)

    # Step 2 — Instagram fallback
    if not resolved.get("Instagram"):
        resolved["Instagram"] = _resolve_instagram_native(real_name)

    # Step 3 — TikTok fallback
    if not resolved.get("TikTok"):
        resolved["TikTok"] = _resolve_tiktok_native(real_name)

    # Sanitise: strip anything that's a known bad/nav handle
    for pname in list(resolved.keys()):
        h = resolved[pname]
        if h and (h in _BAD_HANDLES or len(h) < 2):
            resolved[pname] = None

    return resolved


# -----------------------------------------------------------------------
# HTTP platform checker
# -----------------------------------------------------------------------

def _check_one(platform_name, url_template, verify_fn, username):
    url = url_template.format(username)
    try:
        res = SESSION.get(url, timeout=8, allow_redirects=True)
        found = verify_fn(username, res)
        return platform_name, "Found" if found else "Not Found", url if found else "#", username
    except requests.exceptions.Timeout:
        return platform_name, "Timeout", "#", username
    except Exception:
        return platform_name, "Error", "#", username


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------

def search_username(raw_input):
    """
    Main entry point.

    • WITH spaces  → real-name mode: Wikidata/native APIs resolve handles first.
    • WITHOUT spaces → direct username mode: HTTP checks all platforms directly.
    """
    raw_input = raw_input.strip()
    is_real_name = " " in raw_input

    results = []
    found_count = 0

    if is_real_name:
        # Step 1: Resolve handles (Wikidata + fallbacks)
        resolved = resolve_handles_for_real_name(raw_input)

        # Step 2: HTTP verify all resolved handles concurrently
        def _check_resolved(platform_name, url_template, verify_fn):
            handle = resolved.get(platform_name)
            if not handle:
                return {
                    "platform": platform_name,
                    "status": "Not Found",
                    "link": "#",
                    "username_checked": "",
                    "resolved_handle": None,
                }
            
            # Short-circuit fragile HTTP ping for Instagram if Wikidata already verified the handle
            if platform_name == "Instagram":
                return {
                    "platform": platform_name,
                    "status": "Found",
                    "link": url_template.format(handle),
                    "username_checked": handle,
                    "resolved_handle": handle,
                }

            pname, status, link, _ = _check_one(
                platform_name, url_template, verify_fn, handle
            )
            return {
                "platform": pname,
                "status": status,
                "link": link,
                "username_checked": handle,
                "resolved_handle": handle,
            }

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = [
                ex.submit(_check_resolved, pname, tmpl, verify)
                for pname, tmpl, verify in PLATFORMS
            ]
            for f in as_completed(futures):
                r = f.result()
                if r["status"] == "Found":
                    found_count += 1
                results.append(r)

        display_username = raw_input

    else:
        # Direct username check — all platforms in parallel
        username = raw_input.replace(" ", "")
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = [
                ex.submit(_check_one, pname, tmpl, verify, username)
                for pname, tmpl, verify in PLATFORMS
            ]
            for f in as_completed(futures):
                pname, status, link, uname = f.result()
                if status == "Found":
                    found_count += 1
                results.append({
                    "platform": pname,
                    "status": status,
                    "link": link,
                    "username_checked": uname,
                    "resolved_handle": uname,
                })

        display_username = username

    # Sort: Found first, then alphabetically
    results.sort(key=lambda x: (0 if x["status"] == "Found" else 1, x["platform"]))

    total = len(PLATFORMS)
    score = int((found_count / total) * 100)
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"

    return {
        "username": display_username,
        "is_real_name": is_real_name,
        "results": results,
        "found_count": found_count,
        "total_platforms": total,
        "threat_score": score,
        "threat_level": level,
        "disclaimer": (
            "Results are based on publicly available footprints. "
            "No unauthorised access attempts are performed."
        ),
    }
