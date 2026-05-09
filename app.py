import os
import re
import time
import json
import requests
import threading
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="static")
CORS(app)

TIMEOUT = 20

# ── Helpers ────────────────────────────────────────────────────────────────

def get_domain(url):
    try:
        return urlparse(url).hostname
    except:
        return url

def fetch_page(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, headers={
            "User-Agent": "Mozilla/5.0 (compatible; AtlasSecurecheck/2.0)"
        }, allow_redirects=True)
        return r.text
    except:
        return None

def detect_privacy(html):
    patterns = [
        r"privacy[\s\-]*policy",
        r"privacy\s+notice",
        r"data\s+protection\s+policy",
        r"ndpr",
        r"href=[\"'][^\"']*privac[^\"']*[\"']",
    ]
    return any(re.search(p, html, re.IGNORECASE) for p in patterns)

def detect_cookie(html):
    patterns = [
        r"cookieyes", r"cookiebot", r"onetrust", r"complianz", r"iubenda",
        r"cookie\s*consent", r"we\s+use\s+cookies",
        r"accept\s+(all\s+)?cookies", r"cookie\s*preferences",
        r"cookie\s*notice", r"cookie\s*banner",
    ]
    return any(re.search(p, html, re.IGNORECASE) for p in patterns)

def detect_cms(html):
    cms_patterns = {
        "WordPress": [r"wp-content/", r"wp-includes/"],
        "Joomla":    [r"/components/com_"],
        "Drupal":    [r"Drupal\.settings"],
        "Shopify":   [r"cdn\.shopify\.com"],
        "Wix":       [r"static\.wixstatic\.com"],
    }
    for name, pats in cms_patterns.items():
        if any(re.search(p, html, re.IGNORECASE) for p in pats):
            version_exposed = bool(re.search(
                r"<meta[^>]+generator[^>]+\d+\.\d+|WordPress\s+\d+\.\d+", html, re.IGNORECASE
            ))
            return {"detected": name, "version_exposed": version_exposed}
    return {"detected": None, "version_exposed": False}

def detect_mixed(html, is_https):
    if not is_https:
        return False
    html_no_comments = re.sub(r"<!--[\s\S]*?-->", "", html)
    return bool(re.search(r'(?:src|href|action)=["\']http://(?!localhost)[^"\']+["\']', html_no_comments))

def detect_forms(html, is_https):
    forms = re.findall(r"<form[^>]*>", html, re.IGNORECASE)
    insecure = [f for f in forms if re.search(r'action=["\']http://', f, re.IGNORECASE)]
    return {"has_forms": len(forms) > 0, "has_insecure_forms": len(insecure) > 0}

def extract_links(html, base_url):
    links = []
    base = urlparse(base_url)
    for href in re.findall(r'href=["\']([^"\']+)["\']', html):
        try:
            parsed = urlparse(href)
            if not parsed.scheme:
                href = base.scheme + "://" + base.netloc + (href if href.startswith("/") else "/" + href)
                parsed = urlparse(href)
            if parsed.netloc == base.netloc:
                links.append(href)
        except:
            pass
    return links

# ── API checks ─────────────────────────────────────────────────────────────

def check_observatory(domain):
    try:
        r = requests.post(
            f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={domain}",
            timeout=30
        )
        if not r.ok:
            return None
        data = r.json()
        if data.get("error"):
            return None
        return {
            "grade": data.get("grade"),
            "score": data.get("score"),
            "tests_failed": data.get("tests_failed"),
            "tests_passed": data.get("tests_quantity", 0) - data.get("tests_failed", 0),
            "tests_total": data.get("tests_quantity"),
        }
    except:
        return None

def check_ssl_labs(domain):
    try:
        # Check cache first — returns instantly if already scanned recently
        poll_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"
        r = requests.get(poll_url, timeout=15)
        if r.ok:
            data = r.json()
            if data.get("status") == "READY" and data.get("endpoints"):
                ep = data["endpoints"][0]
                return {
                    "grade": ep.get("grade") or ep.get("gradeTrust") or "T",
                    "ip": ep.get("ipAddress"),
                    "has_warnings": ep.get("hasWarnings", False),
                    "is_exceptional": ep.get("isExceptional", False),
                    "cached": True
                }

        # Not cached — start new scan
        start_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&startNew=on&all=done&ignoreMismatch=on"
        requests.get(start_url, timeout=15)
        time.sleep(8)

        for attempt in range(20):
            r = requests.get(poll_url, timeout=15)
            if not r.ok:
                time.sleep(6)
                continue
            data = r.json()
            if data.get("status") == "ERROR":
                return None
            if data.get("status") == "READY" and data.get("endpoints"):
                ep = data["endpoints"][0]
                return {
                    "grade": ep.get("grade") or ep.get("gradeTrust") or "T",
                    "ip": ep.get("ipAddress"),
                    "has_warnings": ep.get("hasWarnings", False),
                    "is_exceptional": ep.get("isExceptional", False),
                }
            time.sleep(6)
        return None
    except:
        return None

def check_urlscan(url):
    """URLScan requires an API key when called from a server IP."""
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "")
    if not urlscan_key:
        # Return a special marker so frontend can show friendly message
        return {"no_key": True}

    try:
        domain = get_domain(url)
        headers = {
            "Content-Type": "application/json",
            "API-Key": urlscan_key
        }

        # Search for existing results first
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1",
            headers={"API-Key": urlscan_key},
            timeout=15
        )
        if r.ok:
            data = r.json()
            results = data.get("results", [])
            if results:
                scan_id = results[0].get("_id")
                r2 = requests.get(
                    f"https://urlscan.io/api/v1/result/{scan_id}/",
                    headers={"API-Key": urlscan_key},
                    timeout=15
                )
                if r2.ok:
                    return parse_urlscan_result(r2.json())

        # No existing result — submit new scan
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "unlisted"},
            timeout=15
        )
        if not submit.ok:
            return None

        scan_id = submit.json().get("uuid")
        if not scan_id:
            return None

        time.sleep(20)
        for _ in range(6):
            r3 = requests.get(
                f"https://urlscan.io/api/v1/result/{scan_id}/",
                headers={"API-Key": urlscan_key},
                timeout=15
            )
            if r3.ok:
                return parse_urlscan_result(r3.json())
            time.sleep(8)
        return None
    except:
        return None

def parse_urlscan_result(data):
    verdicts = data.get("verdicts", {}).get("overall", {})
    malicious = verdicts.get("malicious", False)
    score = verdicts.get("score", 0)
    stats = data.get("stats", {})
    return {
        "malicious": malicious,
        "score": score,
        "requests": stats.get("requests", 0),
        "domains": stats.get("uniqDomains", 0),
        "tags": data.get("tags", []),
        "report_url": data.get("task", {}).get("reportURL", ""),
    }

def check_gsb(url, api_key):
    if not api_key:
        return None
    try:
        body = {
            "client": {"clientId": "atlas-securecheck", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body, timeout=15
        )
        if not r.ok:
            return None
        matches = r.json().get("matches", [])
        return {
            "clean": len(matches) == 0,
            "threats": [m.get("threatType") for m in matches]
        }
    except:
        return None

# ── Main scan endpoint ─────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json or {}
    url = data.get("url", "").strip()
    gsb_key = data.get("gsb_key", "") or os.environ.get("GSB_API_KEY", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith("http"):
        url = "https://" + url

    domain = get_domain(url)
    is_https = url.startswith("https://")

    # ── Built-in checks ──
    home_html = fetch_page(url)
    fetch_ok = home_html is not None

    has_privacy = False
    if fetch_ok:
        has_privacy = detect_privacy(home_html)
        if not has_privacy:
            # Check subpages
            links = extract_links(home_html, url)
            privacy_links = [l for l in links if re.search(r"privac|data-protect|legal", l, re.I)][:3]
            for link in privacy_links:
                sub = fetch_page(link)
                if sub and detect_privacy(sub):
                    has_privacy = True
                    break
            if not has_privacy:
                for path in ["/privacy-policy", "/privacy", "/data-protection"]:
                    sub = fetch_page(f"{'https' if is_https else 'http'}://{domain}{path}")
                    if sub and len(sub) > 400 and detect_privacy(sub):
                        has_privacy = True
                        break

    has_cookie = fetch_ok and detect_cookie(home_html)
    cms_result = detect_cms(home_html or "")
    has_mixed = detect_mixed(home_html or "", is_https)
    form_result = detect_forms(home_html or "", is_https)

    # ── External API checks ──
    obs = check_observatory(domain)
    ssl = check_ssl_labs(domain) if is_https else {"grade": "N/A", "no_ssl": True}
    urlscan = check_urlscan(url)
    gsb = check_gsb(url, gsb_key)

    # ── Score ──
    checks = {
        "https": {
            "pass": is_https,
            "status": "pass" if is_https else "fail",
            "note": "Site confirmed on HTTPS" if is_https else "Site running on HTTP — data sent in plain text"
        },
        "observatory": {
            "pass": obs and obs["grade"] in ["A+", "A", "A-"],
            "status": "info" if not obs else ("pass" if obs["grade"] in ["A+", "A", "A-"] else ("warn" if obs["grade"] in ["B+", "B", "B-", "C+", "C"] else "fail")),
            "note": f"Grade {obs['grade']} — {obs['tests_failed']} test(s) failed out of {obs['tests_total']}" if obs else "Observatory unavailable"
        },
        "ssl_grade": {
            "pass": ssl and ssl.get("grade") in ["A+", "A"],
            "status": "fail" if ssl and ssl.get("no_ssl") else ("info" if not ssl else ("pass" if ssl.get("grade") in ["A+", "A"] else ("warn" if ssl.get("grade") in ["A-", "B+", "B"] else "fail"))),
            "note": "No SSL certificate installed" if (ssl and ssl.get("no_ssl")) else (f"SSL grade: {ssl['grade']}" if ssl else "SSL Labs unavailable")
        },
        "urlscan": {
            "pass": urlscan is not None and not urlscan.get("malicious") and not urlscan.get("no_key"),
            "status": "info" if (not urlscan or urlscan.get("no_key")) else ("fail" if urlscan.get("malicious") else "pass"),
            "note": "Add URLSCAN_API_KEY to Render environment variables to enable this check" if (urlscan and urlscan.get("no_key")) else ("Scan unavailable" if not urlscan else (f"{'Malicious' if urlscan.get('malicious') else 'Clean'} — threat score {urlscan.get('score', 0)}/100"))
        },
        "safebrowsing": {
            "pass": gsb is not None and gsb.get("clean"),
            "status": "info" if not gsb else ("pass" if gsb.get("clean") else "fail"),
            "note": "No Google API key provided" if not gsb else ("No threats detected" if gsb.get("clean") else f"Threats: {', '.join(gsb.get('threats', []))}")
        },
        "privacy": {
            "pass": has_privacy,
            "status": "info" if not fetch_ok else ("pass" if has_privacy else "fail"),
            "note": "Could not load site" if not fetch_ok else ("Privacy policy found" if has_privacy else "No privacy policy detected")
        },
        "cookie": {
            "pass": has_cookie,
            "status": "info" if not fetch_ok else ("pass" if has_cookie else "warn"),
            "note": "Could not load site" if not fetch_ok else ("Cookie consent tool detected" if has_cookie else "No cookie consent banner found")
        },
        "cms": {
            "pass": not cms_result["version_exposed"],
            "status": "info" if not fetch_ok else ("warn" if cms_result["version_exposed"] else "pass"),
            "note": (f"{cms_result['detected']} detected — version {'exposed' if cms_result['version_exposed'] else 'hidden'}" if cms_result["detected"] else "No CMS fingerprint found")
        },
        "mixed": {
            "pass": not has_mixed,
            "status": "info" if not fetch_ok else ("fail" if has_mixed else "pass"),
            "note": "HTTP resources found on HTTPS page" if has_mixed else "No mixed content detected"
        },
    }

    weights = {"https": 18, "observatory": 20, "ssl_grade": 15, "urlscan": 15, "safebrowsing": 12, "privacy": 8, "cookie": 5, "cms": 4, "mixed": 3}
    score = 0
    for key, chk in checks.items():
        if chk["status"] == "info":
            continue
        w = weights.get(key, 5)
        if chk["pass"]:
            score += w
        elif chk["status"] == "warn":
            score += int(w * 0.35)
    score = min(100, score)

    return jsonify({
        "url": url,
        "domain": domain,
        "score": score,
        "checks": checks,
        "api_results": {
            "observatory": obs,
            "ssl": ssl,
            "urlscan": urlscan,
            "gsb": gsb,
        }
    })

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/anthropic-proxy", methods=["POST"])
def anthropic_proxy():
    data = request.json or {}
    prompt = data.get("prompt", "")
    if not prompt:
        return jsonify({"error": "No prompt"}), 400

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return jsonify({"text": "AI pitch unavailable — ANTHROPIC_API_KEY not set."}), 200

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 400,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30
        )
        if not r.ok:
            return jsonify({"text": "AI pitch generation failed."}), 200
        text = r.json()["content"][0]["text"]
        return jsonify({"text": text})
    except Exception as e:
        return jsonify({"text": "AI pitch unavailable."}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
