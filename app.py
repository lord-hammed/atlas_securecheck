import os
import re
import time
import json
import requests
import threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    urls_to_try = [url]
    if url.startswith("https://"):
        urls_to_try.append(url.replace("https://", "http://"))
    else:
        urls_to_try.append(url.replace("http://", "https://"))

    for attempt_url in urls_to_try:
        try:
            r = requests.get(attempt_url, timeout=TIMEOUT, headers=headers,
                             allow_redirects=True, verify=False)
            if r.status_code == 403:
                return "__BLOCKED__"
            if r.status_code < 400 and r.text and len(r.text) > 100:
                return r.text
        except:
            continue
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
        poll_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"
        # Check cache first
        r = requests.get(poll_url, timeout=12)
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
        # Start new scan
        start_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&startNew=on&all=done&ignoreMismatch=on"
        requests.get(start_url, timeout=12)
        time.sleep(6)
        for attempt in range(12):
            try:
                r = requests.get(poll_url, timeout=12)
                if r.ok:
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
            except Exception:
                pass
            time.sleep(7)
        return None
    except Exception:
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
    fetch_ok = home_html is not None and home_html != "__BLOCKED__"
    fetch_blocked = home_html == "__BLOCKED__"

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
                    for scheme in ["https", "http"]:
                        sub = fetch_page(f"{scheme}://{domain}{path}")
                        if sub and len(sub) > 400 and detect_privacy(sub):
                            has_privacy = True
                            break
                    if has_privacy:
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
            "note": "Site blocked server access — verify manually in browser" if fetch_blocked else ("Could not load site" if not fetch_ok else ("Privacy policy found" if has_privacy else "No privacy policy detected"))
        },
        "cookie": {
            "pass": has_cookie,
            "status": "info" if not fetch_ok else ("pass" if has_cookie else "warn"),
            "note": "Site blocked server access — verify manually in browser" if fetch_blocked else ("Could not load site" if not fetch_ok else ("Cookie consent tool detected" if has_cookie else "No cookie consent banner found"))
        },
        "cms": {
            "pass": not cms_result["version_exposed"],
            "status": "info" if not fetch_ok else ("warn" if cms_result["version_exposed"] else "pass"),
            "note": "Site blocked server access — verify manually in browser" if fetch_blocked else (f"{cms_result['detected']} detected — version {'exposed' if cms_result['version_exposed'] else 'hidden'}" if cms_result["detected"] else "No CMS fingerprint found")
        },
        "mixed": {
            "pass": not has_mixed,
            "status": "info" if not fetch_ok else ("fail" if has_mixed else "pass"),
            "note": "Site blocked server access — verify manually in browser" if fetch_blocked else ("HTTP resources found on HTTPS page" if has_mixed else "No mixed content detected")
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

# ── PDF Generation ─────────────────────────────────────────────────────────

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import Flowable
import io

W, H = A4

# Colours
INK        = colors.HexColor('#0f1117')
INK2       = colors.HexColor('#3a3f4e')
INK3       = colors.HexColor('#6b7280')
GREEN      = colors.HexColor('#00875a')
GREEN_BG   = colors.HexColor('#e6f5f0')
RED        = colors.HexColor('#c0392b')
RED_BG     = colors.HexColor('#fdf0ee')
AMBER      = colors.HexColor('#b45309')
AMBER_BG   = colors.HexColor('#fef3e2')
BLUE       = colors.HexColor('#1d4ed8')
BLUE_BG    = colors.HexColor('#eff6ff')
SURFACE    = colors.HexColor('#f8f7f4')
DARK       = colors.HexColor('#0f1117')
WHITE      = colors.white

def S(name, **kw):
    base = dict(fontName='Helvetica', fontSize=10, leading=16, textColor=INK2, spaceAfter=4)
    base.update(kw)
    return ParagraphStyle(name, **base)

class ColorRect(Flowable):
    def __init__(self, w, h, color, radius=3):
        super().__init__()
        self.width, self.height, self.color, self.radius = w, h, color, radius
    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=0)

class Divider(Flowable):
    def __init__(self, color, height=1):
        super().__init__()
        self.divColor, self.height = color, height
        self.width = 0
    def wrap(self, aw, ah):
        self.width = aw
        return aw, self.height + 6
    def draw(self):
        self.canv.setFillColor(self.divColor)
        self.canv.rect(0, 3, self.width, self.height, fill=1, stroke=0)

def bg_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(WHITE)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # Top accent bar
    canvas.setFillColor(GREEN)
    canvas.rect(0, H - 5, W, 5, fill=1, stroke=0)
    # Footer
    canvas.setFillColor(SURFACE)
    canvas.rect(0, 0, W, 16*mm, fill=1, stroke=0)
    canvas.setFillColor(INK3)
    canvas.setFont('Helvetica', 7)
    canvas.drawString(22*mm, 6*mm, 'Atlas Securecheck  ·  Confidential')
    canvas.setFillColor(GREEN)
    canvas.setFont('Helvetica-Bold', 8)
    canvas.drawRightString(W - 22*mm, 6*mm, f'Page {doc.page}')
    canvas.restoreState()

PLANS = {
    'basic':   {'name': 'Basic Audit',            'price': 'N40,000',       'checks': 5,  'desc': '5-point security check covering critical vulnerabilities'},
    'full':    {'name': 'Full Audit',              'price': 'N100,000',      'checks': 9,  'desc': '9-point comprehensive security and compliance audit'},
    'monthly': {'name': 'Monthly Monitoring',      'price': 'N50,000/month', 'checks': 9,  'desc': 'Monthly full audit with updated report and monitoring'},
}

STATUS_COLORS = {
    'pass': (GREEN, GREEN_BG, '✓', 'PASS'),
    'fail': (RED,   RED_BG,   '✗', 'FAIL'),
    'warn': (AMBER, AMBER_BG, '!', 'WARN'),
    'info': (BLUE,  BLUE_BG,  'i', 'N/A'),
}

CHECKS_META = [
    {'id': 'https',        'name': 'HTTPS / SSL Certificate',        'source': 'Built-in',            'basic': True},
    {'id': 'privacy',      'name': 'Privacy Policy (NDPR)',           'source': 'Built-in',            'basic': True},
    {'id': 'cookie',       'name': 'Cookie Consent Notice',           'source': 'Built-in',            'basic': True},
    {'id': 'mixed',        'name': 'Mixed Content',                   'source': 'Built-in',            'basic': True},
    {'id': 'cms',          'name': 'CMS Version Hidden',              'source': 'Built-in',            'basic': True},
    {'id': 'observatory',  'name': 'Mozilla Observatory Grade',       'source': 'Mozilla Observatory', 'basic': False},
    {'id': 'ssl_grade',    'name': 'SSL Labs Certificate Grade',      'source': 'SSL Labs',            'basic': False},
    {'id': 'urlscan',      'name': 'URLScan.io Threat Check',         'source': 'URLScan.io',          'basic': False},
    {'id': 'safebrowsing', 'name': 'Google Safe Browsing',            'source': 'Google',              'basic': False},
]

@app.route("/api/generate-report", methods=["POST"])
def generate_report():
    d = request.json or {}
    plan_key    = d.get("plan", "full")
    biz_name    = d.get("biz_name", "Business")
    biz_sector  = d.get("biz_sector", "")
    biz_city    = d.get("biz_city", "")
    url         = d.get("url", "")
    domain      = d.get("domain", "")
    score       = d.get("score", 0)
    checks      = d.get("checks", {})
    api_results = d.get("api_results", {})
    audit_date  = d.get("audit_date", "")
    auditor     = d.get("auditor", "Atlas Securecheck")
    notes       = d.get("notes", "")

    plan = PLANS.get(plan_key, PLANS["full"])
    is_basic = plan_key == "basic"
    visible_checks = [c for c in CHECKS_META if (is_basic and c["basic"]) or not is_basic]

    # Score label
    if score >= 80:   risk_label, risk_color = "GOOD",     GREEN
    elif score >= 55: risk_label, risk_color = "AT RISK",  AMBER
    else:             risk_label, risk_color = "CRITICAL", RED

    fails = sum(1 for c in visible_checks if checks.get(c["id"], {}).get("status") == "fail")
    warns = sum(1 for c in visible_checks if checks.get(c["id"], {}).get("status") == "warn")
    passes = sum(1 for c in visible_checks if checks.get(c["id"], {}).get("status") == "pass")
    ndpr_ids = {"https", "privacy", "cookie", "safebrowsing"}
    ndpr_fail = any(checks.get(i, {}).get("status") == "fail" for i in ndpr_ids)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=22*mm, rightMargin=22*mm,
        topMargin=20*mm, bottomMargin=22*mm,
        title=f"Atlas Securecheck — {biz_name} Audit Report")

    PW = doc.width
    story = []

    # ── Cover header ──
    story.append(Spacer(1, 8*mm))

    # Logo row
    logo_data = [[
        Paragraph('<b>AS</b>', S('lg', fontName='Helvetica-Bold', fontSize=16, textColor=GREEN, alignment=TA_CENTER)),
        Paragraph('<b>Atlas Securecheck</b>', S('ln', fontName='Helvetica-Bold', fontSize=22, textColor=INK, leading=26)),
    ]]
    logo_tbl = Table(logo_data, colWidths=[14*mm, PW - 14*mm])
    logo_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (0,0), 0),
        ('LEFTPADDING', (1,0), (1,0), 10),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('BOX', (0,0), (0,0), 1.5, GREEN),
        ('BACKGROUND', (0,0), (0,0), WHITE),
    ]))
    story.append(logo_tbl)
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph('WEBSITE SECURITY AUDIT REPORT', S('sub', fontName='Helvetica', fontSize=9, textColor=INK3, letterSpacing=2)))
    story.append(Divider(GREEN, 2))
    story.append(Spacer(1, 6*mm))

    # Business info + score
    score_color_hex = '#00875a' if score >= 80 else '#b45309' if score >= 55 else '#c0392b'
    biz_info = [
        [Paragraph(f'<b>{biz_name}</b>', S('bn', fontName='Helvetica-Bold', fontSize=20, textColor=INK, leading=24)),
         Paragraph(f'<b>{score}</b>', S('sc', fontName='Helvetica-Bold', fontSize=36, textColor=colors.HexColor(score_color_hex), alignment=TA_CENTER, leading=40))],
        [Paragraph(f'{biz_sector}{"  ·  " + biz_city if biz_city else ""}', S('bm', fontName='Helvetica', fontSize=11, textColor=INK3)),
         Paragraph(f'<b>{risk_label}</b>', S('sl', fontName='Helvetica-Bold', fontSize=11, textColor=colors.HexColor(score_color_hex), alignment=TA_CENTER))],
        [Paragraph(f'{domain}', S('bd', fontName='Helvetica', fontSize=10, textColor=INK3)),
         Paragraph('/ 100', S('sh', fontName='Helvetica', fontSize=9, textColor=INK3, alignment=TA_CENTER))],
    ]
    biz_tbl = Table(biz_info, colWidths=[PW * 0.68, PW * 0.32])
    biz_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (1,0), (1,2), SURFACE),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (1,0), (1,-1), 10),
        ('RIGHTPADDING', (1,0), (1,-1), 10),
        ('LINEAFTER', (0,0), (0,-1), 0.5, colors.HexColor('#e2e0da')),
    ]))
    story.append(biz_tbl)
    story.append(Spacer(1, 4*mm))

    # Stats row
    stats_data = [[
        Paragraph(f'<b>{fails}</b><br/><font size=8>Failed</font>', S('st', fontName='Helvetica-Bold', fontSize=20, textColor=RED, alignment=TA_CENTER, leading=22)),
        Paragraph(f'<b>{warns}</b><br/><font size=8>Warnings</font>', S('st2', fontName='Helvetica-Bold', fontSize=20, textColor=AMBER, alignment=TA_CENTER, leading=22)),
        Paragraph(f'<b>{passes}</b><br/><font size=8>Passed</font>', S('st3', fontName='Helvetica-Bold', fontSize=20, textColor=GREEN, alignment=TA_CENTER, leading=22)),
        Paragraph(f'<b>{len(visible_checks)}</b><br/><font size=8>Checks</font>', S('st4', fontName='Helvetica-Bold', fontSize=20, textColor=BLUE, alignment=TA_CENTER, leading=22)),
        Paragraph(f'<b>{plan["name"]}</b><br/><font size=8>{plan["price"]}</font>', S('st5', fontName='Helvetica-Bold', fontSize=13, textColor=INK, alignment=TA_CENTER, leading=18)),
    ]]
    stats_tbl = Table(stats_data, colWidths=[PW/5]*5)
    stats_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), SURFACE),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(stats_tbl)
    story.append(Spacer(1, 6*mm))

    # NDPR warning
    if ndpr_fail:
        ndpr_data = [[
            Paragraph('NDPR', S('nl', fontName='Helvetica-Bold', fontSize=9, textColor=AMBER, alignment=TA_CENTER)),
            Paragraph('One or more findings constitute a potential violation of the Nigeria Data Protection Regulation (NDPR) 2019. Penalties reach <b>N10 million</b> or 2% of annual gross revenue.', S('nb', fontName='Helvetica', fontSize=9, leading=14, textColor=colors.HexColor('#78350f'))),
        ]]
        ndpr_tbl = Table(ndpr_data, colWidths=[14*mm, PW - 14*mm])
        ndpr_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), AMBER_BG),
            ('BOX', (0,0), (-1,-1), 1, AMBER),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(ndpr_tbl)
        story.append(Spacer(1, 5*mm))

    # ── Findings ──
    story.append(Paragraph('SECURITY FINDINGS', S('sh', fontName='Helvetica-Bold', fontSize=10, textColor=INK3, letterSpacing=1.5)))
    story.append(Divider(colors.HexColor('#e2e0da')))
    story.append(Spacer(1, 3*mm))

    for chk in visible_checks:
        r = checks.get(chk["id"], {"status": "info", "note": "Not checked", "pass": False})
        status = r.get("status", "info")
        col, bg, icon, badge = STATUS_COLORS.get(status, STATUS_COLORS["info"])

        finding_data = [[
            Paragraph(f'<b>{icon}</b>', S('fi', fontName='Helvetica-Bold', fontSize=13, textColor=col, alignment=TA_CENTER)),
            Paragraph(f'<b>{chk["name"]}</b>', S('fn', fontName='Helvetica-Bold', fontSize=11, textColor=INK, leading=14)),
            Paragraph(badge, S('fb', fontName='Helvetica-Bold', fontSize=8, textColor=col, alignment=TA_CENTER)),
        ]]
        finding_tbl = Table(finding_data, colWidths=[10*mm, PW - 26*mm, 16*mm])
        finding_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ]))

        note_data = [[
            Spacer(10*mm, 1),
            Paragraph(r.get("note", ""), S('nd', fontName='Helvetica', fontSize=9, leading=14, textColor=INK2)),
            Paragraph(f'Source: {chk["source"]}', S('ns', fontName='Helvetica', fontSize=8, textColor=INK3)),
        ]]
        note_tbl = Table(note_data, colWidths=[10*mm, PW - 36*mm, 26*mm])
        note_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), WHITE),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ]))
        story.append(KeepTogether([finding_tbl, note_tbl, Spacer(1, 3*mm)]))

    # ── Auditor notes ──
    if notes:
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph('AUDITOR NOTES', S('sh', fontName='Helvetica-Bold', fontSize=10, textColor=INK3, letterSpacing=1.5)))
        story.append(Divider(colors.HexColor('#e2e0da')))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(notes, S('nt', fontName='Helvetica', fontSize=10, leading=16, textColor=INK2)))
        story.append(Spacer(1, 4*mm))

    # ── Footer info ──
    story.append(Spacer(1, 6*mm))
    footer_data = [[
        Paragraph(f'Prepared by: <b>{auditor}</b><br/>Audit date: {audit_date}<br/>Report type: {plan["name"]} ({plan["checks"]}-point audit)', S('fi', fontName='Helvetica', fontSize=9, leading=14, textColor=INK3)),
        Paragraph(f'<b>{plan["price"]}</b><br/><font size=8 color="#6b7280">Service fee</font>', S('fp', fontName='Helvetica-Bold', fontSize=18, textColor=INK, alignment=TA_RIGHT, leading=22)),
    ]]
    # Note: Tool URL intentionally excluded from report
    footer_tbl = Table(footer_data, colWidths=[PW * 0.6, PW * 0.4])
    footer_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), SURFACE),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
    ]))
    story.append(footer_tbl)

    doc.build(story, onFirstPage=bg_page, onLaterPages=bg_page)
    buf.seek(0)

    from flask import send_file
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', biz_name)
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f"Atlas_Securecheck_{safe_name}_Report.pdf")


@app.route("/api/generate-outreach", methods=["POST"])
def generate_outreach():
    """One-page outreach summary — no pricing, no plan labels. For prospect use."""
    d = request.json or {}
    biz_name   = d.get("biz_name", "Business")
    biz_sector = d.get("biz_sector", "")
    biz_city   = d.get("biz_city", "")
    url        = d.get("url", "")
    domain     = d.get("domain", "")
    score      = d.get("score", 0)
    checks     = d.get("checks", {})
    audit_date = d.get("audit_date", "")
    auditor    = d.get("auditor", "Atlas Securecheck")

    # Only show the 5 basic checks in outreach — don't overwhelm the prospect
    outreach_checks = [c for c in CHECKS_META if c["basic"]]

    if score >= 80:   risk_label, risk_color = "LOW RISK",  GREEN
    elif score >= 55: risk_label, risk_color = "AT RISK",   AMBER
    else:             risk_label, risk_color = "CRITICAL",  RED

    fails  = [c for c in outreach_checks if checks.get(c["id"], {}).get("status") == "fail"]
    warns  = [c for c in outreach_checks if checks.get(c["id"], {}).get("status") == "warn"]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=22*mm, rightMargin=22*mm,
        topMargin=20*mm, bottomMargin=22*mm,
        title=f"Atlas Securecheck — Security Summary for {biz_name}")

    PW = doc.width
    story = []
    story.append(Spacer(1, 6*mm))

    # ── Header ──
    story.append(Paragraph(
        '<b>Atlas Securecheck</b>',
        S('h1', fontName='Helvetica-Bold', fontSize=14, textColor=GREEN, spaceAfter=2)
    ))
    story.append(Paragraph(
        'WEBSITE SECURITY SUMMARY',
        S('h2', fontName='Helvetica', fontSize=9, textColor=INK3, letterSpacing=2, spaceAfter=0)
    ))
    story.append(Divider(GREEN, 2))
    story.append(Spacer(1, 5*mm))

    # ── Intro message ──
    intro = (
        f"We conducted a free preliminary security scan of <b>{biz_name}</b>'s website "
        f"({domain}) and identified {len(fails)} critical issue(s) and {len(warns)} warning(s) "
        f"that may be putting your business and customers at risk."
    )
    story.append(Paragraph(intro, S('intro', fontName='Helvetica', fontSize=11, leading=18, textColor=INK2)))
    story.append(Spacer(1, 5*mm))

    # ── Score banner ──
    score_color_hex = '#00875a' if score >= 80 else '#b45309' if score >= 55 else '#c0392b'
    banner_data = [[
        Paragraph(
            f'<b>{score}</b><br/><font size=9>Security Score</font>',
            S('sc', fontName='Helvetica-Bold', fontSize=32, textColor=colors.HexColor(score_color_hex),
              alignment=TA_CENTER, leading=38)
        ),
        Paragraph(
            f'<b>{risk_label}</b><br/><br/>'
            f'<font size=10>{len(fails)} critical &nbsp;·&nbsp; {len(warns)} warnings</font>',
            S('rl', fontName='Helvetica-Bold', fontSize=16, textColor=colors.HexColor(score_color_hex),
              alignment=TA_CENTER, leading=22)
        ),
    ]]
    banner_tbl = Table(banner_data, colWidths=[PW*0.35, PW*0.65])
    banner_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), SURFACE),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING', (0,0), (-1,-1), 14),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LINEAFTER', (0,0), (0,-1), 1, colors.HexColor('#e2e0da')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
    ]))
    story.append(banner_tbl)
    story.append(Spacer(1, 6*mm))

    # ── Findings ──
    story.append(Paragraph(
        'WHAT WE FOUND',
        S('sh', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1.5)
    ))
    story.append(Divider(colors.HexColor('#e2e0da')))
    story.append(Spacer(1, 3*mm))

    for chk in outreach_checks:
        r = checks.get(chk["id"], {"status": "info", "note": "Not checked"})
        status = r.get("status", "info")
        col, bg, icon, badge = STATUS_COLORS.get(status, STATUS_COLORS["info"])

        # Plain English explanation for prospects
        plain_notes = {
            "https":   {
                "fail": "Your website is not encrypted. Customer data — names, emails, phone numbers — is sent in plain text that anyone can intercept.",
                "pass": "Your website uses HTTPS encryption. Customer data is protected in transit.",
                "warn": "HTTPS is partially configured. Some pages may still be unencrypted.",
            },
            "privacy": {
                "fail": "No privacy policy was found. Under Nigerian law (NDPR 2019), any business that collects customer data must publish a privacy policy.",
                "pass": "A privacy policy is present on the website.",
                "warn": "A privacy policy may be present but appears incomplete.",
            },
            "cookie":  {
                "fail": "No cookie consent notice was detected. Websites using tracking tools must inform visitors before collecting data.",
                "pass": "Cookie consent is handled on the website.",
                "warn": "A cookie notice exists but may not fully comply with best practices.",
            },
            "cms":     {
                "warn": "Your website platform version is publicly visible. Attackers use this to find known vulnerabilities specific to that version.",
                "pass": "Platform version information is properly hidden.",
                "fail": "Your CMS version is exposed, making it easier for attackers to target your site.",
            },
            "mixed":   {
                "fail": "Some content on your website loads without encryption, creating security gaps even on HTTPS pages.",
                "pass": "All content loads securely — no mixed content issues detected.",
                "warn": "Some resources may be loading without full encryption.",
            },
        }
        note_text = plain_notes.get(chk["id"], {}).get(status, r.get("note",""))

        row_data = [[
            Paragraph(f'<b>{icon}</b>', S('ri', fontName='Helvetica-Bold', fontSize=13, textColor=col, alignment=TA_CENTER)),
            [Paragraph(f'<b>{chk["name"]}</b>', S('rn', fontName='Helvetica-Bold', fontSize=11, textColor=INK, leading=14, spaceAfter=3)),
             Paragraph(note_text, S('rd', fontName='Helvetica', fontSize=9, leading=14, textColor=INK2, spaceAfter=0))],
            Paragraph(badge, S('rb', fontName='Helvetica-Bold', fontSize=8, textColor=col, alignment=TA_CENTER)),
        ]]
        row_tbl = Table(row_data, colWidths=[10*mm, PW - 26*mm, 16*mm])
        row_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg if status in ['fail','warn'] else WHITE),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ]))
        story.append(row_tbl)
        story.append(Spacer(1, 3*mm))

    # ── NDPR note if relevant ──
    ndpr_fail = any(checks.get(i, {}).get("status") == "fail"
                    for i in ["https", "privacy", "cookie"])
    if ndpr_fail:
        story.append(Spacer(1, 2*mm))
        ndpr_data = [[
            Paragraph('⚠', S('nw', fontName='Helvetica-Bold', fontSize=16, textColor=AMBER, alignment=TA_CENTER)),
            Paragraph(
                '<b>NDPR Compliance Notice</b><br/>'
                'One or more of the above issues may constitute a violation of the Nigeria Data Protection '
                'Regulation (NDPR) 2019. Non-compliance can attract penalties of up to <b>₦10 million</b>.',
                S('nb', fontName='Helvetica', fontSize=9, leading=14, textColor=colors.HexColor('#78350f'))
            ),
        ]]
        ndpr_tbl = Table(ndpr_data, colWidths=[12*mm, PW - 12*mm])
        ndpr_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), AMBER_BG),
            ('BOX', (0,0), (-1,-1), 1, AMBER),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(ndpr_tbl)
        story.append(Spacer(1, 4*mm))

    # ── Next steps ──
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        'WHAT HAPPENS NEXT',
        S('sh2', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1.5)
    ))
    story.append(Divider(colors.HexColor('#e2e0da')))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        'This is a preliminary scan covering 5 key security indicators. A full professional audit '
        'covers 9 checks including SSL certificate analysis, threat database lookups, and a '
        'comprehensive compliance report your developer can act on directly. '
        'Reach out to discuss next steps.',
        S('ns', fontName='Helvetica', fontSize=10, leading=16, textColor=INK2)
    ))

    # ── Footer ──
    story.append(Spacer(1, 6*mm))
    story.append(Divider(colors.HexColor('#e2e0da')))
    story.append(Spacer(1, 3*mm))
    footer_parts = [f'<b>{auditor}</b>']
    if audit_date: footer_parts.append(f'Scan date: {audit_date}')
    # URL intentionally excluded from outreach summary
    story.append(Paragraph(
        '  ·  '.join(footer_parts),
        S('ft', fontName='Helvetica', fontSize=9, textColor=INK3, alignment=TA_CENTER)
    ))

    doc.build(story, onFirstPage=bg_page, onLaterPages=bg_page)
    buf.seek(0)

    from flask import send_file
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', biz_name)
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f"Atlas_Securecheck_{safe_name}_Security_Summary.pdf")


@app.route("/api/generate-invoice", methods=["POST"])
def generate_invoice():
    d = request.json or {}
    plan_key       = d.get("plan", "full")
    biz_name       = d.get("biz_name", "Client")
    biz_contact    = d.get("biz_contact", "")
    biz_email      = d.get("biz_email", "")
    invoice_number = d.get("invoice_number", "INV-001")
    issue_date     = d.get("issue_date", "")
    due_date       = d.get("due_date", "")
    auditor        = d.get("auditor", "Atlas Securecheck")
    auditor_email  = d.get("auditor_email", "")
    auditor_phone  = d.get("auditor_phone", "")
    bank_name      = d.get("bank_name", "")
    account_name   = d.get("account_name", "")
    account_number = d.get("account_number", "")
    notes          = d.get("notes", "")

    plan = PLANS.get(plan_key, PLANS["full"])
    price_str = plan["price"].replace("N", "").replace(",", "").replace("/month", "").strip()
    try: price_val = int(price_str)
    except: price_val = 0

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=22*mm, rightMargin=22*mm,
        topMargin=20*mm, bottomMargin=22*mm,
        title=f"Atlas Securecheck Invoice — {invoice_number}")

    PW = doc.width
    story = []
    story.append(Spacer(1, 8*mm))

    # Header
    hdr_data = [[
        Paragraph('<b>AS</b>', S('lg', fontName='Helvetica-Bold', fontSize=16, textColor=GREEN, alignment=TA_CENTER)),
        [Paragraph('<b>Atlas Securecheck</b>', S('ln', fontName='Helvetica-Bold', fontSize=22, textColor=INK, leading=26)),
         Paragraph('Website Security Auditing Services', S('ls', fontName='Helvetica', fontSize=10, textColor=INK3))],
        Paragraph('INVOICE', S('inv', fontName='Helvetica-Bold', fontSize=28, textColor=GREEN, alignment=TA_RIGHT, leading=32)),
    ]]
    hdr_tbl = Table(hdr_data, colWidths=[14*mm, PW*0.55, PW*0.38])
    hdr_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (1,0), (1,0), 10),
        ('BOX', (0,0), (0,0), 1.5, GREEN),
    ]))
    story.append(hdr_tbl)
    story.append(Divider(GREEN, 3))
    story.append(Spacer(1, 6*mm))

    # Invoice meta + Bill To
    meta_data = [[
        [Paragraph('<b>BILL TO</b>', S('bt', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1)),
         Spacer(1, 2*mm),
         Paragraph(f'<b>{biz_name}</b>', S('bn', fontName='Helvetica-Bold', fontSize=14, textColor=INK, leading=18)),
         Paragraph(biz_contact, S('bc', fontName='Helvetica', fontSize=10, textColor=INK2)),
         Paragraph(biz_email, S('be', fontName='Helvetica', fontSize=10, textColor=BLUE))],
        [Paragraph('<b>INVOICE DETAILS</b>', S('id', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1)),
         Spacer(1, 2*mm),
         Paragraph(f'<b>Invoice No:</b>  {invoice_number}', S('im', fontName='Helvetica', fontSize=10, textColor=INK2, leading=16)),
         Paragraph(f'<b>Issue Date:</b>  {issue_date}', S('im2', fontName='Helvetica', fontSize=10, textColor=INK2, leading=16)),
         Paragraph(f'<b>Due Date:</b>    {due_date}', S('im3', fontName='Helvetica', fontSize=10, textColor=INK2, leading=16)),
         Paragraph(f'<b>Status:</b>        <font color="#b45309">UNPAID</font>', S('im4', fontName='Helvetica', fontSize=10, textColor=INK2, leading=16))],
    ]]
    meta_tbl = Table(meta_data, colWidths=[PW*0.5, PW*0.5])
    meta_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 8*mm))

    # Service table
    story.append(Paragraph('SERVICES', S('sh', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1.5)))
    story.append(Spacer(1, 2*mm))

    svc_header = [
        Paragraph('DESCRIPTION', S('th', fontName='Helvetica-Bold', fontSize=9, textColor=WHITE, letterSpacing=0.5)),
        Paragraph('QTY', S('th2', fontName='Helvetica-Bold', fontSize=9, textColor=WHITE, alignment=TA_CENTER)),
        Paragraph('AMOUNT', S('th3', fontName='Helvetica-Bold', fontSize=9, textColor=WHITE, alignment=TA_RIGHT)),
    ]
    svc_row = [
        [Paragraph(f'<b>{plan["name"]}</b>', S('sd', fontName='Helvetica-Bold', fontSize=11, textColor=INK, leading=14)),
         Paragraph(plan["desc"], S('ss', fontName='Helvetica', fontSize=9, leading=13, textColor=INK3))],
        Paragraph('1', S('sq', fontName='Helvetica', fontSize=11, textColor=INK2, alignment=TA_CENTER)),
        Paragraph(f'<b>{plan["price"]}</b>', S('sa', fontName='Helvetica-Bold', fontSize=13, textColor=INK, alignment=TA_RIGHT)),
    ]
    subtotal_row = [
        Paragraph('Subtotal', S('sub', fontName='Helvetica', fontSize=10, textColor=INK3)),
        '',
        Paragraph(plan["price"], S('subv', fontName='Helvetica', fontSize=10, textColor=INK2, alignment=TA_RIGHT)),
    ]
    total_row = [
        Paragraph('<b>TOTAL DUE</b>', S('tot', fontName='Helvetica-Bold', fontSize=13, textColor=INK)),
        '',
        Paragraph(f'<b>{plan["price"]}</b>', S('totv', fontName='Helvetica-Bold', fontSize=16, textColor=GREEN, alignment=TA_RIGHT)),
    ]

    svc_tbl = Table(
        [svc_header, svc_row, subtotal_row, total_row],
        colWidths=[PW*0.6, PW*0.15, PW*0.25]
    )
    svc_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), DARK),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('RIGHTPADDING',  (0,0), (-1,-1), 10),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS',(0,1), (-1,1), [SURFACE]),
        ('LINEBELOW',     (0,2), (-1,2), 0.5, colors.HexColor('#e2e0da')),
        ('BACKGROUND',    (0,3), (-1,3), GREEN_BG),
        ('BOX',           (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ('INNERGRID',     (0,0), (-1,-1), 0.25, colors.HexColor('#e2e0da')),
    ]))
    story.append(svc_tbl)
    story.append(Spacer(1, 8*mm))

    # Payment details
    story.append(Paragraph('PAYMENT DETAILS', S('sh', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1.5)))
    story.append(Spacer(1, 2*mm))
    pay_data = [
        [Paragraph('Bank Name', S('pk', fontName='Helvetica', fontSize=10, textColor=INK3)),
         Paragraph(f'<b>{bank_name}</b>', S('pv', fontName='Helvetica-Bold', fontSize=10, textColor=INK))],
        [Paragraph('Account Name', S('pk2', fontName='Helvetica', fontSize=10, textColor=INK3)),
         Paragraph(f'<b>{account_name}</b>', S('pv2', fontName='Helvetica-Bold', fontSize=10, textColor=INK))],
        [Paragraph('Account Number', S('pk3', fontName='Helvetica', fontSize=10, textColor=INK3)),
         Paragraph(f'<b>{account_number}</b>', S('pv3', fontName='Helvetica-Bold', fontSize=14, textColor=GREEN))],
    ]
    pay_tbl = Table(pay_data, colWidths=[PW*0.35, PW*0.65])
    pay_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), SURFACE),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [SURFACE, WHITE]),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
        ('RIGHTPADDING',  (0,0), (-1,-1), 12),
        ('BOX',           (0,0), (-1,-1), 0.5, colors.HexColor('#e2e0da')),
        ('INNERGRID',     (0,0), (-1,-1), 0.25, colors.HexColor('#e2e0da')),
        ('LINEAFTER',     (0,0), (0,-1), 0.5, colors.HexColor('#e2e0da')),
    ]))
    story.append(pay_tbl)

    if notes:
        story.append(Spacer(1, 6*mm))
        story.append(Paragraph('NOTES', S('sh', fontName='Helvetica-Bold', fontSize=9, textColor=INK3, letterSpacing=1.5)))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph(notes, S('nt', fontName='Helvetica', fontSize=10, leading=16, textColor=INK2)))

    # Contact footer
    story.append(Spacer(1, 8*mm))
    story.append(Divider(colors.HexColor('#e2e0da')))
    story.append(Spacer(1, 3*mm))
    contact_parts = [auditor]
    if auditor_email: contact_parts.append(auditor_email)
    if auditor_phone: contact_parts.append(auditor_phone)
    story.append(Paragraph('  ·  '.join(contact_parts), S('cf', fontName='Helvetica', fontSize=9, textColor=INK3, alignment=TA_CENTER)))
    # Note: Tool URL intentionally excluded from invoice

    doc.build(story, onFirstPage=bg_page, onLaterPages=bg_page)
    buf.seek(0)

    from flask import send_file
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f"Atlas_Securecheck_Invoice_{invoice_number}.pdf")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
