"""
app.py - Website Security Scanner | فاحص أمان المواقع
واجهة ويب ثنائية اللغة (العربية / English) بـ Streamlit، مناسبة للجوال.

Run:
    pip install -r requirements.txt
    streamlit run app.py

Scan only sites you own or have written permission to test.
افحص فقط المواقع التي تملكها أو لديك إذن كتابي بفحصها.
"""
import functools
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from html import escape
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------------ Settings
TIMEOUT = 8
MAX_REDIRECTS = 5
MAX_BODY = 500_000
COOLDOWN_SECONDS = 8
# حدود الاستخدام (تُعدَّل من متغيرات البيئة عند النشر)
PER_CLIENT_LIMIT = int(os.environ.get("SCAN_LIMIT_PER_CLIENT", 10))   # فحوصات/ساعة لكل مستخدم
PER_HOST_LIMIT = int(os.environ.get("SCAN_LIMIT_PER_HOST", 5))        # فحوصات/ساعة لكل موقع مستهدف
GLOBAL_LIMIT = int(os.environ.get("SCAN_LIMIT_GLOBAL", 200))          # فحوصات/ساعة للخدمة كلها
LIMIT_WINDOW = 3600
ALLOWED_PORTS = {None, 80, 443}
UA = {"User-Agent": "SiteScanner/3.0 (authorized security check)"}

LANGS = {"العربية": "ar", "English": "en"}
ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
WEIGHT = {"high": 20, "medium": 8, "low": 3, "info": 0}
COLOR = {"high": "#C93B3B", "medium": "#D98A12", "low": "#A08C00", "info": "#2F6FDB"}
TINT = {"high": "#FBE9E9", "medium": "#FCF0DC", "low": "#F7F3D4", "info": "#E5EEFB"}
GREEN, GREEN_TINT = "#1E8E5A", "#E3F3EA"


class BlockedError(Exception):
    """Address not allowed. args[0] is a code: 'private' or 'port'."""


class Report:
    """Collects findings (negatives) and passed checks (positives) as ids + params."""

    def __init__(self):
        self.findings = []
        self.passed = []

    def add(self, sev, mid, **p):
        self.findings.append({"severity": sev, "id": mid, "p": p})

    def ok(self, mid, **p):
        self.passed.append({"id": mid, "p": p})


# ------------------------------------------------------------------ Messages (title, detail, fix)
MSG = {
    # ---- findings
    "ssl_verify_failed": {
        "ar": ("فشل التحقق من شهادة SSL", "{raw}", "أصلح الشهادة أو جدّدها."),
        "en": ("SSL certificate verification failed", "{raw}", "Fix or renew the certificate."),
    },
    "tls_invalid": {
        "ar": ("شهادة SSL غير صالحة", "{raw}", "ثبّت شهادة صحيحة (مثل Let's Encrypt)."),
        "en": ("Invalid SSL certificate", "{raw}", "Install a valid certificate (e.g. Let's Encrypt)."),
    },
    "tls_check_failed": {
        "ar": ("تعذّر فحص TLS على المنفذ 443", "{raw}", ""),
        "en": ("Could not check TLS on port 443", "{raw}", ""),
    },
    "cert_expired": {
        "ar": ("شهادة SSL منتهية", "انتهت منذ {days} يوم", "جدّد الشهادة فوراً."),
        "en": ("SSL certificate expired", "Expired {days} days ago", "Renew the certificate immediately."),
    },
    "cert_expiring": {
        "ar": ("شهادة SSL توشك على الانتهاء", "متبقي {days} يوم", "فعّل التجديد التلقائي."),
        "en": ("SSL certificate is about to expire", "{days} days left", "Enable automatic renewal."),
    },
    "tls_old": {
        "ar": ("إصدار TLS قديم", "{raw}", "فعّل TLS 1.2 أو 1.3 فقط."),
        "en": ("Outdated TLS version", "{raw}", "Allow only TLS 1.2 or 1.3."),
    },
    "no_https_redirect": {
        "ar": ("الموقع يعمل عبر HTTP دون تحويل إلى HTTPS", "{raw}", "أضف تحويلاً دائماً (301) من HTTP إلى HTTPS."),
        "en": ("Site serves HTTP without redirecting to HTTPS", "{raw}",
               "Add a permanent (301) redirect from HTTP to HTTPS."),
    },
    "hdr_missing_hsts": {
        "ar": ("ترويسة أمان مفقودة: Strict-Transport-Security", "", "يمنع تخفيض الاتصال إلى HTTP. أضف HSTS."),
        "en": ("Missing security header: Strict-Transport-Security", "",
               "Prevents downgrade to HTTP. Add HSTS."),
    },
    "hdr_missing_csp": {
        "ar": ("ترويسة أمان مفقودة: Content-Security-Policy", "", "يحدّ من هجمات XSS وحقن السكربتات."),
        "en": ("Missing security header: Content-Security-Policy", "",
               "Limits XSS and script-injection attacks."),
    },
    "hdr_missing_xcto": {
        "ar": ("ترويسة أمان مفقودة: X-Content-Type-Options", "", "أضف القيمة: nosniff"),
        "en": ("Missing security header: X-Content-Type-Options", "", "Add the value: nosniff"),
    },
    "hdr_missing_refpol": {
        "ar": ("ترويسة أمان مفقودة: Referrer-Policy", "", "مثال: strict-origin-when-cross-origin"),
        "en": ("Missing security header: Referrer-Policy", "", "Example: strict-origin-when-cross-origin"),
    },
    "hdr_missing_perm": {
        "ar": ("ترويسة أمان مفقودة: Permissions-Policy", "", "قيّد صلاحيات الكاميرا والموقع وغيرها."),
        "en": ("Missing security header: Permissions-Policy", "",
               "Restrict camera, location and other browser permissions."),
    },
    "no_clickjack": {
        "ar": ("لا حماية من Clickjacking", "X-Frame-Options / frame-ancestors غير موجودة",
               "أضف X-Frame-Options: DENY"),
        "en": ("No Clickjacking protection", "X-Frame-Options / frame-ancestors not found",
               "Add X-Frame-Options: DENY"),
    },
    "version_leak": {
        "ar": ("كشف إصدار التقنية عبر {name}", "{raw}", "أخفِ رقم الإصدار من إعدادات الخادم."),
        "en": ("Technology version disclosed via {name}", "{raw}", "Hide the version number in the server settings."),
    },
    "cookie_flags": {
        "ar": ("كوكي '{name}' ينقصه: {missing}", "", "أضف الخصائص المفقودة للكوكيز الحساسة."),
        "en": ("Cookie '{name}' is missing: {missing}", "", "Add the missing flags to sensitive cookies."),
    },
    "cors_reflect": {
        "ar": ("CORS يعكس أي Origin مع السماح بالـ Credentials", "{raw}",
               "استخدم قائمة بيضاء صريحة للنطاقات المسموحة."),
        "en": ("CORS reflects any Origin while allowing credentials", "{raw}",
               "Use an explicit allow-list of trusted origins."),
    },
    "cors_wild": {
        "ar": ("CORS مفتوح للجميع (*)", "", "قيّده إن كان الـ API يحمل بيانات حساسة."),
        "en": ("CORS is open to everyone (*)", "", "Restrict it if the API carries sensitive data."),
    },
    "mixed": {
        "ar": ("محتوى مختلط (Mixed Content)", "موارد تُحمَّل عبر HTTP داخل صفحة HTTPS", "حوّل كل الروابط إلى HTTPS."),
        "en": ("Mixed content", "Resources load over HTTP inside an HTTPS page", "Switch all links to HTTPS."),
    },
    "pw_http": {
        "ar": ("نموذج كلمة مرور عبر اتصال غير مشفّر", "", "فعّل HTTPS على كامل الموقع."),
        "en": ("Password form over an unencrypted connection", "", "Enable HTTPS on the whole site."),
    },
    "sensitive_file": {
        "ar": ("ملف حساس متاح للعامة: {path}", "{url}", "امنع الوصول إليه من إعدادات الخادم."),
        "en": ("Sensitive file publicly accessible: {path}", "{url}", "Block access to it in the server settings."),
    },
    # ---- passed checks
    "ok_cert": {
        "ar": ("شهادة SSL صالحة وسارية", "متبقي {days} يوم", ""),
        "en": ("SSL certificate is valid", "{days} days left", ""),
    },
    "ok_tls": {
        "ar": ("إصدار TLS حديث", "{raw}", ""),
        "en": ("Modern TLS version", "{raw}", ""),
    },
    "ok_redirect": {
        "ar": ("التحويل من HTTP إلى HTTPS يعمل", "", ""),
        "en": ("HTTP to HTTPS redirect works", "", ""),
    },
    "ok_headers": {
        "ar": ("ترويسات الأمان الموجودة ({n} من {total})", "{raw}", ""),
        "en": ("Security headers present ({n} of {total})", "{raw}", ""),
    },
    "ok_clickjack": {
        "ar": ("حماية من Clickjacking مفعّلة", "", ""),
        "en": ("Clickjacking protection is enabled", "", ""),
    },
    "ok_noleak": {
        "ar": ("لا يكشف إصدارات الخادم في الترويسات", "", ""),
        "en": ("Server versions are not disclosed in headers", "", ""),
    },
    "ok_cookies": {
        "ar": ("الكوكيز محمية", "{n} كوكي بخصائص Secure وHttpOnly وSameSite", ""),
        "en": ("Cookies are protected", "{n} cookie(s) with Secure, HttpOnly and SameSite", ""),
    },
    "ok_cors": {
        "ar": ("إعدادات CORS لا تسمح بأي نطاق خارجي", "", ""),
        "en": ("CORS settings don't allow arbitrary origins", "", ""),
    },
    "ok_mixed": {
        "ar": ("لا يوجد محتوى مختلط في الصفحة الرئيسية", "", ""),
        "en": ("No mixed content on the main page", "", ""),
    },
    "ok_files": {
        "ar": ("لا ملفات حساسة مكشوفة", "فُحصت مسارات شائعة مثل .git و .env و phpinfo", ""),
        "en": ("No exposed sensitive files", "Common paths checked, such as .git, .env and phpinfo", ""),
    },
}

# ------------------------------------------------------------------ UI text
UI = {
    "ar": {
        "dir": "rtl", "end": "right",
        "title": "فاحص أمان المواقع",
        "subtitle": "ألصق رابط موقعك واحصل على تقرير بالثغرات والنقاط الآمنة خلال ثوانٍ.",
        "url_label": "رابط الموقع",
        "consent": "أملك هذا الموقع أو لدي إذن كتابي بفحصه",
        "scan": "فحص الموقع",
        "spinner": "جارٍ الفحص…",
        "cooldown": "انتظر بضع ثوانٍ قبل الفحص التالي.",
        "unreachable": "تعذّر الوصول إلى الموقع. تأكد من الرابط وحاول مجدداً. ({err})",
        "err_empty": "اكتب رابط الموقع أولاً.",
        "err_invalid": "الرابط غير صالح. مثال صحيح: example.com",
        "err_private": "لا يمكن فحص العناوين الداخلية أو الخاصة.",
        "err_port": "يُسمح بالمنفذين 80 و443 فقط.",
        "err_limit_client": "وصلت للحد الأقصى من الفحوصات في الساعة. حاول بعد {m} دقيقة تقريباً.",
        "err_limit_host": "فُحص هذا الموقع مرات كثيرة مؤخراً. حاول بعد {m} دقيقة تقريباً.",
        "err_limit_global": "الخدمة مشغولة حالياً. حاول بعد {m} دقيقة تقريباً.",
        "remaining": "المتبقي لك هذه الساعة: {n} فحوصات",
        "sec_findings": "الملاحظات",
        "sec_passed": "النقاط الآمنة",
        "none_findings": "لم نجد ملاحظات في الفحوصات الأساسية.",
        "none_passed": "لم تنجح أي فحوصات في هذه المرة.",
        "safe": "سليم",
        "note": "فحص أساسي وسلبي لا يغني عن اختبار اختراق شامل.",
        "download": "تنزيل التقرير (JSON)",
        "summary": lambda n, m: f"{n} ملاحظة · {m} فحص سليم" if n else f"لا ملاحظات · {m} فحص سليم",
        "sev": {"high": "عالية", "medium": "متوسطة", "low": "منخفضة", "info": "معلومة"},
        "grade": {"excellent": "ممتاز", "good": "جيد", "improve": "يحتاج تحسين", "weak": "ضعيف"},
    },
    "en": {
        "dir": "ltr", "end": "left",
        "title": "Website Security Scanner",
        "subtitle": "Paste your site's URL and get a report of vulnerabilities and passed checks in seconds.",
        "url_label": "Website URL",
        "consent": "I own this website or have written permission to scan it",
        "scan": "Scan website",
        "spinner": "Scanning…",
        "cooldown": "Please wait a few seconds before the next scan.",
        "unreachable": "Couldn't reach the website. Check the URL and try again. ({err})",
        "err_empty": "Enter a website URL first.",
        "err_invalid": "Invalid URL. Example: example.com",
        "err_private": "Internal or private addresses can't be scanned.",
        "err_port": "Only ports 80 and 443 are allowed.",
        "err_limit_client": "You've reached the hourly scan limit. Try again in about {m} minute(s).",
        "err_limit_host": "This website was scanned too many times recently. Try again in about {m} minute(s).",
        "err_limit_global": "The service is busy right now. Try again in about {m} minute(s).",
        "remaining": "Scans left for you this hour: {n}",
        "sec_findings": "Findings",
        "sec_passed": "Passed checks",
        "none_findings": "No findings in the basic checks.",
        "none_passed": "No checks passed this time.",
        "safe": "Passed",
        "note": "A basic, passive scan. It doesn't replace a full penetration test.",
        "download": "Download report (JSON)",
        "summary": lambda n, m: (f"{n} finding{'s' if n != 1 else ''} · {m} passed" if n
                                 else f"No findings · {m} passed"),
        "sev": {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "grade": {"excellent": "Excellent", "good": "Good", "improve": "Needs work", "weak": "Weak"},
    },
}


def text_of(item, lang):
    """Render (title, detail, fix) of a stored finding/passed item in the given language."""
    t, d, f = MSG[item["id"]][lang]
    p = item.get("p", {})
    return t.format(**p), d.format(**p), f.format(**p)


# ------------------------------------------------------------------ Rate limiting
class RateLimiter:
    """Sliding-window limits: per client, per target host, and global. Shared across sessions."""

    def __init__(self, per_client, per_host, global_limit, window=LIMIT_WINDOW):
        self.per_client, self.per_host, self.global_limit, self.window = per_client, per_host, global_limit, window
        self.hits = {}
        self.lock = threading.Lock()

    def _recent(self, key, now):
        lst = [t for t in self.hits.get(key, []) if now - t < self.window]
        if lst:
            self.hits[key] = lst
        else:
            self.hits.pop(key, None)
        return lst

    def check_and_record(self, client, host, now=None):
        """Returns (None, remaining_for_client) if allowed, else (kind, minutes_to_wait)."""
        now = time.time() if now is None else now
        keys = (("client", "c:" + client, self.per_client),
                ("host", "h:" + host, self.per_host),
                ("global", "g", self.global_limit))
        with self.lock:
            for kind, key, limit in keys:
                lst = self._recent(key, now)
                if len(lst) >= limit:
                    return kind, int((lst[0] + self.window - now) // 60) + 1
            for _, key, _ in keys:
                self.hits.setdefault(key, []).append(now)
            return None, self.per_client - len(self.hits["c:" + client])


@st.cache_resource
def get_limiter():
    return RateLimiter(PER_CLIENT_LIMIT, PER_HOST_LIMIT, GLOBAL_LIMIT)


def client_id():
    """Best-effort client key: forwarded IP when behind a proxy, else a per-session id."""
    try:
        h = st.context.headers
        ip = (h.get("X-Forwarded-For", "").split(",")[0].strip() or h.get("X-Real-Ip", "")).strip()
        if ip:
            return ip
    except Exception:
        pass
    return st.session_state.setdefault("_sid", uuid.uuid4().hex)


# ------------------------------------------------------------------ SSRF protection
def assert_public(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise requests.ConnectionError("DNS lookup failed")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise BlockedError("private")


def safe_get(url, headers=None, stream=True, verify=True):
    """GET that validates every redirect hop so the scanner can't reach internal networks."""
    hdrs = {**UA, **(headers or {})}
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(url)
        try:
            port = p.port
        except ValueError:
            raise BlockedError("port")
        if p.scheme not in ("http", "https") or not p.hostname or port not in ALLOWED_PORTS:
            raise BlockedError("port")
        assert_public(p.hostname)
        r = requests.get(url, headers=hdrs, timeout=TIMEOUT, allow_redirects=False,
                         stream=stream, verify=verify)
        loc = r.headers.get("Location")
        if r.is_redirect and loc:
            r.close()
            url = urljoin(url, loc)
            continue
        return r
    raise requests.TooManyRedirects("Too many redirects")


def read_text(r):
    data = b""
    for chunk in r.iter_content(65536):
        data += chunk
        if len(data) >= MAX_BODY:
            break
    r.close()
    return data.decode(r.encoding or "utf-8", errors="ignore")


def normalize(raw):
    """Returns a clean URL or raises ValueError('empty' | 'invalid')."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    try:
        p = urlparse(raw)
        host = p.hostname
        p.port
    except ValueError:
        raise ValueError("invalid")
    if not host or "." not in host or p.username:
        raise ValueError("invalid")
    return raw.rstrip("/")


# ------------------------------------------------------------------ Checks
def check_tls(host, rep):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert, ver = ss.getpeercert(), ss.version()
    except ssl.SSLCertVerificationError as e:
        rep.add("high", "tls_invalid", raw=str(e)[:160])
        return
    except Exception as e:
        rep.add("info", "tls_check_failed", raw=str(e)[:160])
        return
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (exp - datetime.now(timezone.utc)).days
    if days < 0:
        rep.add("high", "cert_expired", days=-days)
    elif days < 15:
        rep.add("medium", "cert_expiring", days=days)
    else:
        rep.ok("ok_cert", days=days)
    if ver not in ("TLSv1.2", "TLSv1.3"):
        rep.add("high", "tls_old", raw=ver)
    else:
        rep.ok("ok_tls", raw=ver)


def check_https_redirect(host, get, rep):
    try:
        r = get(f"http://{host}")
        final = r.url
        r.close()
    except (requests.RequestException, BlockedError):
        return
    if final.startswith("https://"):
        rep.ok("ok_redirect")
    else:
        rep.add("high", "no_https_redirect", raw=final)


HEADERS = {
    "Strict-Transport-Security": ("medium", "hsts"),
    "Content-Security-Policy": ("medium", "csp"),
    "X-Content-Type-Options": ("low", "xcto"),
    "Referrer-Policy": ("low", "refpol"),
    "Permissions-Policy": ("low", "perm"),
}


def check_headers(resp, rep):
    h = resp.headers
    present = []
    for name, (sev, code) in HEADERS.items():
        if name in h:
            present.append(name)
        else:
            rep.add(sev, "hdr_missing_" + code)
    if present:
        rep.ok("ok_headers", n=len(present), total=len(HEADERS), raw=", ".join(present))
    if "X-Frame-Options" in h or "frame-ancestors" in h.get("Content-Security-Policy", ""):
        rep.ok("ok_clickjack")
    else:
        rep.add("medium", "no_clickjack")
    leaks = [n for n in ("Server", "X-Powered-By", "X-AspNet-Version") if n in h and re.search(r"\d", h[n])]
    for n in leaks:
        rep.add("low", "version_leak", name=n, raw=h[n])
    if not leaks:
        rep.ok("ok_noleak")


def check_cookies(cookies, rep):
    if not cookies:
        return
    bad = 0
    for c in cookies:
        name, low = c.split("=", 1)[0], c.lower()
        missing = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if k not in low]
        if missing:
            bad += 1
            rep.add("medium", "cookie_flags", name=name, missing=", ".join(missing))
    if bad == 0:
        rep.ok("ok_cookies", n=len(cookies))


def check_cors(url, get, rep):
    try:
        r = get(url, headers={"Origin": "https://evil.example"})
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        r.close()
    except (requests.RequestException, BlockedError):
        return
    if acao == "https://evil.example" and creds:
        rep.add("high", "cors_reflect", raw=acao)
    elif acao == "*":
        rep.add("low", "cors_wild")
    else:
        rep.ok("ok_cors")


def check_content(final_url, body, rep):
    if 
