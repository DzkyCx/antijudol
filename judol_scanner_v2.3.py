#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════╗
║         JUDOL SCANNER - Web Security & Gambling Link Detector       ║
║    Iframe Injection | Clickjacking | Redirect | Judol Detection     ║
║              Untuk Tim IT Security yang Berwenang Saja              ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ══════════════════════════════════════════════════════
#  BAGIAN 1: AUTO-INSTALLER DEPENDENSI
# ══════════════════════════════════════════════════════
import subprocess, sys, os

DEPS = [
    ('requests',    'requests'),
    ('bs4',         'beautifulsoup4'),
    ('colorama',    'colorama'),
    ('tldextract',  'tldextract'),
    ('lxml',        'lxml'),
]

def _silent_install(pkg):
    subprocess.check_call(
        [sys.executable, '-m', 'pip', 'install', pkg, '-q'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

print("  [*] Memeriksa dependensi...", flush=True)
_missing = []
for mod, pkg in DEPS:
    try:
        __import__(mod)
    except ImportError:
        _missing.append(pkg)

if _missing:
    print(f"  [*] Menginstal: {', '.join(_missing)}")
    for pkg in _missing:
        try:
            _silent_install(pkg)
            print(f"      ✓ {pkg}")
        except Exception as e:
            print(f"      ✗ {pkg}: {e}")

# ══════════════════════════════════════════════════════
#  BAGIAN 2: IMPORTS
# ══════════════════════════════════════════════════════
import re, json, time, base64, socket, hashlib, csv, smtplib, threading, urllib.parse, webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
import tldextract

init(autoreset=True)

# ══════════════════════════════════════════════════════
#  BAGIAN 3: KONSTANTA & KONFIGURASI
# ══════════════════════════════════════════════════════
VERSION      = "2.3"
REPORT_DIR   = Path("reports")
HISTORY_FILE = Path("scan_history.json")
TIMEOUT      = 18
MAX_WORKERS  = 5
USER_AGENTS  = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

# ── Kata kunci judi (Indonesia + Inggris) ─────────────────────────────────────
GAMBLING_KW = [
    # Umum
    'judi','judol','taruhan','betting','kasino','casino','togel','toto','lotre',
    'lotere','buntut','angka jitu','prediksi togel','bocoran togel',
    # Data togel
    'data sgp','data hk','data sdy','pengeluaran hk','pengeluaran sgp',
    'result togel','live draw hk','live draw sgp','live draw sdy',
    'hk prize','sgp prize','keluaran hk','keluaran sgp','keluaran sdy',
    'nomor keluar','nomor jitu','angka keluar',
    # Slot & Casino
    'slot','slot online','slot gacor','slot gampang menang','slot rtp tinggi',
    'rtp live','rtp slot','maxwin','max win','scatter','free spin',
    'jackpot','progressive','pragmatic','pragmaticplay','pg soft','pgsoft',
    'habanero','joker123','joker388','joker gaming','spadegaming','cq9',
    'microgaming','playtech','netent','evolution gaming',
    'baccarat','roulette','blackjack','poker online','dominoqq',
    'domino99','capsa','ceme','samgong','gaple','qq online',
    # Nama game slot populer (sering dipakai SEO injection)
    'gates of olympus','gates olympus','olympus slot','olympus 1000',
    'sweet bonanza','starlight princess','mahjong ways','mahjong slot',
    'spaceman slot','wild west gold','the dog house','big bass','money train',
    'bonus buy','demo slot','main slot','main demo','tanpa deposit',
    'gratis tanpa deposit','main gratis','demo gratis','x1000','perkalian',
    # Sportsbook
    'sbobet','ibcbet','ibc','188bet','bola88','maxbet','cmd368',
    'bola online','judi bola','mix parlay','parlay','handicap',
    'over under','asian handicap','malay odds','hong kong odds',
    # Bisnis judol
    'agen judi','bandar judi','bandar togel','bandar slot',
    'agen slot','agen casino','agen togel','daftar slot',
    'daftar casino','daftar togel','link alternatif','link daftar',
    'link login','deposit slot','withdraw slot','bonus new member',
    'bonus deposit','cashback','turnover','rollover',
    'minimal deposit','no rek','rek slot','daftar sekarang judi',
    'menang judi','tips menang slot',
]

# ── Pola domain gambling ───────────────────────────────────────────────────────
GAMBLING_DOMAIN_RE = [
    r'togel\w*\.', r'slot\w*\.', r'judi\w*\.', r'poker\w*\.',
    r'casino\w*\.', r'bet\d+\.', r'sbobet\.', r'bandar\w+\.',
    r'\w+gacor\.', r'\w+maxwin\.', r'pragmatic\w+\.', r'\w+4d\.',
    r'sport\w+bet\.', r'live\w+casino\.', r'\w+jackpot\.',
    r'agen\w*slot\.', r'\w+scatter\.', r'rtp\w+\.',
    r'\w+judol\.', r'\w+taruhan\.', r'daftar\w+slot\.',
]

# ── TLD mencurigakan ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {'.xyz','.club','.online','.site','.live','.fun',
                   '.bet','.casino','.poker','.bingo','.win','.games'}

# ── Security headers yang harus dicek ──────────────────────────────────────────
SEC_HEADERS = {
    'x-frame-options':           ('HIGH', 'Rentan Clickjacking — Header X-Frame-Options tidak ada'),
    'content-security-policy':   ('HIGH', 'Tidak ada Content-Security-Policy'),
    'x-content-type-options':    ('MED',  'Tidak ada X-Content-Type-Options'),
    'strict-transport-security': ('MED',  'Tidak ada HSTS (HTTP Strict Transport Security)'),
    'x-xss-protection':          ('LOW',  'Tidak ada X-XSS-Protection'),
    'referrer-policy':           ('LOW',  'Tidak ada Referrer-Policy'),
    'permissions-policy':        ('LOW',  'Tidak ada Permissions-Policy'),
}

SEV_COLOR = {'HIGH': Fore.RED, 'MED': Fore.YELLOW, 'LOW': Fore.CYAN, 'INFO': Fore.BLUE}

# ══════════════════════════════════════════════════════
#  BAGIAN 4: HELPER UI
# ══════════════════════════════════════════════════════
R   = Fore.RED;    G  = Fore.GREEN;  Y  = Fore.YELLOW
B   = Fore.BLUE;   C  = Fore.CYAN;   M  = Fore.MAGENTA
W   = Fore.WHITE;  BR = Style.BRIGHT; DIM = Style.DIM; RST = Style.RESET_ALL

def _ok(m):    print(f"  {G}[✓]{RST} {m}")
def _warn(m):  print(f"  {Y}[!]{RST} {m}")
def _err(m):   print(f"  {R}[✗]{RST} {m}")
def _info(m):  print(f"  {C}[i]{RST} {m}")
def _found(m): print(f"  {M}[★]{RST} {m}")
def _step(m):  print(f"  {B}[→]{RST} {m}")
def _div(c='─', n=68): print(f"  {DIM}{c * n}{RST}")
def _clr():    os.system('clear' if os.name == 'posix' else 'cls')
def _pause():  input(f"\n  {DIM}Tekan Enter untuk lanjut...{RST}")

def _spinner(msg: str, done_event: threading.Event):
    chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    i = 0
    while not done_event.is_set():
        print(f"\r  {C}{chars[i % len(chars)]}{RST} {msg}", end='', flush=True)
        time.sleep(0.08)
        i += 1
    print(f"\r  {G}✓{RST} {msg:<60}", flush=True)

def _score_display(score: int) -> str:
    if score >= 70: return f"{R}{BR}{score}/100 [KRITIS]{RST}"
    if score >= 40: return f"{Y}{BR}{score}/100 [TINGGI]{RST}"
    if score >= 20: return f"{Y}{score}/100 [SEDANG]{RST}"
    return f"{G}{score}/100 [RENDAH]{RST}"

def _banner():
    _clr()
    b = f"""
{R}{BR}╔══════════════════════════════════════════════════════════════════════╗{RST}
{R}{BR}║{RST}  {Y}{BR}     ██╗██╗   ██╗██████╗  ██████╗ ██╗       ███████╗ ██████╗      {RST}{R}{BR}║{RST}
{R}{BR}║{RST}  {Y}{BR}     ██║██║   ██║██╔══██╗██╔═══██╗██║       ██╔════╝██╔════╝      {RST}{R}{BR}║{RST}
{R}{BR}║{RST}  {Y}{BR}     ██║██║   ██║██║  ██║██║   ██║██║       ███████╗██║           {RST}{R}{BR}║{RST}
{R}{BR}║{RST}  {Y}{BR}██   ██║██║   ██║██║  ██║██║   ██║██║       ╚════██║██║           {RST}{R}{BR}║{RST}
{R}{BR}║{RST}  {Y}{BR}╚█████╔╝╚██████╔╝██████╔╝╚██████╔╝███████╗  ███████║╚██████╗      {RST}{R}{BR}║{RST}
{R}{BR}║{RST}  {Y}{BR} ╚════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝  ╚══════╝ ╚═════╝     {RST}{R}{BR}║{RST}
{R}{BR}╠══════════════════════════════════════════════════════════════════════╣{RST}
{R}{BR}║{RST}   {C}{BR}Web Security & Gambling Link Detector  v{VERSION}{RST}                         {R}{BR}║{RST}
{R}{BR}║{RST}   {DIM}Iframe Injection │ Clickjacking │ Redirect │ Judol Detector        {RST}{R}{BR}║{RST}
{R}{BR}║{RST}   {DIM}Untuk penggunaan IT Security yang berwenang saja                   {RST}{R}{BR}║{RST}
{R}{BR}╚══════════════════════════════════════════════════════════════════════╝{RST}
"""
    print(b)

# ══════════════════════════════════════════════════════
#  BAGIAN 5: HTTP SESSION FACTORY
# ══════════════════════════════════════════════════════
def _make_session(ua_index: int = 0) -> requests.Session:
    sess    = requests.Session()
    retry   = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount('http://', adapter)
    sess.mount('https://', adapter)
    sess.headers.update({'User-Agent': USER_AGENTS[ua_index % len(USER_AGENTS)]})
    return sess

# ══════════════════════════════════════════════════════
#  BAGIAN 6: SCANNER ENGINE
# ══════════════════════════════════════════════════════
class JudolScanner:
    """
    Engine utama untuk mendeteksi:
    - Iframe Injection (visible & hidden)
    - Clickjacking (security headers)
    - URL Redirect (meta/JS/chain)
    - Hidden gambling links
    - Obfuscated JS
    - CSS-hidden content
    - Gambling keywords
    - WordPress/CMS enumeration
    """

    def __init__(self, url: str):
        self.raw_url  = url
        self.url      = self._norm(url)
        self.session  = _make_session()
        self.results: Dict = {
            'url':              self.url,
            'domain':           '',
            'scan_time':        datetime.now().isoformat(),
            'status_code':      None,
            'server':           '',
            'cms_detected':     '',
            'redirect_chain':   [],
            'final_url':        '',
            'is_gambling':      False,
            'risk_score':       0,
            'vulnerabilities':  [],
            'gambling_links':   [],
            'hidden_elements':  [],
            'iframes':          [],
            'js_redirects':     [],
            'security_headers': [],
            'obfuscated_js':    [],
            'suspicious_meta':  [],
            'wp_issues':        [],
            'seo_injections':   [],
            'errors':           [],
        }
        try:
            ext = tldextract.extract(self.url)
            self.results['domain'] = ext.registered_domain or self.url
        except Exception:
            self.results['domain'] = self.url

        self._resp: Optional[requests.Response] = None
        self._soup: Optional[BeautifulSoup]     = None
        self._body: str                          = ''
        self._bot_body: str                      = ''   # respons versi Googlebot UA
        self._bot_soup: Optional[BeautifulSoup] = None

    # ────────────────────────────────────────────────
    # HELPERS
    # ────────────────────────────────────────────────
    @staticmethod
    def _norm(url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _vuln(self, sev: str, category: str, detail: str, evidence: str = ''):
        self.results['vulnerabilities'].append({
            'severity': sev, 'category': category,
            'detail': detail, 'evidence': evidence[:250],
        })
        self.results['risk_score'] += {'HIGH': 30, 'MED': 15, 'LOW': 5, 'INFO': 1}.get(sev, 0)

    def _is_gambling_url(self, url: str) -> bool:
        if not url: return False
        ul = url.lower()
        if any(kw in ul for kw in GAMBLING_KW): return True
        if any(re.search(p, ul) for p in GAMBLING_DOMAIN_RE): return True
        try:
            ext = tldextract.extract(url)
            tld = f'.{ext.suffix}' if ext.suffix else ''
            sub = ext.subdomain.lower()
            dom = ext.domain.lower()
            if tld in SUSPICIOUS_TLDS:
                if any(k in dom or k in sub for k in ['slot','bet','judi','casino','togel','poker']): 
                    return True
        except Exception: pass
        return False

    def _is_gambling_text(self, text: str) -> bool:
        if not text or len(text) < 3: return False
        tl = text.lower()
        return sum(1 for kw in GAMBLING_KW if kw in tl) >= 2

    # ────────────────────────────────────────────────
    # 1. FETCH HALAMAN
    # ────────────────────────────────────────────────
    def fetch(self) -> bool:
        for attempt in range(2):
            try:
                resp = self.session.get(
                    self.url, timeout=TIMEOUT,
                    verify=False, allow_redirects=True,
                )
                self.results['status_code'] = resp.status_code
                self.results['final_url']   = resp.url
                self.results['server']      = resp.headers.get('Server', '')
                for r in resp.history:
                    self.results['redirect_chain'].append(
                        {'url': r.url, 'status': r.status_code}
                    )
                self._resp = resp
                self._body = resp.text
                try:
                    self._soup = BeautifulSoup(self._body, 'lxml')
                except Exception:
                    self._soup = BeautifulSoup(self._body, 'html.parser')

                # ── Fetch ulang dengan Googlebot UA untuk deteksi cloaking ──
                try:
                    _bot_resp = self.session.get(
                        self.url, timeout=TIMEOUT, verify=False,
                        allow_redirects=True,
                        headers={
                            'User-Agent': (
                                'Mozilla/5.0 (compatible; Googlebot/2.1; '
                                '+http://www.google.com/bot.html)'
                            )
                        }
                    )
                    self._bot_body = _bot_resp.text
                    try:
                        self._bot_soup = BeautifulSoup(self._bot_body, 'lxml')
                    except Exception:
                        self._bot_soup = BeautifulSoup(self._bot_body, 'html.parser')
                except Exception:
                    self._bot_body = ''
                    self._bot_soup = None

                return True

            except requests.exceptions.TooManyRedirects:
                self._vuln('HIGH', 'Redirect Loop', 'Terlalu banyak redirect – potensi redirect loop berbahaya')
                self.results['errors'].append('Too many redirects')
                return False
            except requests.exceptions.SSLError:
                if attempt == 0:
                    self._vuln('MED', 'SSL Error', 'Sertifikat SSL tidak valid atau expired')
                    continue
                self.results['errors'].append('SSL Error')
                return False
            except requests.exceptions.ConnectionError as e:
                self.results['errors'].append(f'Koneksi gagal: {e}')
                return False
            except requests.exceptions.Timeout:
                self.results['errors'].append(f'Request timeout ({TIMEOUT}s)')
                return False
            except Exception as e:
                self.results['errors'].append(str(e))
                return False
        return False

    # ────────────────────────────────────────────────
    # 2. CEK REDIRECT CHAIN
    # ────────────────────────────────────────────────
    def check_redirects(self):
        chain = self.results['redirect_chain']
        # Rantai redirect panjang
        if len(chain) >= 3:
            sev = 'HIGH' if len(chain) >= 5 else 'MED'
            self._vuln(sev, 'Suspicious Redirect Chain',
                f'Rantai redirect mencurigakan ({len(chain)} hop)',
                ' → '.join(c['url'] for c in chain[:6]))

        # Meta Refresh redirect
        if self._soup:
            for meta in self._soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)}):
                content = meta.get('content', '')
                url_m   = re.search(r'url\s*=\s*([^\s;]+)', content, re.I)
                dest    = url_m.group(1).strip('"\'') if url_m else content
                self.results['suspicious_meta'].append(dest)
                sev = 'HIGH' if self._is_gambling_url(dest) else 'MED'
                self._vuln(sev, 'Meta Refresh Redirect',
                    f'Meta Refresh redirect terdeteksi → {dest[:60]}', dest)
                if self._is_gambling_url(dest):
                    self.results['is_gambling'] = True
                    self.results['gambling_links'].append(
                        {'type': 'meta_refresh', 'url': dest, 'method': 'meta refresh redirect', 'text': ''})

        # JavaScript redirects
        if self._body:
            js_patterns = [
                r'window\.location\s*(?:\.href)?\s*=\s*["\']([^"\']{5,})["\']',
                r'window\.location\.replace\s*\(\s*["\']([^"\']{5,})["\']',
                r'window\.location\.assign\s*\(\s*["\']([^"\']{5,})["\']',
                r'document\.location\s*(?:\.href)?\s*=\s*["\']([^"\']{5,})["\']',
                r'location\.href\s*=\s*["\']([^"\']{5,})["\']',
                r'top\.location\s*=\s*["\']([^"\']{5,})["\']',
            ]
            seen = set()
            for pat in js_patterns:
                for m in re.finditer(pat, self._body, re.I):
                    dest = m.group(1)
                    if dest in seen: continue
                    seen.add(dest)
                    self.results['js_redirects'].append(dest)
                    if self._is_gambling_url(dest):
                        self._vuln('HIGH', 'JS Redirect → Judol',
                            f'JavaScript redirect ke situs judi: {dest[:80]}', dest)
                        self.results['is_gambling'] = True
                        self.results['gambling_links'].append(
                            {'type': 'js_redirect', 'url': dest, 'method': 'JavaScript redirect', 'text': ''})
                    elif not dest.startswith('/') and self.results['domain'] not in dest:
                        self._vuln('MED', 'JS External Redirect',
                            f'JavaScript redirect ke domain lain', dest[:80])

    # ────────────────────────────────────────────────
    # 3. CEK IFRAMES
    # ────────────────────────────────────────────────
    def check_iframes(self):
        if not self._soup: return
        for iframe in self._soup.find_all('iframe'):
            src   = (iframe.get('src') or '').strip()
            style = iframe.get('style', '')
            w     = str(iframe.get('width', ''))
            h     = str(iframe.get('height', ''))

            hidden = False
            reasons = []

            checks = [
                (r'display\s*:\s*none',          'display:none'),
                (r'visibility\s*:\s*hidden',      'visibility:hidden'),
                (r'opacity\s*:\s*0[^.]',          'opacity:0'),
                (r'width\s*:\s*0\s*(?:px)?[;]',  'width:0'),
                (r'height\s*:\s*0\s*(?:px)?[;]', 'height:0'),
                (r'position\s*:\s*absolute',      'absolute'),
                (r'(left|top)\s*:\s*-\d+',        'off-screen'),
                (r'z-index\s*:\s*-\d+',           'z-index negatif'),
                (r'overflow\s*:\s*hidden',         'overflow:hidden'),
            ]
            for pat, label in checks:
                if re.search(pat, style, re.I): hidden = True; reasons.append(label)
            if w in ('0','1','2'):  hidden = True; reasons.append(f'width={w}')
            if h in ('0','1','2'):  hidden = True; reasons.append(f'height={h}')

            entry = {'src': src, 'hidden': hidden, 'reasons': ', '.join(reasons), 'style': style[:120]}
            self.results['iframes'].append(entry)

            if hidden:
                self.results['hidden_elements'].append({'type': 'iframe', 'src': src, 'reason': ', '.join(reasons)})
                if src and self._is_gambling_url(src):
                    self._vuln('HIGH', 'Iframe Injection Judol',
                        f'Iframe tersembunyi inject ke situs judi! ({", ".join(reasons)})', src)
                    self.results['is_gambling'] = True
                    self.results['gambling_links'].append({'type': 'iframe', 'url': src, 'method': f'hidden iframe ({", ".join(reasons)})', 'text': ''})
                else:
                    self._vuln('HIGH', 'Hidden Iframe',
                        f'Iframe tersembunyi ({", ".join(reasons)})', src or 'no-src')
            elif src and self._is_gambling_url(src):
                self._vuln('HIGH', 'Iframe → Situs Judol',
                    f'Iframe mengarah ke situs judi', src)
                self.results['is_gambling'] = True
                self.results['gambling_links'].append({'type': 'iframe', 'url': src, 'method': 'iframe visible', 'text': ''})

    # ────────────────────────────────────────────────
    # 4. CEK SECURITY HEADERS (Clickjacking dll)
    # ────────────────────────────────────────────────
    def check_security_headers(self):
        if not self._resp: return
        headers_lower = {k.lower(): v for k, v in self._resp.headers.items()}

        for hdr, (sev, msg) in SEC_HEADERS.items():
            val = headers_lower.get(hdr)
            self.results['security_headers'].append({
                'header': hdr, 'status': 'PRESENT' if val else 'MISSING',
                'severity': sev, 'value': val or '',
            })
            if not val:
                self._vuln(sev, 'Security Header Missing', msg)

        # Nilai X-Frame-Options yang lemah
        xfo = headers_lower.get('x-frame-options', '')
        if xfo and xfo.upper() not in ('DENY', 'SAMEORIGIN'):
            self._vuln('HIGH', 'Clickjacking',
                f'X-Frame-Options bernilai lemah: {xfo} (harus DENY/SAMEORIGIN)')

        # CSP yang terlalu longgar
        csp = headers_lower.get('content-security-policy', '')
        if csp and 'unsafe-inline' in csp.lower():
            self._vuln('MED', 'CSP Lemah',
                "Content-Security-Policy mengizinkan 'unsafe-inline'")
        if csp and 'unsafe-eval' in csp.lower():
            self._vuln('MED', 'CSP Lemah',
                "Content-Security-Policy mengizinkan 'unsafe-eval'")
        if csp and 'frame-ancestors' not in csp.lower():
            self._vuln('MED', 'CSP No frame-ancestors',
                "CSP tidak mendefinisikan 'frame-ancestors' (tetap rentan Clickjacking)")

    # ────────────────────────────────────────────────
    # 5. CEK HIDDEN ELEMENTS & GAMBLING LINKS
    # ────────────────────────────────────────────────
    def check_hidden_elements(self):
        if not self._soup: return
        for a in self._soup.find_all('a', href=True):
            href  = (a.get('href') or '').strip()
            style = a.get('style', '')
            text  = a.get_text(strip=True)

            hidden  = False
            reasons = []

            checks = [
                (r'display\s*:\s*none',                          'display:none'),
                (r'visibility\s*:\s*hidden',                     'visibility:hidden'),
                (r'opacity\s*:\s*0[^.]',                         'opacity:0'),
                (r'font-size\s*:\s*0',                           'font-size:0'),
                (r'color\s*:\s*(#fff{0,3}|white|transparent)',   'warna tidak terlihat'),
                (r'(left|top)\s*:\s*-\d{3,}',                    'off-screen'),
                (r'clip\s*:\s*rect\s*\(\s*0',                    'clip:rect(0)'),
                (r'text-indent\s*:\s*-\d+',                      'text-indent negatif'),
            ]
            for pat, label in checks:
                if re.search(pat, style, re.I): hidden = True; reasons.append(label)

            if hidden:
                self.results['hidden_elements'].append(
                    {'type': 'link', 'href': href, 'text': text[:80], 'reason': ', '.join(reasons)})
                if self._is_gambling_url(href) or self._is_gambling_text(text):
                    self._vuln('HIGH', 'Hidden Gambling Link',
                        f'Link judi tersembunyi CSS ({", ".join(reasons)}): "{text[:50]}"', href)
                    self.results['is_gambling'] = True
                    self.results['gambling_links'].append(
                        {'type': 'link', 'url': href, 'text': text[:80], 'method': f'hidden link ({", ".join(reasons)})'})
                else:
                    self._vuln('MED', 'Hidden Link',
                        f'Link tersembunyi ({", ".join(reasons)}): "{text[:50] or href[:50]}"', href)

            elif href and (self._is_gambling_url(href) or self._is_gambling_text(text)):
                self._vuln('MED', 'Gambling Link Visible',
                    f'Link mengarah ke situs judi: "{text[:50]}"', href)
                self.results['is_gambling'] = True
                self.results['gambling_links'].append(
                    {'type': 'link', 'url': href, 'text': text[:80], 'method': 'visible link'})

    # ────────────────────────────────────────────────
    # 6. CEK CSS-HIDDEN CONTENT
    # ────────────────────────────────────────────────
    def check_css_hidden(self):
        if not self._soup: return
        css_patterns = [
            re.compile(r'display\s*:\s*none', re.I),
            re.compile(r'visibility\s*:\s*hidden', re.I),
            re.compile(r'opacity\s*:\s*0[^.]', re.I),
            re.compile(r'font-size\s*:\s*0', re.I),
            re.compile(r'color\s*:\s*(#fff{0,3}|white|rgba\(255,255,255,0\)|transparent)', re.I),
            re.compile(r'(left|top)\s*:\s*-\d{3,}', re.I),
            re.compile(r'text-indent\s*:\s*-9{2,}', re.I),
        ]
        tags = ['div', 'span', 'p', 'section', 'article', 'aside', 'li', 'ul']
        for pat in css_patterns:
            for el in self._soup.find_all(tags, style=pat):
                text = el.get_text(separator=' ', strip=True)
                if not text or len(text) < 10: continue
                if self._is_gambling_text(text):
                    snippet = text[:120]
                    self._vuln('HIGH', 'CSS Hidden Gambling Content',
                        'Konten judi disembunyikan melalui manipulasi CSS', snippet)
                    self.results['is_gambling'] = True
                    self.results['hidden_elements'].append(
                        {'type': 'css_text', 'text': snippet, 'reason': 'CSS visibility manipulation'})

    # ────────────────────────────────────────────────
    # 7. CEK OBFUSCATED JAVASCRIPT
    # ────────────────────────────────────────────────
    def check_obfuscated_js(self):
        if not self._soup: return
        for script in self._soup.find_all('script'):
            code = script.string or ''
            if len(code) < 100: continue
            flags = []

            # Base64 strings
            b64_matches = re.findall(r'[A-Za-z0-9+/]{60,}={0,2}', code)
            if len(b64_matches) > 2:
                flags.append(f'{len(b64_matches)} base64 string')
                for m in b64_matches[:5]:
                    try:
                        dec = base64.b64decode(m + '==').decode('utf-8', errors='ignore')
                        if self._is_gambling_text(dec) or self._is_gambling_url(dec):
                            self._vuln('HIGH', 'Obfuscated Judol (Base64)',
                                'Konten judi dienkode base64 dalam JavaScript', dec[:120])
                            self.results['is_gambling'] = True
                    except Exception: pass

            # Teknik obfuscation umum
            if re.search(r'\beval\s*\(',         code): flags.append('eval()')
            if re.search(r'\bFunction\s*\(',      code): flags.append('Function()')
            if re.search(r'\bunescape\s*\(',      code): flags.append('unescape()')
            if re.search(r'\\x[0-9a-f]{2}',       code): flags.append('hex encoding')
            if re.search(r'\\u[0-9a-f]{4}',       code): flags.append('unicode encoding')
            if re.search(r'String\.fromCharCode', code): flags.append('fromCharCode')
            if re.search(r'atob\s*\(',            code): flags.append('atob()')
            if len(re.findall(r'\b[a-z]{1,2}\d{1,3}\b', code)) > 25:
                flags.append('nama variabel acak')
            lines = code.strip().split('\n')
            if lines and len(lines[0]) > 8000:
                flags.append('sangat diminifikasi')

            if flags:
                snip = code[:100].replace('\n', ' ')
                self.results['obfuscated_js'].append({'flags': flags, 'snippet': snip})
                self._vuln('MED', 'Obfuscated JavaScript',
                    f'Script mencurigakan: {", ".join(flags)}', snip)

    # ────────────────────────────────────────────────
    # 8. CEK GAMBLING KEYWORDS DI HALAMAN
    # ────────────────────────────────────────────────
    def check_gambling_content(self):
        if not self._body: return
        body_l  = self._body.lower()
        kw_hits = [kw for kw in GAMBLING_KW if kw in body_l]
        if len(kw_hits) >= 5:
            self._vuln('HIGH', 'Gambling Content Masif',
                f'{len(kw_hits)} kata kunci judi terdeteksi di halaman',
                ', '.join(kw_hits[:12]))
            self.results['is_gambling'] = True
        elif len(kw_hits) >= 2:
            self._vuln('MED', 'Gambling Keywords',
                f'Beberapa kata kunci judi: {", ".join(kw_hits[:6])}')

        # Cek di <title> dan <meta>
        if self._soup:
            title = self._soup.title.string if self._soup.title else ''
            if title and self._is_gambling_text(title):
                self._vuln('HIGH', 'Gambling in Title',
                    f'Tag <title> mengandung konten judi: {title[:80]}')
                self.results['is_gambling'] = True
            for meta in self._soup.find_all('meta', attrs={'name': re.compile(r'(description|keywords)', re.I)}):
                content = meta.get('content', '')
                if self._is_gambling_text(content):
                    self._vuln('HIGH', 'Gambling in Meta',
                        f'Meta tag mengandung konten judi', content[:100])
                    self.results['is_gambling'] = True

    # ────────────────────────────────────────────────
    # 9. CEK NOSCRIPT INJECTION
    # ────────────────────────────────────────────────
    def check_noscript(self):
        if not self._soup: return
        for ns in self._soup.find_all('noscript'):
            inner = ns.get_text(separator=' ', strip=True)
            ns_html = str(ns)
            if self._is_gambling_text(inner) or self._is_gambling_text(ns_html):
                self._vuln('HIGH', '<noscript> Injection',
                    'Konten judi disembunyikan dalam tag <noscript>', inner[:100])
                self.results['is_gambling'] = True
            # Link tersembunyi dalam noscript
            for a in ns.find_all('a', href=True):
                href = a.get('href', '')
                if self._is_gambling_url(href):
                    self._vuln('HIGH', 'Noscript Gambling Link',
                        f'Link judi tersembunyi dalam <noscript>', href)
                    self.results['is_gambling'] = True
                    self.results['gambling_links'].append(
                        {'type': 'noscript', 'url': href, 'text': inner[:60], 'method': 'noscript injection'})

    # ────────────────────────────────────────────────
    # 10. CEK HTML COMMENT INJECTION
    # ────────────────────────────────────────────────
    def check_html_comments(self):
        if not self._body: return
        comments = re.findall(r'<!--(.*?)-->', self._body, re.DOTALL)
        for c in comments:
            if len(c) > 30 and (self._is_gambling_text(c) or self._is_gambling_url(c)):
                self._vuln('HIGH', 'HTML Comment Injection',
                    'Konten judi disembunyikan dalam HTML comment', c[:120])
                self.results['is_gambling'] = True

    # ────────────────────────────────────────────────
    # 11. DETEKSI CMS (WordPress dll)
    # ────────────────────────────────────────────────
    def detect_cms(self):
        if not self._body and not self._soup: return
        cms = ''
        if 'wp-content' in self._body or 'wp-includes' in self._body:
            cms = 'WordPress'
            # Cek file-file WordPress yang sering diserang
            wp_checks = [
                ('/wp-login.php',  'Login page WordPress exposed'),
                ('/xmlrpc.php',    'XML-RPC aktif (potensi brute force)'),
                ('/wp-json/',      'REST API WordPress terbuka'),
                ('/wp-config.php', 'Konfigurasi WordPress mungkin accessible'),
            ]
            for path, msg in wp_checks:
                try:
                    r = self.session.get(
                        self.url.rstrip('/') + path,
                        timeout=8, verify=False, allow_redirects=False
                    )
                    if r.status_code in (200, 403):
                        sev = 'HIGH' if 'wp-config' in path else 'MED'
                        self._vuln(sev, f'WordPress Issue', f'{msg} (HTTP {r.status_code})', path)
                        self.results['wp_issues'].append({'path': path, 'status': r.status_code, 'msg': msg})
                except Exception: pass

        elif 'Joomla' in self._body or '/components/com_' in self._body:
            cms = 'Joomla'
        elif 'drupal' in self._body.lower():
            cms = 'Drupal'
        elif 'laravel' in self._body.lower() or 'XSRF-TOKEN' in self._body:
            cms = 'Laravel'

        if cms:
            self.results['cms_detected'] = cms
            self._vuln('INFO', 'CMS Terdeteksi', f'Platform: {cms}')

    # ────────────────────────────────────────────────
    # 13. CEK GOOGLE CACHE (Cloaking Detection)
    # ────────────────────────────────────────────────
    def check_cloaking(self):
        """
        Deteksi cloaking: server menampilkan konten BERBEDA ke Googlebot vs user biasa.
        Inilah teknik utama yang dipakai pada gambar contoh (judol muncul di Google
        tapi tidak terlihat saat dibuka manual).

        Strategi:
        - _body     = respons normal (sudah di-fetch di fetch())
        - _bot_body = respons Googlebot (juga sudah di-fetch di fetch())
        - Bandingkan keyword judol, title, H1-H3, dan link judol di keduanya
        """
        if not self._body or not self._bot_body:
            return

        bot_body  = self._bot_body
        bot_soup  = self._bot_soup
        norm_body = self._body

        # ── A. Hitung keyword judol di tiap versi ────────────────────────
        normal_hits = sum(1 for kw in GAMBLING_KW if kw in norm_body.lower())
        bot_hits    = sum(1 for kw in GAMBLING_KW if kw in bot_body.lower())
        diff        = bot_hits - normal_hits

        # ── B. Bandingkan <title> ─────────────────────────────────────────
        normal_title = (self._soup.find('title') or BeautifulSoup('', 'html.parser')).get_text(strip=True) if self._soup else ''
        bot_title    = (bot_soup.find('title') or BeautifulSoup('', 'html.parser')).get_text(strip=True) if bot_soup else ''
        title_differs = normal_title.lower() != bot_title.lower()
        bot_title_judol = self._is_gambling_text(bot_title)

        # ── C. Kumpulkan H1–H3 judol yang ADA di bot tapi TIDAK di normal ─
        def _get_headings(soup):
            if not soup: return set()
            return {h.get_text(separator=' ', strip=True).lower()
                    for h in soup.find_all(['h1','h2','h3'])}

        normal_headings = _get_headings(self._soup)
        bot_headings    = _get_headings(bot_soup)
        injected_headings = [
            h for h in (bot_headings - normal_headings)
            if self._is_gambling_text(h)
        ]

        # ── D. Kumpulkan link judol yang ADA di bot tapi TIDAK di normal ──
        def _get_judol_links(soup):
            if not soup: return set()
            links = set()
            for a in soup.find_all('a', href=True):
                href = (a.get('href') or '').strip()
                text = a.get_text(separator=' ', strip=True).lower()
                if self._is_gambling_url(href) or self._is_gambling_text(text):
                    links.add(href)
            return links

        normal_links = _get_judol_links(self._soup)
        bot_links    = _get_judol_links(bot_soup)
        injected_links = bot_links - normal_links

        # ── E. Evaluasi & laporkan ────────────────────────────────────────
        cloaking_confirmed = (
            diff >= 3 or
            (title_differs and bot_title_judol) or
            len(injected_headings) > 0 or
            len(injected_links) > 0
        )
        cloaking_suspect = diff >= 1 and not cloaking_confirmed

        if cloaking_confirmed:
            evidence_parts = [
                f'Keyword diff: normal={normal_hits} vs Googlebot={bot_hits} (+{diff})',
            ]
            if title_differs and bot_title_judol:
                evidence_parts.append(f'Title Googlebot: "{bot_title[:80]}"')
            if injected_headings:
                evidence_parts.append(f'Heading injeksi: {", ".join(list(injected_headings)[:3])}')
            if injected_links:
                evidence_parts.append(f'Link judol eksklusif Googlebot: {", ".join(list(injected_links)[:3])}')

            full_evidence = ' | '.join(evidence_parts)
            self._vuln('HIGH', '🚨 CLOAKING TERDETEKSI',
                f'Server menampilkan konten judol HANYA ke Googlebot! {full_evidence}',
                full_evidence)
            self.results['is_gambling'] = True
            self.results['seo_injections'].append({
                'type': 'cloaking_confirmed',
                'evidence': full_evidence,
                'method': 'Content cloaking — Googlebot UA vs normal UA',
            })

            # Tambahkan link terinjeksi ke gambling_links
            for link in injected_links:
                self.results['gambling_links'].append({
                    'type': 'cloaked_link',
                    'url':  link,
                    'text': '',
                    'method': 'Hanya muncul di versi Googlebot (cloaking)',
                })

            # Jika heading terinjeksi, catat juga
            for h in injected_headings:
                self.results['seo_injections'].append({
                    'type': 'cloaked_heading',
                    'evidence': h[:150],
                    'method': 'Heading judol eksklusif Googlebot',
                })

        elif cloaking_suspect:
            self._vuln('MED', 'Kemungkinan Cloaking',
                f'Perbedaan kecil konten: normal={normal_hits} kw vs Googlebot={bot_hits} kw. '
                f'Periksa manual halaman dengan User-Agent Googlebot.',
                f'diff=+{diff}')
            self.results['seo_injections'].append({
                'type': 'cloaking_suspect',
                'evidence': f'Normal: {normal_hits} hits | Googlebot: {bot_hits} hits | Diff: +{diff}',
                'method': 'Possible cloaking (perbedaan minor)',
            })

    # ────────────────────────────────────────────────
    # 12. CEK SEO INJECTION / PARASITE BACKLINK
    # ────────────────────────────────────────────────
    def check_seo_injection(self):
        """
        Mendeteksi teknik SEO Injection / Parasite SEO yang digunakan judol:
        - Konten tersembunyi dengan class/id mencurigakan
        - Canonical tag dibajak ke domain judol
        - Structured data (JSON-LD/microdata) palsu
        - Anchor text judol dalam elemen apapun (walau tidak hidden)
        - Konten yang hanya muncul untuk crawler (cloaking hints)
        - Title/H1/H2 yang diinjeksi dengan keyword judol
        - Sitemap link mencurigakan
        - Link judol tercecer di mana saja dalam DOM
        """
        if not self._soup or not self._body: return

        # ── 12a. Cek <title> diinjeksi ───────────────────────────────────
        title_tag = self._soup.find('title')
        if title_tag:
            title_text = title_tag.get_text(strip=True)
            if self._is_gambling_text(title_text):
                self._vuln('HIGH', 'SEO Injection — Title Tag',
                    f'<title> halaman mengandung keyword judol: {title_text[:100]}',
                    title_text)
                self.results['is_gambling'] = True
                self.results['seo_injections'].append({
                    'type': 'title_injection',
                    'evidence': title_text[:150],
                    'method': 'Title tag injection'
                })

        # ── 12b. Cek H1/H2/H3 yang diinjeksi ────────────────────────────
        for tag in self._soup.find_all(['h1', 'h2', 'h3']):
            text = tag.get_text(separator=' ', strip=True)
            if len(text) < 5: continue
            if self._is_gambling_text(text):
                # Cek apakah heading ini di-hide
                style = tag.get('style', '')
                cls   = ' '.join(tag.get('class', []))
                hidden_hint = bool(re.search(
                    r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0', style, re.I))
                sev = 'HIGH'
                note = f'<{tag.name}> berisi keyword judol'
                if hidden_hint:
                    note += ' (DISEMBUNYIKAN)'
                self._vuln(sev, f'SEO Injection — {tag.name.upper()} Tag',
                    f'{note}: {text[:100]}', text)
                self.results['is_gambling'] = True
                self.results['seo_injections'].append({
                    'type': f'{tag.name}_injection',
                    'evidence': text[:150],
                    'method': f'{tag.name.upper()} tag injection' + (' (hidden)' if hidden_hint else '')
                })

        # ── 12c. Canonical tag dibajak ───────────────────────────────────
        for link in self._soup.find_all('link', rel=lambda x: x and 'canonical' in x):
            href = link.get('href', '')
            if href and self._is_gambling_url(href):
                self._vuln('HIGH', 'SEO Injection — Canonical Hijack',
                    f'Canonical URL diarahkan ke situs judol: {href[:100]}', href)
                self.results['is_gambling'] = True
                self.results['seo_injections'].append({
                    'type': 'canonical_hijack',
                    'evidence': href,
                    'method': 'Canonical tag hijacking'
                })

        # ── 12d. JSON-LD / Structured Data palsu ────────────────────────
        for script in self._soup.find_all('script', type=re.compile(r'application/ld\+json', re.I)):
            raw = script.string or ''
            if not raw.strip(): continue
            if self._is_gambling_text(raw) or self._is_gambling_url(raw):
                self._vuln('HIGH', 'SEO Injection — JSON-LD Palsu',
                    'Structured data (JSON-LD) mengandung konten judol', raw[:150])
                self.results['is_gambling'] = True
                self.results['seo_injections'].append({
                    'type': 'jsonld_injection',
                    'evidence': raw[:200],
                    'method': 'JSON-LD structured data injection'
                })

        # ── 12e. Anchor text judol (semua <a>, termasuk yang tidak hidden) ──
        # Ini menangkap backlink yang mungkin VISIBLE di mata crawler tapi
        # tersembunyi secara visual (warna sama dengan background, ukuran 1px, dll.)
        ANCHOR_JUDOL_KW = [
            'slot','togel','casino','kasino','judi','sbobet','poker','jackpot',
            'gacor','maxwin','scatter','bonus','deposit','daftar','login','pragmatic',
            'pg soft','habanero','rtp','demo slot','gates of olympus','sweet bonanza',
            'spaceman','mahjong','starlight princess','olympus','zeus slot',
        ]
        seen_hrefs: set = set()
        for a in self._soup.find_all('a', href=True):
            href  = (a.get('href') or '').strip()
            text  = a.get_text(separator=' ', strip=True).lower()
            style = a.get('style', '').lower()
            cls   = ' '.join(a.get('class', [])).lower()
            parent_style = ''
            parent = a.parent
            if parent:
                parent_style = (parent.get('style') or '').lower()

            if not href or href in seen_hrefs: continue
            seen_hrefs.add(href)

            anchor_has_judol = any(kw in text for kw in ANCHOR_JUDOL_KW)
            url_has_judol    = self._is_gambling_url(href)

            if not (anchor_has_judol or url_has_judol): continue

            # Tentukan apakah link ini disembunyikan dengan berbagai teknik
            hide_signals = []
            if re.search(r'display\s*:\s*none',      style): hide_signals.append('display:none')
            if re.search(r'visibility\s*:\s*hidden',  style): hide_signals.append('visibility:hidden')
            if re.search(r'opacity\s*:\s*0[^.]',      style): hide_signals.append('opacity:0')
            if re.search(r'font-size\s*:\s*[01]px',   style): hide_signals.append('font-size:0-1px')
            if re.search(r'color\s*:\s*(#fff|white|transparent|rgba\(255,255,255)', style):
                hide_signals.append('warna tak terlihat')
            if re.search(r'(left|top)\s*:\s*-\d{3,}', style): hide_signals.append('off-screen')
            if re.search(r'position\s*:\s*absolute',   style) and re.search(r'(left|top)\s*:\s*-', style):
                hide_signals.append('absolute off-screen')
            if re.search(r'display\s*:\s*none',       parent_style): hide_signals.append('parent:display:none')
            if re.search(r'visibility\s*:\s*hidden',  parent_style): hide_signals.append('parent:hidden')
            # Class mencurigakan yang sering dipakai injector
            if re.search(r'(hidden|invisible|d-none|sr-only|visually.hidden|offscreen)', cls):
                hide_signals.append(f'class:{cls[:40]}')

            sev    = 'HIGH'
            method = 'SEO parasite backlink'
            if hide_signals:
                method = f'Hidden SEO backlink ({", ".join(hide_signals)})'

            self._vuln(sev, 'SEO Injection — Parasite Backlink',
                f'{method}: anchor="{text[:60]}" → {href[:80]}',
                href)
            self.results['is_gambling'] = True
            self.results['gambling_links'].append({
                'type': 'seo_backlink',
                'url':  href,
                'text': text[:80],
                'method': method,
            })
            self.results['seo_injections'].append({
                'type': 'parasite_backlink',
                'evidence': f'anchor="{text[:60]}" → {href[:80]}',
                'method': method,
            })

        # ── 12f. Cek elemen dengan class/id khas SEO injector ────────────
        # Penyerang sering pakai wrapper div tersembunyi berisi banyak link
        INJECTOR_CLASS_RE = re.compile(
            r'(seo[-_]?inject|judol|judi|slot[-_]?link|hidden[-_]?link|'
            r'backlink|spam[-_]?link|inject[-_]?content|fake[-_]?content|'
            r'wrap[-_]?judi|konten[-_]?judol)',
            re.I
        )
        for el in self._soup.find_all(True):  # semua tag
            cls_str = ' '.join(el.get('class', []))
            id_str  = el.get('id', '')
            if INJECTOR_CLASS_RE.search(cls_str) or INJECTOR_CLASS_RE.search(id_str):
                inner = el.get_text(separator=' ', strip=True)[:150]
                self._vuln('HIGH', 'SEO Injection — Elemen Mencurigakan',
                    f'Elemen dengan class/id khas injeksi: class="{cls_str[:50]}" id="{id_str[:30]}"',
                    inner)
                self.results['seo_injections'].append({
                    'type': 'suspicious_element',
                    'evidence': f'class="{cls_str[:60]}" id="{id_str[:30]}" → {inner}',
                    'method': 'Suspicious class/id pattern'
                })

        # ── 12g. Cek konten teks judol dalam paragraf biasa ─────────────
        # Teknik "paragraph injection": teks judol disisipkan di artikel normal
        for tag in self._soup.find_all(['p', 'div', 'span', 'li', 'td']):
            text = tag.get_text(separator=' ', strip=True)
            # Harus minimal 20 karakter dan punya banyak keyword judol
            if len(text) < 20: continue
            kw_hits = [kw for kw in GAMBLING_KW if kw in text.lower()]
            if len(kw_hits) >= 3:
                style = (tag.get('style') or '').lower()
                # Hanya laporkan sebagai SEO injection jika belum tertangkap sebelumnya
                # dan tidak ada anak <a> yang sudah dilaporkan
                child_links = tag.find_all('a', href=True)
                if child_links: continue  # sudah tertangkap di 12e
                self._vuln('HIGH' if len(kw_hits) >= 5 else 'MED',
                    'SEO Injection — Paragraph Content',
                    f'Paragraf mengandung {len(kw_hits)} keyword judol: {", ".join(kw_hits[:6])}',
                    text[:150])
                self.results['is_gambling'] = True
                self.results['seo_injections'].append({
                    'type': 'paragraph_injection',
                    'evidence': text[:200],
                    'method': f'Paragraph text injection ({len(kw_hits)} keywords)'
                })

        # ── 12h. Cek meta description/keywords judol ────────────────────
        for meta in self._soup.find_all('meta'):
            name    = (meta.get('name') or meta.get('property') or '').lower()
            content = meta.get('content', '')
            if not content or name not in ('description', 'keywords', 'og:description', 'og:title'):
                continue
            if self._is_gambling_text(content):
                self._vuln('HIGH', 'SEO Injection — Meta Tag',
                    f'Meta <{name}> berisi konten judol', content[:150])
                self.results['is_gambling'] = True
                self.results['seo_injections'].append({
                    'type': 'meta_injection',
                    'evidence': f'{name}: {content[:150]}',
                    'method': 'Meta tag SEO injection'
                })

    # ────────────────────────────────────────────────
    # SCAN PENUH
    # ────────────────────────────────────────────────
    def scan(self) -> Dict:
        if not self.fetch():
            return self.results
        self.check_security_headers()
        self.check_redirects()
        self.check_iframes()
        self.check_hidden_elements()
        self.check_css_hidden()
        self.check_noscript()
        self.check_html_comments()
        self.check_gambling_content()
        self.check_obfuscated_js()
        self.detect_cms()
        self.check_seo_injection()
        self.check_cloaking()
        # Cap skor 0–100
        self.results['risk_score'] = min(self.results['risk_score'], 100)
        return self.results


# ══════════════════════════════════════════════════════
#  BAGIAN 7: REPORT GENERATOR
# ══════════════════════════════════════════════════════
def _save_history(r: Dict):
    history = []
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except Exception: pass
    history.append({
        'url': r['url'], 'domain': r['domain'],
        'scan_time': r['scan_time'],
        'risk_score': r['risk_score'],
        'is_gambling': r['is_gambling'],
        'vuln_count': len(r['vulnerabilities']),
        'gambling_count': len(r['gambling_links']),
        'cms': r.get('cms_detected', ''),
    })
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history[-200:], f, indent=2)

def generate_txt_report(r: Dict) -> Path:
    REPORT_DIR.mkdir(exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = re.sub(r'[^\w]', '_', r.get('domain', 'unknown'))
    path = REPORT_DIR / f"scan_{safe}_{ts}.txt"
    sep  = '═' * 68

    with open(path, 'w', encoding='utf-8') as f:
        def w(s=''): f.write(s + '\n')
        w(sep)
        w('  JUDOL SCANNER — LAPORAN KEAMANAN WEB')
        w(f"  Tanggal  : {datetime.now().strftime('%d %B %Y, %H:%M:%S WIB')}")
        w(f"  Tool     : JUDOL SCANNER v{VERSION}")
        w(sep)
        w()
        w(f"  URL          : {r['url']}")
        w(f"  Domain       : {r['domain']}")
        w(f"  Status HTTP  : {r.get('status_code', 'N/A')}")
        w(f"  URL Akhir    : {r.get('final_url', 'N/A')}")
        w(f"  Server       : {r.get('server', '-')}")
        w(f"  CMS          : {r.get('cms_detected', '-')}")
        w(f"  Situs Judol  : {'⚠ YA — PERLU TINDAK LANJUT' if r['is_gambling'] else 'Tidak terdeteksi'}")
        w(f"  Risk Score   : {r['risk_score']}/100")
        w()

        if r['redirect_chain']:
            w('  ' + '─'*66)
            w(f"  RANTAI REDIRECT ({len(r['redirect_chain'])} hop)")
            w('  ' + '─'*66)
            for hop in r['redirect_chain']:
                w(f"    [{hop['status']}] → {hop['url']}")
            w()

        w('  ' + '─'*66)
        w(f"  VULNERABILITIES DITEMUKAN ({len(r['vulnerabilities'])})")
        w('  ' + '─'*66)
        for i, v in enumerate(r['vulnerabilities'], 1):
            w(f"\n  [{i:02d}] [{v['severity']}] {v['category']}")
            w(f"        {v['detail']}")
            if v['evidence']:
                w(f"        Bukti: {v['evidence'][:150]}")
        w()

        if r['gambling_links']:
            w('  ' + '─'*66)
            w(f"  GAMBLING LINKS ({len(r['gambling_links'])})")
            w('  ' + '─'*66)
            for i, gl in enumerate(r['gambling_links'], 1):
                w(f"\n  [{i}] Metode : {gl['method']}")
                w(f"       URL    : {gl['url']}")
                if gl.get('text'): w(f"       Teks   : {gl['text']}")
            w()

        if r['iframes']:
            w('  ' + '─'*66)
            w(f"  IFRAMES ({len(r['iframes'])})")
            w('  ' + '─'*66)
            for ifr in r['iframes']:
                status = '⚠ TERSEMBUNYI' if ifr['hidden'] else 'OK'
                w(f"\n  [{status}] {ifr['src'] or 'no-src'}")
                if ifr['reasons']: w(f"     Alasan: {ifr['reasons']}")
            w()

        if r.get('seo_injections'):
            w('  ' + '─'*66)
            w(f"  SEO INJECTION / PARASITE BACKLINK ({len(r['seo_injections'])})")
            w('  ' + '─'*66)
            for i, si in enumerate(r['seo_injections'], 1):
                w(f"\n  [{i:02d}] Tipe    : {si['type']}")
                w(f"        Metode  : {si['method']}")
                if si.get('evidence'):
                    w(f"        Bukti   : {si['evidence'][:200]}")
            w()

        if r['security_headers']:
            w('  ' + '─'*66)
            w('  SECURITY HEADERS')
            w('  ' + '─'*66)
            for h in r['security_headers']:
                mark = '✓' if h['status'] == 'PRESENT' else '✗'
                w(f"  [{mark}] {h['header']:<40} [{h['status']}]")
                if h.get('value') and h['status'] == 'PRESENT':
                    w(f"       Value: {h['value'][:80]}")
            w()

        if r.get('errors'):
            w('  ERRORS')
            for e in r['errors']: w(f"  - {e}")
            w()

        w(sep)
        w('  END OF REPORT')
        w(sep)
    return path

def generate_json_report(r: Dict) -> Path:
    REPORT_DIR.mkdir(exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = re.sub(r'[^\w]', '_', r.get('domain', 'unknown'))
    path = REPORT_DIR / f"scan_{safe}_{ts}.json"
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(r, f, ensure_ascii=False, indent=2)
    return path


# ══════════════════════════════════════════════════════
#  BAGIAN 8: DMCA / KOMINFO REPORTER
# ══════════════════════════════════════════════════════
class Reporter:
    def __init__(self):
        self.sender      = ''
        self.app_pass    = ''
        self.configured  = False
        self._cfg_file   = Path('.reporter_config.json')
        self._load_config()

    def _load_config(self):
        if self._cfg_file.exists():
            try:
                d = json.loads(self._cfg_file.read_text())
                self.sender     = d.get('sender', '')
                self.app_pass   = d.get('app_pass', '')
                self.configured = bool(self.sender and self.app_pass)
            except Exception: pass

    def _save_config(self):
        self._cfg_file.write_text(json.dumps(
            {'sender': self.sender, 'app_pass': self.app_pass}))

    def setup_gmail(self) -> bool:
        print(f"\n  {C}Konfigurasi Gmail SMTP{RST}")
        _div()
        print(f"  {Y}Gunakan App Password Gmail, bukan password biasa.{RST}")
        print(f"  {DIM}Cara: myaccount.google.com → Keamanan → 2-Step → App Passwords{RST}\n")
        sender   = input(f"  {W}Email Gmail Anda   : {RST}").strip()
        app_pass = input(f"  {W}App Password Gmail : {RST}").strip()
        if not sender or not app_pass:
            _err("Email atau App Password kosong."); return False
        # Tes koneksi
        try:
            with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as s:
                s.ehlo(); s.starttls(); s.login(sender, app_pass)
            self.sender, self.app_pass, self.configured = sender, app_pass, True
            self._save_config()
            _ok("Koneksi Gmail berhasil ✓")
            return True
        except smtplib.SMTPAuthenticationError:
            _err("Autentikasi gagal. Periksa App Password Anda."); return False
        except Exception as e:
            _err(f"Gagal koneksi Gmail: {e}"); return False

    def send_gmail_report(self, gambling_url: str, victim_url: str,
                          evidence: str, attach: Optional[Path] = None) -> bool:
        if not self.configured:
            _err("Gmail belum dikonfigurasi."); return False

        subj = f"[Laporan Penyalahgunaan] Gambling Content Injection — {victim_url}"
        body = f"""Yth. Tim Google Legal / Safe Browsing,

Dengan hormat, kami melaporkan temuan konten perjudian online ilegal (judol) yang telah
diinjeksikan ke dalam sebuah situs web, melanggar kebijakan Google dan hukum Indonesia.

═══════════════════════════════════════════
  SITUS KORBAN (Yang Diinjeksi)
═══════════════════════════════════════════
URL       : {victim_url}
Masalah   : Iframe Injection / Hidden Link / URL Redirect ke situs judi
Ditemukan : {datetime.now().strftime('%d %B %Y, %H:%M WIB')}

═══════════════════════════════════════════
  SITUS JUDOL YANG DILAPORKAN
═══════════════════════════════════════════
URL       : {gambling_url}
Jenis     : Perjudian Online Ilegal (Judol)
Hukum     : Melanggar UU ITE No.11/2008 Pasal 27 ayat (2) dan KUHP Pasal 303

═══════════════════════════════════════════
  BUKTI TEKNIS
═══════════════════════════════════════════
{evidence}

═══════════════════════════════════════════
  TINDAKAN YANG DIMINTA
═══════════════════════════════════════════
1. Hapus {gambling_url} dari indeks Google Search
2. Tandai sebagai situs berbahaya di Google Safe Browsing
3. Cabut akses Google AdSense jika ada

Laporan ini juga diteruskan ke:
- Kominfo (aduankonten.id)
- BSSN (Badan Siber dan Sandi Negara)

Hormat kami,
Tim IT Security
Dilaporkan via: JUDOL SCANNER v{VERSION}
Waktu: {datetime.now().isoformat()}
"""
        try:
            msg = MIMEMultipart()
            msg['From']    = self.sender
            msg['To']      = 'legal@google.com'
            msg['Cc']      = 'safebrowsing-violations@google.com'
            msg['Subject'] = subj
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            if attach and attach.exists():
                with open(attach, 'rb') as fh:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(fh.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename="{attach.name}"')
                    msg.attach(part)
            with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as s:
                s.ehlo(); s.starttls()
                s.login(self.sender, self.app_pass)
                s.send_message(msg)
            _ok(f"Email laporan terkirim dari {self.sender}")
            return True
        except Exception as e:
            _err(f"Gagal kirim email: {e}")
            return False

    def generate_kominfo_report(self, gambling_url: str, victim_url: str = '') -> Path:
        REPORT_DIR.mkdir(exist_ok=True)
        ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = REPORT_DIR / f"kominfo_report_{ts}.txt"
        with open(path, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("  LAPORAN KONTEN NEGATIF INTERNET\n")
            f.write("  Kepada: Kominfo — https://aduankonten.id\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Tanggal Laporan  : {datetime.now().strftime('%d %B %Y, %H:%M WIB')}\n")
            f.write(f"Jenis Konten     : Perjudian Online Ilegal\n")
            f.write(f"URL Situs Judol  : {gambling_url}\n")
            if victim_url:
                f.write(f"URL Situs Korban : {victim_url}\n")
            f.write("\nDasar Hukum:\n")
            f.write("- UU ITE No. 11 Tahun 2008 Pasal 27 ayat (2) tentang konten perjudian\n")
            f.write("- KUHP Pasal 303 tentang Perjudian\n")
            f.write("- PM Kominfo No. 19 Tahun 2014 tentang Situs Internet Bermuatan Negatif\n\n")
            f.write("Keterangan Teknis:\n")
            f.write(f"Situs {gambling_url} teridentifikasi sebagai situs perjudian online\n")
            f.write("ilegal yang beroperasi di Indonesia. Situs ini menyediakan layanan\n")
            f.write("slot, togel, casino, dan/atau sportsbook online yang melanggar hukum.\n\n")
            f.write("Mohon segera dilakukan pemblokiran DNS dan/atau IP sesuai ketentuan.\n\n")
            f.write(f"Dibuat oleh  : JUDOL SCANNER v{VERSION}\n")
            f.write(f"Timestamp    : {datetime.now().isoformat()}\n")
        return path


# ══════════════════════════════════════════════════════
#  BAGIAN 8b: PELACAK DOMAIN JUDOL
# ══════════════════════════════════════════════════════
def trace_judol_domain(gambling_links: list) -> list:
    """
    Ikuti setiap gambling_link yang ditemukan, resolusi redirect sampai
    domain final, lalu kembalikan daftar domain judol asli yang unik.
    """
    session = _make_session()
    seen_domains: set = set()
    traces: list      = []

    unique_urls: list = []
    seen_urls: set    = set()
    for gl in gambling_links:
        url = (gl.get('url') or '').strip()
        if url and url not in seen_urls:
            if url.startswith('#') or url.startswith('/'):
                continue
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            seen_urls.add(url)
            unique_urls.append(url)

    for orig_url in unique_urls:
        entry = {
            'original_url' : orig_url,
            'final_url'    : orig_url,
            'final_domain' : '',
            'redirect_hops': 0,
            'chain'        : [orig_url],
            'ip'           : '',
            'status_code'  : None,
            'error'        : '',
        }
        try:
            resp = session.get(orig_url, timeout=10, verify=False, allow_redirects=True)
            entry['status_code']   = resp.status_code
            entry['final_url']     = resp.url
            entry['redirect_hops'] = len(resp.history)
            chain = [r.url for r in resp.history]
            chain.append(resp.url)
            entry['chain'] = chain
            try:
                ext = tldextract.extract(resp.url)
                entry['final_domain'] = ext.registered_domain or resp.url
            except Exception:
                from urllib.parse import urlparse
                entry['final_domain'] = urlparse(resp.url).netloc
            try:
                hostname = entry['final_domain'].split(':')[0]
                entry['ip'] = socket.gethostbyname(hostname)
            except Exception:
                entry['ip'] = 'Tidak dapat di-resolve'
        except requests.exceptions.TooManyRedirects:
            entry['error'] = 'Terlalu banyak redirect (redirect loop)'
        except requests.exceptions.ConnectionError:
            entry['error'] = 'Koneksi gagal — domain mungkin sudah offline/diblokir'
        except requests.exceptions.Timeout:
            entry['error'] = 'Timeout — server tidak merespons'
        except Exception as e:
            entry['error'] = str(e)[:120]

        fd = entry['final_domain']
        if fd and fd not in seen_domains:
            seen_domains.add(fd)
            traces.append(entry)
        elif not fd and entry.get('error'):
            traces.append(entry)

    return traces


def display_judol_traces(traces: list):
    """Tampilkan hasil pelacakan domain judol di terminal."""
    if not traces:
        print(f"\n  {Y}Tidak ada domain judol yang dapat dilacak.{RST}")
        return

    print(f"\n  {R}{'═'*68}{RST}")
    print(f"  {R}{BR}🕵  HASIL PELACAKAN DOMAIN JUDOL ASLI ({len(traces)} domain unik){RST}")
    print(f"  {R}{'═'*68}{RST}")

    for i, t in enumerate(traces, 1):
        ok = not t['error']
        print(f"\n  {R}{BR}[{i:02d}]{RST} {'OK' if ok else '!!'} {BR}{t['final_domain'] or '(tidak diketahui)'}{RST}")
        print(f"       {'─'*60}")
        print(f"       URL Awal     : {DIM}{t['original_url'][:80]}{RST}")
        if ok:
            if t['final_url'] != t['original_url']:
                print(f"       URL Final    : {C}{t['final_url'][:80]}{RST}")
            print(f"       Domain Judol : {R}{BR}{t['final_domain']}{RST}")
            print(f"       IP Server    : {Y}{t['ip']}{RST}")
            print(f"       Status HTTP  : {t['status_code']}")
            if t['redirect_hops'] > 0:
                print(f"       Redirect     : {t['redirect_hops']} hop(s)")
                for j, hop in enumerate(t['chain'], 1):
                    arrow = 'L-' if j == len(t['chain']) else '|-'
                    print(f"         {DIM}{arrow} [{j}] {hop[:72]}{RST}")
        else:
            print(f"       {Y}Error: {t['error']}{RST}")

    print(f"\n  {R}{'─'*68}{RST}")
    success = [t for t in traces if not t['error'] and t['final_domain']]
    if success:
        print(f"  {BR}Ringkasan Domain Judol Teridentifikasi:{RST}")
        for t in success:
            print(f"    {R}* {t['final_domain']:<35}{RST}  {DIM}IP: {t['ip']}{RST}")
    print(f"  {R}{'═'*68}{RST}\n")


# ══════════════════════════════════════════════════════
#  BAGIAN 9: TAMPILAN HASIL SCAN
# ══════════════════════════════════════════════════════
def display_results(r: Dict):
    _clr()
    score = r['risk_score']
    sc    = R if score >= 70 else (Y if score >= 30 else G)
    sl    = 'KRITIS' if score >= 70 else ('TINGGI' if score >= 40 else ('SEDANG' if score >= 20 else 'RENDAH'))

    print(f"\n  {BR}{'═'*68}{RST}")
    print(f"  {W}{BR}  HASIL SCAN — {r['url'][:55]}{RST}")
    print(f"  {'═'*68}")

    def row(lbl, val): print(f"  {DIM}{lbl:<20}{RST}: {val}")
    row("URL Target",     f"{C}{r['url'][:60]}{RST}")
    row("Domain",         r['domain'])
    row("Status HTTP",    str(r.get('status_code', 'N/A')))
    row("URL Akhir",      f"{DIM}{(r.get('final_url') or '-')[:60]}{RST}")
    row("Server",         r.get('server', '-') or '-')
    row("CMS",            r.get('cms_detected', '-') or '-')
    row("Situs Judol",    f"{R}{BR}⚠  YA — PERLU TINDAK LANJUT{RST}" if r['is_gambling'] else f"{G}Tidak terdeteksi{RST}")
    row("Risk Score",     f"{sc}{BR}{score}/100 [{sl}]{RST}")
    row("Vuln Ditemukan", str(len(r['vulnerabilities'])))
    row("Gambling Links", f"{(R+str(len(r['gambling_links']))) if r['gambling_links'] else str(0)}{RST}")
    row("Hidden Elements",str(len(r['hidden_elements'])))
    row("Iframes",        str(len(r['iframes'])))
    row("JS Redirects",   str(len(r['js_redirects'])))
    row("SEO Injections", f"{(R+str(len(r.get('seo_injections',[])))) if r.get('seo_injections') else str(0)}{RST}")

    if r['redirect_chain']:
        print(f"\n  {Y}{'─'*66}{RST}")
        print(f"  {Y}{BR}RANTAI REDIRECT ({len(r['redirect_chain'])} hop):{RST}")
        for hop in r['redirect_chain']:
            print(f"    {DIM}[{hop['status']}] → {hop['url'][:80]}{RST}")

    if r['vulnerabilities']:
        print(f"\n  {R}{'─'*66}{RST}")
        print(f"  {R}{BR}⚠  VULNERABILITIES ({len(r['vulnerabilities'])} ditemukan):{RST}")
        for i, v in enumerate(r['vulnerabilities'], 1):
            c2 = SEV_COLOR.get(v['severity'], W)
            print(f"\n  {c2}{BR}[{v['severity']:4}]{RST} {BR}{v['category']}{RST}")
            print(f"         {v['detail']}")
            if v['evidence']:
                print(f"         {DIM}↳ {v['evidence'][:90]}...{RST}" if len(v['evidence']) > 90
                      else f"         {DIM}↳ {v['evidence']}{RST}")

    if r['gambling_links']:
        print(f"\n  {M}{'─'*66}{RST}")
        print(f"  {M}{BR}🎰 GAMBLING LINKS DITEMUKAN ({len(r['gambling_links'])}):{RST}")
        for gl in r['gambling_links']:
            print(f"\n  {M}★{RST} {BR}[{gl['method']}]{RST}")
            print(f"    URL  : {R}{gl['url'][:90]}{RST}")
            if gl.get('text'): print(f"    Teks : {gl['text'][:60]}")

    if r.get('seo_injections'):
        print(f"\n  {Y}{'─'*66}{RST}")
        print(f"  {Y}{BR}🔍 SEO INJECTION / PARASITE BACKLINK ({len(r['seo_injections'])} ditemukan):{RST}")
        for i, si in enumerate(r['seo_injections'], 1):
            print(f"\n  {Y}[{i:02d}]{RST} {BR}{si['type'].replace('_',' ').upper()}{RST}")
            print(f"       Metode  : {si['method']}")
            ev = si.get('evidence','')
            if ev:
                print(f"       Bukti   : {DIM}{ev[:100]}{'...' if len(ev)>100 else ''}{RST}")

    if r['security_headers']:
        print(f"\n  {C}{'─'*66}{RST}")
        print(f"  {C}{BR}SECURITY HEADERS:{RST}")
        for h in r['security_headers']:
            mark = f"{G}✓{RST}" if h['status'] == 'PRESENT' else f"{R}✗{RST}"
            sev_c = SEV_COLOR.get(h.get('severity', ''), W) if h['status'] == 'MISSING' else ''
            print(f"    {mark} {h['header']:<42} {sev_c}[{h['status']}]{RST}")

    if r.get('errors'):
        print(f"\n  {Y}{'─'*66}{RST}")
        print(f"  {Y}ERRORS:{RST}")
        for e in r['errors']: print(f"  {DIM}  - {e}{RST}")

    print(f"\n  {'═'*68}")


# ══════════════════════════════════════════════════════
#  BAGIAN 10: MENU SISTEM
# ══════════════════════════════════════════════════════
reporter = Reporter()

def _menu_scan_single():
    _banner()
    print(f"  {C}{BR}[1] SCAN URL TUNGGAL{RST}")
    _div()
    url = input(f"\n  {W}Masukkan URL (contoh: https://example.com) : {RST}").strip()
    if not url: return

    print()
    done = threading.Event()
    t    = threading.Thread(target=_spinner, args=(f"Scanning {url[:50]}...", done), daemon=True)
    t.start()
    scanner = JudolScanner(url)
    results = scanner.scan()
    done.set(); time.sleep(0.15)

    display_results(results)
    _save_history(results)

    print(f"\n  {W}Tindakan lanjutan:{RST}")
    print(f"  {C}[1]{RST} Simpan laporan TXT")
    print(f"  {C}[2]{RST} Simpan laporan JSON")
    print(f"  {C}[3]{RST} Laporkan ke DMCA / Kominfo")
    if results.get('gambling_links'):
        print(f"  {R}[4]{RST} {BR}Lacak domain judol aslinya{RST}  {DIM}({len(results['gambling_links'])} link ditemukan){RST}")
    print(f"  {C}[0]{RST} Kembali ke menu")

    ch = input(f"\n  Pilihan : ").strip()
    if ch == '1':
        p = generate_txt_report(results)
        _ok(f"Laporan disimpan: {p}")
    elif ch == '2':
        p = generate_json_report(results)
        _ok(f"Laporan disimpan: {p}")
    elif ch == '3':
        _menu_report(results)
    elif ch == '4' and results.get('gambling_links'):
        print(f"\n  {C}Melacak {len(results['gambling_links'])} gambling link...{RST}")
        done = threading.Event()
        t    = threading.Thread(target=_spinner, args=("Mengikuti redirect...", done), daemon=True)
        t.start()
        traces = trace_judol_domain(results['gambling_links'])
        done.set(); time.sleep(0.12)
        display_judol_traces(traces)
        _pause()
        return
    _pause()

def _menu_scan_batch():
    _banner()
    print(f"  {C}{BR}[2] SCAN BATCH (BANYAK URL){RST}")
    _div()
    print(f"  {DIM}Buat file .txt dengan 1 URL per baris. Baris dimulai # diabaikan.{RST}\n")
    fpath = input(f"  {W}Path file URL : {RST}").strip()
    if not fpath or not Path(fpath).exists():
        _err("File tidak ditemukan."); _pause(); return

    with open(fpath) as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    if not urls:
        _warn("File kosong."); _pause(); return

    print(f"\n  {C}Memulai batch scan untuk {len(urls)} URL...{RST}\n")
    all_results   = []
    judol_list    = []
    high_risk     = []

    for i, url in enumerate(urls, 1):
        print(f"\n  {C}[{i:02d}/{len(urls):02d}]{RST} {url[:60]}")
        done = threading.Event()
        t    = threading.Thread(target=_spinner, args=("  Scanning...", done), daemon=True)
        t.start()
        sc = JudolScanner(url)
        r  = sc.scan()
        done.set(); time.sleep(0.12)

        if r['is_gambling']:
            _found(f"{R}JUDOL TERDETEKSI!{RST}  Risk={r['risk_score']}/100  Links={len(r['gambling_links'])}")
            judol_list.append(url)
        elif r['risk_score'] >= 40:
            _warn(f"Risk TINGGI: {r['risk_score']}/100 — {len(r['vulnerabilities'])} vuln")
            high_risk.append(url)
        else:
            _ok(f"Risk rendah: {r['risk_score']}/100")

        all_results.append(r)
        _save_history(r)
        time.sleep(0.3)

    # Ringkasan
    print(f"\n  {'═'*68}")
    print(f"  {W}{BR}RINGKASAN BATCH SCAN{RST}")
    _div()
    print(f"  Total URL   : {len(urls)}")
    print(f"  Judol       : {R}{BR}{len(judol_list)}{RST}")
    print(f"  Risk Tinggi : {Y}{len(high_risk)}{RST}")
    print(f"  Bersih      : {G}{len(urls) - len(judol_list) - len(high_risk)}{RST}")

    if judol_list:
        print(f"\n  {R}{BR}SITUS JUDOL DITEMUKAN:{RST}")
        for u in judol_list: print(f"  {R}★{RST} {u}")

    REPORT_DIR.mkdir(exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    bp   = REPORT_DIR / f"batch_{ts}.json"
    with open(bp, 'w') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    _ok(f"Laporan batch disimpan: {bp}")
    _pause()

def _menu_report(last_results: Optional[Dict] = None):
    _banner()
    print(f"  {C}{BR}[3] LAPORAN DMCA & KOMINFO{RST}")
    _div()

    if last_results and last_results.get('gambling_links'):
        print(f"  {Y}Hasil scan terakhir — gambling links:{RST}")
        for i, gl in enumerate(last_results['gambling_links'], 1):
            print(f"  [{i}] {gl['url'][:70]}")
        gambling_url = last_results['gambling_links'][0]['url']
        victim_url   = last_results['url']
        print(f"\n  {DIM}Menggunakan data dari scan terakhir.{RST}")
        print(f"  Situs Judol   : {R}{gambling_url[:60]}{RST}")
        print(f"  Situs Korban  : {victim_url[:60]}")
        ok_data = input(f"\n  Gunakan data ini? [Y/n] : ").strip().lower()
        if ok_data == 'n':
            gambling_url = input(f"  URL Situs Judol  : ").strip()
            victim_url   = input(f"  URL Situs Korban : ").strip()
    else:
        gambling_url = input(f"\n  URL Situs Judol  : ").strip()
        victim_url   = input(f"  URL Situs Korban : ").strip()

    if not gambling_url:
        _err("URL tidak boleh kosong."); _pause(); return

    print(f"\n  {W}Pilih metode laporan:{RST}")
    print(f"  {C}[1]{RST} Buat laporan Kominfo (aduankonten.id) — Format siap upload")
    print(f"  {C}[2]{RST} Kirim laporan via Gmail SMTP")
    print(f"  {C}[3]{RST} Buka Google Safe Browsing Report di browser")
    print(f"  {C}[4]{RST} Buka semua channel pelaporan sekaligus")
    print(f"  {C}[0]{RST} Kembali")

    ch = input(f"\n  Pilihan : ").strip()

    if ch == '1':
        p = reporter.generate_kominfo_report(gambling_url, victim_url)
        _ok(f"Laporan Kominfo disimpan: {p}")
        print(f"\n  {Y}→ Upload file ini ke: {C}https://aduankonten.id{RST}")

    elif ch == '2':
        if not reporter.configured:
            _warn("Gmail belum dikonfigurasi.")
            if input("  Konfigurasi sekarang? [Y/n] : ").lower() != 'n':
                if not reporter.setup_gmail():
                    _pause(); return
            else:
                _pause(); return
        evidence = f"Situs judol ditemukan terinjeksi di: {victim_url}\n"
        if last_results:
            for gl in last_results.get('gambling_links', []):
                evidence += f"  [{gl['method']}] {gl['url']}\n"
            attach = generate_txt_report(last_results)
        else:
            attach = None
        reporter.send_gmail_report(gambling_url, victim_url, evidence, attach)

    elif ch == '3':
        enc = urllib.parse.quote(gambling_url)
        urls_to_open = [
            f"https://safebrowsing.google.com/safebrowsing/report_badware/?url={enc}",
        ]
        print(f"\n  {C}Link untuk dilaporkan:{RST}")
        for u in urls_to_open: print(f"  → {u}")
        try:
            webbrowser.open(urls_to_open[0])
            _ok("Browser dibuka.")
        except Exception: _warn("Tidak bisa membuka browser otomatis. Salin URL di atas.")

    elif ch == '4':
        enc  = urllib.parse.quote(gambling_url)
        links = [
            ('Google Safe Browsing', f"https://safebrowsing.google.com/safebrowsing/report_badware/?url={enc}"),
            ('Kominfo Aduan Konten', 'https://aduankonten.id'),
            ('Google Report Gambling', 'https://reportcontent.google.com/forms/gambling'),
            ('BSSN Aduan Siber',      'https://www.bssn.go.id/laporkan-insiden/'),
        ]
        print(f"\n  {C}Link pelaporan:{RST}")
        for lbl, u in links: print(f"  → {lbl:25} : {u}")
        try:
            for _, u in links: webbrowser.open(u); time.sleep(0.5)
            _ok("Browser dibuka untuk semua channel.")
        except Exception: pass
        p = reporter.generate_kominfo_report(gambling_url, victim_url)
        _ok(f"Laporan Kominfo disimpan: {p}")

    _pause()

def _menu_history():
    _banner()
    print(f"  {C}{BR}[4] RIWAYAT SCAN{RST}")
    _div()
    if not HISTORY_FILE.exists():
        _warn("Belum ada riwayat scan."); _pause(); return
    try:
        with open(HISTORY_FILE) as f:
            history = json.load(f)
        if not history:
            _warn("Riwayat kosong."); _pause(); return

        print(f"\n  {'#':<4} {'URL':<42} {'Score':<7} {'Judol':<7} {'Vuln':<6} {'CMS':<10} {'Tanggal'}")
        _div()
        for i, h in enumerate(reversed(history[-20:]), 1):
            jd   = f"{R}YA   {RST}" if h['is_gambling'] else f"{G}Tidak{RST}"
            s    = h['risk_score']
            sc   = (R if s >= 70 else (Y if s >= 40 else G))
            url  = h['url'][:40] + '..' if len(h['url']) > 42 else h['url']
            date = h['scan_time'][:10]
            cms  = h.get('cms', '-') or '-'
            print(f"  {i:<4} {url:<42} {sc}{s:>3}{RST}/100  {jd}  {h['vuln_count']:<6} {cms:<10} {date}")
    except Exception as e:
        _err(f"Gagal baca riwayat: {e}")
    _pause()

def _menu_settings():
    _banner()
    print(f"  {C}{BR}[5] PENGATURAN{RST}")
    _div()
    print(f"  {C}[1]{RST} Konfigurasi Gmail SMTP (untuk laporan email)")
    print(f"  {C}[2]{RST} Lihat status konfigurasi")
    print(f"  {C}[3]{RST} Reset konfigurasi Gmail")
    print(f"  {C}[0]{RST} Kembali")

    ch = input(f"\n  Pilihan : ").strip()
    if ch == '1':
        reporter.setup_gmail()
    elif ch == '2':
        _div()
        if reporter.configured:
            _ok(f"Gmail aktif  : {reporter.sender}")
        else:
            _warn("Gmail       : belum dikonfigurasi")
        _ok(f"Report dir  : {REPORT_DIR.resolve()}")
        _ok(f"Riwayat     : {HISTORY_FILE.resolve()}")
    elif ch == '3':
        reporter.sender = ''; reporter.app_pass = ''; reporter.configured = False
        if reporter._cfg_file.exists(): reporter._cfg_file.unlink()
        _ok("Konfigurasi Gmail direset.")
    _pause()

def _menu_about():
    _banner()
    print(f"  {C}{BR}TENTANG JUDOL SCANNER v{VERSION}{RST}")
    _div()
    features = [
        "✓ Deteksi Iframe Injection (hidden/visible)",
        "✓ Deteksi Clickjacking (security headers)",
        "✓ Deteksi Redirect Berbahaya (meta/JS/chain)",
        "✓ Deteksi Hidden Gambling Links (CSS manipulation)",
        "✓ Deteksi Gambling Keywords (200+ kata kunci)",
        "✓ Deteksi Obfuscated JavaScript & Base64",
        "✓ Deteksi <noscript> & HTML Comment Injection",
        "✓ CMS Detection (WordPress, Joomla, dll)",
        "✓ WordPress Security Check",
        "✓ Scan Batch dari file .txt",
        "✓ Laporan TXT & JSON",
        "✓ Laporan DMCA via Gmail SMTP",
        "✓ Generate laporan untuk Kominfo (aduankonten.id)",
        "✓ Riwayat scan (200 entri terakhir)",
    ]
    for f in features: print(f"  {G}{f}{RST}")
    print(f"\n  {DIM}Channel Pelaporan Judol:{RST}")
    print(f"  {C}→ Kominfo       : https://aduankonten.id{RST}")
    print(f"  {C}→ BSSN          : https://www.bssn.go.id/laporkan-insiden/{RST}")
    print(f"  {C}→ Google SafeBr. : https://safebrowsing.google.com/safebrowsing/report_badware/{RST}")
    print(f"  {C}→ Google Gambling: https://reportcontent.google.com/forms/gambling{RST}")
    _pause()


# ══════════════════════════════════════════════════════
#  BAGIAN 11: MAIN LOOP
# ══════════════════════════════════════════════════════
def main():
    while True:
        _banner()
        print(f"  {W}{BR}MENU UTAMA{RST}")
        _div()
        print(f"\n  {C}[1]{RST}  Scan URL Tunggal")
        print(f"  {C}[2]{RST}  Scan Batch (dari file .txt)")
        print(f"  {C}[3]{RST}  Laporan DMCA & Kominfo")
        print(f"  {C}[4]{RST}  Riwayat Scan")
        print(f"  {C}[5]{RST}  Pengaturan Gmail")
        print(f"  {C}[6]{RST}  Tentang & Channel Pelaporan")
        print(f"\n  {R}[0]{RST}  Keluar")
        _div()

        if reporter.configured:
            print(f"  {DIM}Gmail: {reporter.sender} ✓{RST}")
        else:
            print(f"  {DIM}Gmail: belum dikonfigurasi{RST}")

        ch = input(f"\n  {W}Pilihan [{C}0-6{W}] : {RST}").strip()

        if   ch == '1': _menu_scan_single()
        elif ch == '2': _menu_scan_batch()
        elif ch == '3': _menu_report()
        elif ch == '4': _menu_history()
        elif ch == '5': _menu_settings()
        elif ch == '6': _menu_about()
        elif ch == '0':
            _clr()
            print(f"\n  {G}Terima kasih telah menggunakan JUDOL SCANNER v{VERSION}{RST}")
            print(f"  {DIM}Stay safe, fight judol! 🛡️{RST}\n")
            sys.exit(0)
        # Pilihan tidak valid: loop ulang tanpa pesan error


# ══════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Dibatalkan. Sampai jumpa!{RST}\n")
        sys.exit(0)
    except Exception as exc:
        print(f"\n  {R}Error tidak terduga: {exc}{RST}")
        import traceback; traceback.print_exc()
        sys.exit(1)
