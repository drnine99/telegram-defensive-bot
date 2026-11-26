"""بوت فحص دفاعي V26 (Baseline + Hybrid) - ملف واحد: python3 bot.py
أول تشغيل ينشئ ملف .env بقيم توضيحية ويوقف؛ املأه بالتوكن الجديد ورقمك ثم شغّل نفس الأمر تاني.
كل الشغل من شات المالك الخاص: ابعت الدومين أو الرابط مباشرة، أو استخدم الأوامر.

ما يفعله البوت عند إرسال رابط:
1) فحوصات سلبية مبدئية تعمل دائماً: شهادة TLS، هيدرز الحماية، خصائص الكوكيز، التحويل من HTTP إلى HTTPS.
   الاتصال المباشر يتم إلى عنوان IP تم التحقق أنه عام (بدون متابعة تحويلات).
2) الفحص العميق (تحليل JS عن أنماط أسرار شائعة + زحف Katana + قوالب Nuclei) يعمل فقط لو
   ENABLE_ACTIVE_SCAN=true في .env، وهو مقفول افتراضياً.
3) /zap example.com يشغّل ZAP Baseline عبر Docker لو ENABLE_ZAP=true (مقفول افتراضياً).
   ZAP يعمل داخل Docker ويتصل بالشبكة بنفسه، فحماية تثبيت الـIP في الفحوصات المباشرة لا تشمله.
4) /observatory example.com فحص خارجي عند Mozilla لو ENABLE_OBSERVATORY=true (مقفول افتراضياً)،
   ويطلب تأكيد /confirm قبل إرسال اسم الدومين لهم.

حدود مهمة: البوت لا يكتشف كل الملفات أو الفولدرات المكشوفة، ولا يضمن العثور على كل الأسرار.
غياب النتائج لا يعني أن الموقع آمن. نطاق الاستخدام: أهداف مملوكة لك أو مصرح لك كتابيًا بفحصها فقط."""
import asyncio
import http.client
import ipaddress
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import types
import unicodedata
import re
import time
import logging
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse, urljoin

# محاولة استيراد مكتبات تحليل الويب (سيتم تثبيتها تلقائياً)
try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    pass # سيتم تثبيتها في ensure_runtime

BOT_VERSION = "V26.3 (Baseline + Hybrid)"
MAX_JS_FILES_SHOWN = 30
MAX_LINKS = 50
MAX_FINDINGS = 30
KATANA_TIMEOUT = 180
NUCLEI_TIMEOUT = 600
ZAP_TIMEOUT = 600
NUCLEI_TAGS = "cve,sqli,xss,rce,lfi,rfi,ssrf,idor,auth-bypass,cms,exposure"
SEVERITIES = "critical,high,medium"
UA = "v26-baseline-hybrid/1"

HEADERS_WANTED = {"strict-transport-security": "HSTS", "content-security-policy": "CSP",
                  "x-content-type-options": "X-Content-Type-Options", "referrer-policy": "Referrer-Policy"}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(SCRIPT_DIR, ".env")
LOCK_PATH = os.path.join(SCRIPT_DIR, ".bot.lock")
TARGETS_PATH = os.path.join(SCRIPT_DIR, "targets.json")
MAX_DYNAMIC_TARGETS = 50
VENV_DIR = os.path.join(SCRIPT_DIR, "venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")

ENV_TEMPLATE = """\
BOT_TOKEN=PUT_NEW_TOKEN_HERE
OWNER_ID=PUT_YOUR_NUMERIC_TELEGRAM_ID
ALLOWED_TARGETS=
ENABLE_ACTIVE_SCAN=false
ENABLE_ZAP=false
ENABLE_OBSERVATORY=false
"""

HELP = ("أوامر البوت (من شات المالك الخاص فقط):\n"
        "أرسل الدومين أو الرابط مباشرة، أو /scan example.com : الفحوصات السلبية دائماً + الفحص العميق لو مفعّل.\n"
        "/zap example.com : فحص ZAP السلبي عبر Docker (لو ENABLE_ZAP=true). ZAP يتصل بنفسه وحماية تثبيت الـIP لا تشمله.\n"
        "/observatory example.com : فحص خارجي عند Mozilla (لو ENABLE_OBSERVATORY=true)، يرسل اسم الدومين لهم بعد تأكيدك بـ /confirm.\n"
        "/status : تقرير حالة الاعتماديات (أدوات الفحص الخارجية) وما تم تثبيته وما يحتاج خطوة يدوية.\n"
        "المحدود: لا يكتشف كل الملفات/الفولدرات المكشوفة ولا يضمن كل الأسرار. غياب النتائج لا يعني الأمان.")

# تعبيرات منتظمة لصيد الأسرار
SECRET_PATTERNS = {
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Firebase Config": r"firebaseConfig\s*=\s*\{[^}]+\}",
    "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24}",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "GreenAPI": r"(?i)green[_-]?api[\"']?\s*[:=]\s*[\"']([a-f0-9]{32,50})[\"']", # مفتاح GreenAPI مع سياقه لتفادي الإيجابيات الكاذبة
    "Generic API Key": r"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{15,})[\"']",
    "Hidden Endpoint": r"[\"'](/api/[a-zA-Z0-9_\-/]+)[\"']"
}

class ConfigError(Exception):
    pass

def parse_env_file(path):
    values = {}
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"): continue
            if "=" not in line: raise ConfigError(f".env سطر غير مفهوم {lineno}")
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip()
    return values

ENV_KEYS = ("BOT_TOKEN", "OWNER_ID", "ALLOWED_TARGETS", "ENABLE_ACTIVE_SCAN", "ENABLE_ZAP", "ENABLE_OBSERVATORY")

def merged_env(path=None, env=None):
    path = path or ENV_PATH
    env = os.environ if env is None else env
    out = dict(parse_env_file(path))
    for key in ENV_KEYS:
        if env.get(key): out[key] = env[key]
    return out

def ensure_env_file(path=None):
    path = path or ENV_PATH
    if os.path.exists(path): return True
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f: f.write(ENV_TEMPLATE)
    return False

def parse_allowlist(raw):
    out = set()
    for item in raw.split(","):
        item = item.strip().lower().rstrip(".")
        if item and "/" not in item and ":" not in item and "*" not in item:
            out.add(item)
    return frozenset(out)

def load_config(env=None):
    env = os.environ if env is None else env
    token = env.get("BOT_TOKEN", "").strip()
    owner = env.get("OWNER_ID", "").strip()
    if not owner.isdigit(): raise ConfigError("OWNER_ID غير صالح")
    if not token or token == "PUT_NEW_TOKEN_HERE": raise ConfigError("BOT_TOKEN غير مضبوط في ملف .env")
    t = lambda k: env.get(k, "false").strip().lower() == "true"
    return {
        "token": token,
        "owner_id": int(owner),
        "allowlist": parse_allowlist(env.get("ALLOWED_TARGETS", "")),
        "active_scan": t("ENABLE_ACTIVE_SCAN"),
        "zap": t("ENABLE_ZAP"),
        "observatory": t("ENABLE_OBSERVATORY"),
    }

# ---------- الأهداف المضافة من محادثة المالك ----------
def load_dynamic_targets(path=None):
    path = path or TARGETS_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return {h for h in (str(x).strip().lower().rstrip(".") for x in data) if h}
    except (OSError, ValueError):
        pass
    return set()

def save_dynamic_targets(targets, path=None):
    path = path or TARGETS_PATH
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(targets), f)
    os.replace(tmp, path)

# ---------- إدارة الشبكة والأهداف ----------
def resolve_all(host):
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]

def host_is_public(host, resolver=resolve_all):
    try:
        addrs = resolver(host)
        return bool(addrs) and all(a.is_global for a in addrs)
    except Exception: return False

def strict_host(raw):
    """يستخرج اسم دومين عام صالح من نص المستخدم. يرفض بيانات الدخول والبورتات غير القياسية وعناوين IP."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 253 or any(c.isspace() for c in raw): return None
    url = raw if raw.lower().startswith(("http://", "https://")) else "https://" + raw
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except ValueError: return None
    if not host or p.username or p.password or port not in (None, 80, 443): return None
    try:
        ipaddress.ip_address(host); return None
    except ValueError: pass
    if "." not in host or host.endswith((".local", ".internal", ".localhost")): return None
    return host

def validate_target(raw, allowlist, resolver=resolve_all):
    """للفحص العميق وأهداف سبق قبولها: العضوية في القائمة المصرح بها + عنوان عام. يعيد (ok, host_or_reason, ips)."""
    host = strict_host(raw)
    if not host: return False, "اكتب اسم الدومين فقط بدون بيانات دخول أو بورت غير قياسي", []
    if host not in allowlist: return False, "الهدف خارج القائمة المصرح بها", []
    try: ips = resolver(host)
    except Exception: return False, "تعذر حل اسم الدومين", []
    if not ips or not all(a.is_global for a in ips): return False, "الهدف داخلي أو غير عام", []
    return True, host, ips

def admit_target(raw, cfg, resolver=resolve_all):
    """سير العمل الأصلي: إرسال رابط من شات المالك يقبل الهدف ويضيفه للأهداف الديناميكية.
    القبول هنا آلية تشغيل فقط، وليس إثبات ملكية؛ مسؤولية التصريح على المالك."""
    host = strict_host(raw)
    if not host: return False, "رابط غير صالح (اسم دومين فقط، بدون بيانات دخول أو بورت غير قياسي)", []
    try: ips = resolver(host)
    except Exception: return False, "تعذر حل اسم الدومين", []
    if not ips or not all(a.is_global for a in ips): return False, "الهدف داخلي أو غير قابل للوصول", []
    if host in cfg["allowlist"] or host in cfg["dynamic_targets"]:
        return True, host, ips
    if len(cfg["dynamic_targets"]) >= MAX_DYNAMIC_TARGETS:
        return False, "تم بلوغ حد الأهداف المضافة", []
    cfg["dynamic_targets"].add(host)
    save_dynamic_targets(cfg["dynamic_targets"])
    return True, host, ips

# ---------- التجهيز الذاتي ----------
def ensure_runtime(run=subprocess.run, execv=os.execv):
    """تجهيز بيئة بايثون بأمر واحد: ينشئ venv ويثبت المكتبات ويعيد التشغيل منها.
    يتحقق من أكواد الخروج؛ أي فشل يُبلَّغ عنه بوضوح بدل الاستمرار ببيئة ناقصة."""
    try:
        import telegram, aiohttp, bs4
        return
    except ImportError: pass
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        raise SystemExit("خطأ: المكتبات غير مثبتة داخل البيئة الافتراضية. نفّذ يدوياً: venv/bin/pip install python-telegram-bot aiohttp beautifulsoup4")
    if not os.path.exists(VENV_PYTHON):
        print("إنشاء البيئة الافتراضية...")
        r = run([sys.executable, "-m", "venv", VENV_DIR])
        if getattr(r, "returncode", 1) != 0 or not os.path.exists(VENV_PYTHON):
            raise SystemExit("خطأ: فشل إنشاء البيئة الافتراضية (غالباً python3-venv غير مثبت). ثبّته بصلاحيات النظام (مثال: sudo apt install python3-venv) ثم أعد التشغيل.")
    print("تثبيت مكتبات بايثون (تليجرام، aiohttp، bs4) داخل البيئة الافتراضية...")
    r = run([VENV_PYTHON, "-m", "pip", "install", "--disable-pip-version-check", "python-telegram-bot", "aiohttp", "beautifulsoup4"])
    if getattr(r, "returncode", 1) != 0:
        raise SystemExit("خطأ: فشل تثبيت مكتبات بايثون (pip أعاد خطأ). تحقق من اتصال الإنترنت ثم أعد التشغيل.")
    os.environ["DAST_BOT_BOOTSTRAPPED"] = "1"
    execv(VENV_PYTHON, [VENV_PYTHON, os.path.abspath(__file__)] + sys.argv[1:])

def obtain_lock(path=None):
    path = path or LOCK_PATH
    if os.environ.get("DAST_BOT_BOOTSTRAPPED") == "1": return None
    import fcntl
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise SystemExit("خطأ: نسخة أخرى تعمل بالفعل.")
    os.set_inheritable(fd, True)
    return fd

# ---------- فحص الاعتماديات الخارجية مع تثبيت تلقائي محدود وآمن ----------
GO_TOOLS = {"katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
            "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}

def find_tool(tool, which=shutil.which, env=None):
    """يحدد مسار الأداة التنفيذي بشكل موحد للكشف والتثبيت والتشغيل:
    PATH أولاً، ثم GOBIN، ثم GOPATH/bin، ثم ~/go/bin (وجهة go install الافتراضية)."""
    env = os.environ if env is None else env
    p = which(tool)
    if p: return p
    dirs = []
    if env.get("GOBIN"): dirs.append(env["GOBIN"])
    if env.get("GOPATH"): dirs.append(os.path.join(env["GOPATH"], "bin"))
    dirs.append(os.path.join(os.path.expanduser("~"), "go", "bin"))
    for d in dirs:
        full = os.path.join(d, tool)
        if os.path.isfile(full) and os.access(full, os.X_OK): return full
    return None

def _tool_present(tool, which=shutil.which):
    return find_tool(tool, which) is not None

def check_dependencies(cfg, which=shutil.which, runner=None):
    """يفحص الأدوات الخارجية المطلوبة للميزات المفعّلة فقط ويحاول تثبيت الناقص تلقائياً بشكل محدود:
    katana وnuclei من مستودعاتهما الرسمية عبر go install فقط لو go متاح، مع التحقق من كود الخروج وإعادة الفحص.
    Docker لا يُثبَّت تلقائياً (يحتاج صلاحيات نظام): يُبلَّغ عنه كخطوة يدوية. لا يعطّل أي حماية ولا يغيّر إعدادات النظام."""
    runner = runner or (lambda cmd, timeout: subprocess.run(cmd, capture_output=True, timeout=timeout))
    rep = []
    need = []
    if cfg["active_scan"]: need += ["katana", "nuclei"]
    if cfg["zap"]: need.append("docker")
    if not need:
        rep.append(("الأدوات الخارجية", "SKIPPED", "الفحص العميق وZAP مقفولان حالياً، فلا حاجة لأدوات خارجية."))
        return rep
    go = which("go")
    for tool in need:
        if _tool_present(tool, which):
            rep.append((tool, "OK", "مثبت وجاهز."))
            continue
        if tool == "docker":
            rep.append((tool, "MISSING", "غير مثبت ولا يمكن تثبيته تلقائياً بأمان (يحتاج صلاحيات نظام). ثبّته من وثائق Docker الرسمية ثم أعد التشغيل."))
            continue
        if not go:
            rep.append((tool, "MISSING", f"غير مثبت، وGo غير متاحة للتثبيت التلقائي. ثبّته يدوياً: go install {GO_TOOLS[tool]}"))
            continue
        try:
            r = runner(["go", "install", GO_TOOLS[tool]], 600)
            installed = getattr(r, "returncode", 1) == 0
        except Exception:
            installed = False
        if installed and _tool_present(tool, which):
            rep.append((tool, "INSTALLED", "ثبّته البوت تلقائياً الآن من مستودعه الرسمي عبر go install."))
        else:
            rep.append((tool, "MISSING", f"فشل التثبيت التلقائي. ثبّته يدوياً: go install {GO_TOOLS[tool]}"))
    return rep

def fmt_deps(rep):
    icons = {"OK": "✅", "INSTALLED": "🛠️", "MISSING": "⚠️", "SKIPPED": "ℹ️"}
    lines = ["🧰 تقرير الاعتماديات:"]
    for name, st, detail in rep:
        lines.append(f"{icons.get(st, '•')} {name}: {st} - {detail}")
    return lines

# ---------- أدوات التشغيل ----------
async def _kill(proc):
    if not proc: return
    try: os.killpg(proc.pid, signal.SIGKILL)
    except: pass
    try: await asyncio.wait_for(proc.wait(), 5)
    except: pass

LAST_TOOL_DIAG = {}
STDERR_CATEGORIES = (("DNS/اسم المضيف", r"no such host|lookup|dns"), ("TLS/شهادة", r"tls|certificate|x509|handshake"),
                     ("حد معدل أو HTTP 429", r"429|rate.?limit|too many requests"), ("مهلة اتصال", r"timeout|deadline|timed out"),
                     ("قوالب/تحديث", r"template|update"), ("صلاحيات ملفات", r"permission denied|read-only"),
                     ("اتصال مرفوض أو مقطوع", r"connection refused|connection reset|eof|broken pipe"), ("نفاد ذاكرة", r"out of memory|oom"))

def _safe_stderr_info(text):
    """معلومات تشخيص آمنة فقط: عدد الأسطر وفئات عامة. لا يُحفظ ولا يُعرض أي نص خام (قد يحمل توكن/كلمة سر/روابط بقيم)."""
    low = text.lower()
    return {"stderr_lines": len([l for l in text.splitlines() if l.strip()]),
            "stderr_categories": [name for name, rx in STDERR_CATEGORIES if re.search(rx, low)]}

async def run_command(cmd, timeout=300):
    proc = None
    buf, errbuf = bytearray(), bytearray()
    tasks = []
    t0 = time.time()
    async def pump(stream, sink):
        while True:
            chunk = await stream.read(65536)
            if not chunk: return
            sink.extend(chunk)
            if len(sink) > 8_000_000: del sink[:len(sink) - 4_000_000]
    def diag(status):
        LAST_TOOL_DIAG[os.path.basename(str(cmd[0]))] = {"status": status, "seconds": int(time.time() - t0), **_safe_stderr_info(errbuf.decode(errors="replace"))}
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
        tasks = [asyncio.ensure_future(pump(proc.stdout, buf)), asyncio.ensure_future(pump(proc.stderr, errbuf))]
        await asyncio.wait_for(proc.wait(), timeout=timeout)
        await asyncio.gather(*tasks, return_exceptions=True)
        st = "SUCCESS" if proc.returncode == 0 else "ERROR"
        diag(st)
        return (st, buf.decode(errors="replace").strip()) if st == "SUCCESS" else ("ERROR", "")
    except asyncio.TimeoutError:
        await _kill(proc)
        for t in tasks: t.cancel()
        diag("TIMEOUT")
        return "TIMEOUT", buf.decode(errors="replace").strip()  # ما وصل قبل المهلة يُحفظ كنتائج جزئية
    except Exception:
        await _kill(proc)
        for t in tasks: t.cancel()
        diag("ERROR")
        return "ERROR", ""

# ---------- الفحوصات السلبية المبدئية (اتصال مثبّت بعنوان IP متحقق منه، بدون متابعة تحويلات) ----------
class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, **kw): super().__init__(host, timeout=10, **kw); self._ip = ip
    def connect(self): self.sock = socket.create_connection((self._ip, self.port), timeout=10)
class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kw): super().__init__(host, timeout=10, context=ssl.create_default_context(), **kw); self._ip = ip
    def connect(self):
        s = socket.create_connection((self._ip, self.port), timeout=10)
        self.sock = self._context.wrap_socket(s, server_hostname=self.host)

def _get_sync(host, ip, https):
    c = (_PinnedHTTPS if https else _PinnedHTTP)(host, str(ip))
    try:
        c.request("GET", "/", headers={"User-Agent": UA, "Host": host})
        r = c.getresponse(); r.read(65536)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.msg.get_all("Set-Cookie") or []
    finally: c.close()

def _tls_days_sync(host, ip):
    ctx = ssl.create_default_context()
    with socket.create_connection((str(ip), 443), timeout=8) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t: cert = t.getpeercert()
    return int((ssl.cert_time_to_seconds(cert["notAfter"]) - datetime.now(timezone.utc).timestamp()) // 86400)

async def stage_tls(host, ip, fetch=None):
    try: d = await asyncio.to_thread(fetch or _tls_days_sync, host, ip)
    except Exception as e: return "FAILED", [f"تعذر التحقق من شهادة TLS ({type(e).__name__})."]
    if d < 0: return "OK", [f"شهادة TLS منتهية منذ {-d} يوم."]
    if d < 21: return "OK", [f"الشهادة صالحة لكن تنتهي خلال {d} يوم."]
    return "OK", [f"الشهادة صالحة، متبقي {d} يوم."]

async def stage_headers(host, ip, fetch=None):
    try: status, h, cookies = await asyncio.to_thread(fetch or _get_sync, host, ip, True)
    except Exception as e: return "FAILED", [f"الصفحة الرئيسية غير متاحة ({type(e).__name__})، المرحلة لم تعمل."]
    lines = [f"الصفحة الرئيسية ردت HTTP {status} (طلب GET واحد، بدون متابعة تحويلات)."]
    miss = [l for k, l in HEADERS_WANTED.items() if k not in h]
    lines.append("هيدرز ناقصة: " + ", ".join(miss) if miss else "الهيدرز الأربعة الشائعة موجودة (وجودها فقط وليس جودتها).")
    if any(c.isdigit() for c in h.get("server", "")): lines.append(f"هيدر Server يكشف الإصدار: {h['server'][:60]}")
    for c in cookies[:10]:
        parts = [x.strip() for x in c.split(";")]
        attrs = {x.split("=", 1)[0].strip().lower() for x in parts[1:] if x}
        bad = [n for n, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in attrs]
        if bad: lines.append(f"كوكي {parts[0].split('=',1)[0]} ينقصه: {', '.join(bad)}")
    return "OK", lines

async def stage_redirect(host, ip, fetch=None):
    try: status, h, _ = await asyncio.to_thread(fetch or _get_sync, host, ip, False)
    except Exception as e: return "FAILED", [f"لم يتم فحص تحويل HTTP إلى HTTPS ({type(e).__name__})."]
    if 300 <= status < 400 and h.get("location", "").startswith("https://"): return "OK", ["HTTP يتحول إلى HTTPS."]
    return "OK", [f"HTTP العادي رد {status} بدون تحويل إلى HTTPS."]

async def _run(cmd, timeout):
    p = None
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(p.wait(), timeout); return "OK"
    except asyncio.TimeoutError:
        if p: p.kill()
        return "TIMEOUT"
    except Exception: return "ERROR"

async def stage_zap(host, enabled, runner=None):
    """ZAP Baseline حسب الوثائق الرسمية: زحف ~دقيقة + قواعد سلبية بدون هجوم. يعمل محلياً عبر Docker.
    ملاحظة: يعمل داخل Docker وينفذ DNS واتصالاته بنفسه، فحماية تثبيت الـIP في الفحوصات المباشرة لا تنطبق عليه."""
    if not enabled: return "NOT_CONFIGURED", ["ZAP مقفل (ENABLE_ZAP=true في .env ويحتاج Docker)."]
    if not runner and not shutil.which("docker"): return "NOT_CONFIGURED", ["Docker غير مثبت، المرحلة لم تعمل."]
    d = tempfile.mkdtemp(); os.chmod(d, 0o777)
    cmd = ["docker", "run", "--rm", "-v", f"{d}:/zap/wrk/:rw", "ghcr.io/zaproxy/zaproxy:stable",
           "zap-baseline.py", "-t", f"https://{host}", "-m", "1", "-J", "r.json", "-I"]
    try:
        st = await (runner or _run)(cmd, ZAP_TIMEOUT)
        if st != "OK": return ("TIMEOUT" if st == "TIMEOUT" else "FAILED"), [f"ZAP: {st}، لا يوجد تقرير."]
        data = json.load(open(os.path.join(d, "r.json")))
    except Exception as e: return "FAILED", [f"تقرير ZAP غير قابل للقراءة ({type(e).__name__})."]
    finally: shutil.rmtree(d, ignore_errors=True)
    sites = data.get("site") if isinstance(data, dict) else None
    if not isinstance(sites, list) or not sites or not all(isinstance(x, dict) and isinstance(x.get("alerts"), list) for x in sites):
        return "FAILED", ["ZAP: التقرير ناقص أو بصيغة غير متوقعة، لا يمكن الجزم بنتيجة."]
    al = [(str(a.get("name", "?"))[:100], str(a.get("riskdesc", "?"))[:40]) for x in sites for a in x["alerts"] if isinstance(a, dict)]
    if not al: return "OK", ["ZAP السلبي: التقرير صالح وبلا تنبيهات (فحص سلبي محدود، لا يعني الأمان)."]
    return "OK", [f"ZAP السلبي: {len(al)} نوع تنبيه:"] + [f"- {n} ({r})" for n, r in al[:15]]

def _obs_sync(host):
    r = urllib.request.Request(f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={host}", method="POST", headers={"User-Agent": UA})
    with urllib.request.urlopen(r, timeout=30) as x: return json.load(x)

async def stage_observatory(host, post=None):
    try: d = await asyncio.to_thread(post or _obs_sync, host)
    except Exception as e: return "FAILED", [f"Observatory فشل ({type(e).__name__})."]
    if not isinstance(d, dict) or "grade" not in d: return "FAILED", ["Observatory رد بشكل غير متوقع، لا نتيجة."]
    return "OK", [f"Observatory: التقدير {d.get('grade')}، الدرجة {d.get('score','?')} (هيدرز فقط)."]

def fmt(host, stages):
    out = [f"🎯 {host}", f"{BOT_VERSION}", ""]
    for name, (st, lines) in stages:
        out.append(f"[{name}: {st}]"); out += lines; out.append("")
    out.append("«لا نتائج» لا تعني أن الموقع آمن أو أنه لا توجد ملفات مكشوفة. البوت لا يكتشف كل الملفات/الفولدرات ولا يضمن العثور على كل الأسرار.")
    return "\n".join(out)

# ---------- 1. صائد الأسرار (Python Engine) ----------
def _js_label(js_url):
    """اسم عرض آمن للملف: المسار فقط (بدون query/fragment لأنها قد تحمل قيماً حساسة) ومقصوص."""
    try:
        u = urlparse(js_url)
        label = (u.path or "/")
        if u.hostname: label = f"{u.hostname}{label}"
    except Exception:
        label = "?"
    return label[:90]

def format_discovery(stats, limit=10):
    pages = stats.get("pages", [])
    if not pages: return []
    out = [f"🗺️ تتبع روابط نفس الموقع (حتى {MAX_PAGES} صفحة، عمق {MAX_DEPTH}، حتى {MAX_JS_FILES} ملف JS، GET فقط بدون نماذج أو تخمين مسارات):"]
    ok = [p for p in pages if p["outcome"] == "fetched"]
    out.append(f"• صفحات HTML اتقرأت: {len(ok)}")
    for p in ok[:limit]:
        tag = " [مسار مذكور داخل كود JS/script]" if p.get("source") == "js-route" else ""
        out.append(f"   - {p['label']}{tag}")
    if len(ok) > limit: out.append(f"   … و{len(ok) - limit} صفحة إضافية لم تُعرض")
    for p in pages:
        if p["outcome"] == "http_error": out.append(f"• {p['label']} — لم يُقرأ: HTTP {p['status']}")
        elif p["outcome"] == "not_html": out.append(f"• {p['label']} — لم يُحلَّل: ليس HTML")
        elif p["outcome"] == "failed": out.append(f"• {p['label']} — لم يُقرأ: فشل الجلب")
    if stats.get("inline_scripts"): out.append(f"• script مضمّن في HTML: {stats['inline_scripts']} (فُحص بحثاً عن مراجع ملفات/صفحات فقط، لا عن أسرار)")
    if stats.get("links_skipped"):
        out.append(f"• روابط/مسارات لم تُتبع: {stats['links_skipped']}")
        for d in stats.get("skip_detail", []): out.append(f"   - {d['label']} — {d['reason']}")
        if stats["links_skipped"] > len(stats.get("skip_detail", [])):
            out.append(f"   … و{stats['links_skipped'] - len(stats['skip_detail'])} إضافية لم تُعرض")
    for lab in stats.get("dynamic", []):
        out.append(f"⚠️ {lab} يبني اسم ملف JS بالتركيب النصي؛ لا يمكن تتبعه بدون تشغيل الكود.")
    if stats.get("limits"):
        names = {"pages": "حد الصفحات", "js": "حد ملفات JS"}
        out.append("⚠️ التتبع وقف عند " + " و".join(names[x] for x in stats["limits"]) + "، فقد توجد صفحات/ملفات لم يُتتبّع إليها.")
    out.append("غير مدعوم: صفحات أو ملفات تُبنى/تُحمّل بالجافاسكريبت وقت التشغيل أو بعد تسجيل الدخول أو بعد ضغط زر، ومسارات مركّبة بالتجميع النصي.")
    return out

def format_js_coverage(files, limit=None):
    """سطر لكل ملف JS حاول البوت قراءته: النتيجة والحجم وعدد التطابقات (صفر يظهر صراحة). لا قيم أسرار."""
    limit = MAX_JS_FILES_SHOWN if limit is None else limit
    if not files: return []
    out = [f"📄 ملفات JS التي حاول البوت قراءتها ({len(files)}، مسارات مختصرة):"]
    for f in files[:limit]:
        o = f["outcome"]
        src = " [مذكور داخل ملف JS]" if f.get("source") == "js-ref" else ""
        if o == "fetched":
            out.append(f"• {f['label']}{src} — اتقرأ (HTTP 200، {f['size']} بايت): تطابقات أسرار {f['secrets']}، مسارات {f['endpoints']}")
        elif o == "http_error":
            out.append(f"• {f['label']}{src} — لم يُفحص: HTTP {f['status']}")
        elif o == "skipped":
            out.append(f"• {f['label']}{src} — لم يُفحص: مضيف غير عام (تخطّي)")
        else:
            out.append(f"• {f['label']}{src} — لم يُفحص: فشل الجلب")
    if len(files) > limit:
        out.append(f"… و{len(files) - limit} ملف إضافي لم يُعرض هنا (القائمة مقصوصة).")
    if len(files) > limit:
        out.append("القائمة مقصوصة، فالملفات غير المعروضة قد تكون اتقرأت أو لا. الأسماء مختصرة (host + path بدون query/fragment).")
    else:
        out.append("القائمة تشمل ما وصل إليه التتبع المحدود فقط (روابط وملفات مذكورة في صفحات نفس الموقع وفي ملفات JS)؛ أي ملف آخر لم تحاول هذه المرحلة قراءته. الأسماء مختصرة (host + path بدون query/fragment).")
    return out

MAX_PAGES = 15
MAX_JS_FILES = 40
MAX_DEPTH = 2
MAX_TEXT = 2_000_000
MAX_SKIP_DETAIL = 10
SKIP_PATH_RE = re.compile(r"(?i)(logout|signout|sign-out|log-out|delete|remove|unsubscribe|destroy|revoke|reset|pay|checkout|order|buy|purchase|confirm|submit|send|subscribe|activate|verify|callback|webhook)")
PAGE_EXTS = ("", ".html", ".htm")
ROUTE_SKIP_FIRST = {"api", "static", "assets", "js", "css", "img", "images", "fonts", "_next", "node_modules", ".well-known", "favicon.ico"}
JS_REF_RE = re.compile(r"""["'`]((?:https?:)?//[^"'`\s]+?\.m?js|[A-Za-z0-9_\-./~]+?\.m?js)(?:\?[^"'`\s]*)?["'`]""")
ROUTE_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_\-]+){0,3}(?:\.html?)?)["'`]""")
DYN_JS_RE = re.compile(r"""(\+\s*["'`]\.m?js["'`])|(\$\{[^}]*\}[A-Za-z0-9_\-./]*\.m?js)""")

def _clean_url(u):
    """بدون fragment وبدون query: التتبع لا يرسل بارامترات من عنده."""
    p = urlparse(u)
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))

def _skip_reason(u, base_host):
    """None لو الرابط صفحة مسموح تتبعها، وإلا سبب التخطي."""
    p = urlparse(u)
    try: port = p.port
    except ValueError: return "منفذ غير صالح"
    if (p.hostname or "").lower() != base_host: return "خارج الموقع"
    if p.scheme != "https" or port not in (None, 443): return "ليس https على المنفذ العادي"
    path = (p.path or "/").lower()
    if os.path.splitext(path)[1] not in PAGE_EXTS: return "ليس صفحة (امتداد ملف)"
    if SKIP_PATH_RE.search(path): return "اسم مستبعد للأمان (خروج/حذف/دفع/إرسال...)"
    return None

def _same_site(u, base_host):
    p = urlparse(u)
    try: port = p.port
    except ValueError: return False
    return p.scheme == "https" and (p.hostname or "").lower() == base_host and port in (None, 443)

async def analyze_javascript(url, resolver=resolve_all, session_factory=None):
    """تتبع محدود لروابط نفس الموقع (عمق %d، حتى %d صفحة، حتى %d ملف JS): روابط <a>، ملفات script (src أو داخل HTML)،
    مراجع .js وأسماء مسارات صفحات مكتوبة كنص كامل داخل JS أو داخل script مضمّن. GET فقط، بدون نماذج أو بارامترات
    أو تخمين أسماء، بدون متابعة تحويلات في الطلبات الجديدة، وتخطّي أسماء الخروج/الحذف/الدفع/الإرسال.
    لا يزور مضيفاً غير مضيف الهدف إلا لملفات script المذكورة في وسوم HTML.""" % (MAX_DEPTH, MAX_PAGES, MAX_JS_FILES)
    endpoints, secrets_found = set(), []
    stats = {"scripts": 0, "fetched": 0, "failed": 0, "skipped": 0, "files": [], "pages": [], "limits": [],
             "links_skipped": 0, "skip_detail": [], "dynamic": [], "inline_scripts": 0}
    base_host = (urlparse(url).hostname or "").lower()
    js_seen, js_queue = set(), []
    page_seen = {_clean_url(url)}
    page_queue = [(url, 0, "page")]

    def add_js(js_url, source, depth):
        key = _clean_url(js_url) if source == "js-ref" else js_url
        if key in js_seen: return
        if len(js_seen) >= MAX_JS_FILES:
            if "js" not in stats["limits"]: stats["limits"].append("js")
            return
        js_seen.add(key)
        js_queue.append((js_url, source, depth))

    def add_page(full, depth, source):
        if depth > MAX_DEPTH: return
        c = _clean_url(full)
        if c in page_seen: return
        if len(page_seen) >= MAX_PAGES:
            if "pages" not in stats["limits"]: stats["limits"].append("pages")
            return
        page_seen.add(c); page_queue.append((c, depth, source))

    def skip(full, reason):
        stats["links_skipped"] += 1
        if len(stats["skip_detail"]) < MAX_SKIP_DETAIL:
            stats["skip_detail"].append({"label": _js_label(full), "reason": reason})

    def harvest_refs(text, base_url, depth, label):
        """مراجع JS ومسارات صفحات مكتوبة كنص كامل (بدون تركيب نصوص)."""
        if depth >= MAX_DEPTH:
            if DYN_JS_RE.search(text): stats["dynamic"].append(label)
            return
        for ref in JS_REF_RE.findall(text):
            full = urljoin(base_url, ref if not ref.startswith("//") else "https:" + ref)
            if _same_site(full, base_host): add_js(full, "js-ref", depth + 1)
        for route in ROUTE_RE.findall(text):
            first_seg = route.strip("/").split("/")[0].lower()
            if first_seg in ROUTE_SKIP_FIRST: continue
            full = urljoin(base_url, route)
            r = _skip_reason(full, base_host)
            if r: skip(full, r + " (مسار مذكور في الكود)")
            else: add_page(full, depth + 1, "js-route")
        if DYN_JS_RE.search(text): stats["dynamic"].append(label)

    try:
        async with (session_factory or aiohttp.ClientSession)() as session:
            first = True
            while page_queue or js_queue:
                if page_queue:
                    if len(stats["pages"]) >= MAX_PAGES:
                        if "pages" not in stats["limits"]: stats["limits"].append("pages")
                        page_queue.clear()
                        continue
                    page_url, depth, source = page_queue.pop(0)
                    label = _js_label(page_url)
                    try:
                        kw = {} if first else {"allow_redirects": False}
                        async with session.get(page_url, timeout=aiohttp.ClientTimeout(total=10), **kw) as res:
                            if res.status != 200:
                                if first: return "FETCH_FAILED", [], [], stats
                                stats["pages"].append({"label": label, "outcome": "http_error", "status": res.status, "source": source})
                                continue
                            ctype = str(getattr(res, "headers", {}).get("Content-Type", "text/html")).lower()
                            if "html" not in ctype:
                                stats["pages"].append({"label": label, "outcome": "not_html", "source": source})
                                continue
                            html = (await res.text())[:MAX_TEXT]
                    except Exception:
                        if first: return "ERROR", [], [], stats
                        stats["pages"].append({"label": label, "outcome": "failed", "source": source})
                        continue
                    first = False
                    soup = BeautifulSoup(html, "html.parser")
                    for sc in soup.find_all("script"):
                        if sc.get("src"): add_js(urljoin(page_url, sc["src"]), "page", depth)
                        elif sc.get_text():
                            stats["inline_scripts"] += 1
                            harvest_refs(sc.get_text()[:MAX_TEXT], page_url, depth, label + " (script مضمّن)")
                    for lk in soup.find_all("link", href=True):
                        rel = " ".join(lk.get("rel") or []).lower()
                        if "modulepreload" in rel or (("preload" in rel) and str(lk.get("as", "")).lower() == "script"):
                            add_js(urljoin(page_url, lk["href"]), "page", depth)
                    nlinks = 0
                    if depth < MAX_DEPTH:
                        for a in soup.find_all("a", href=True):
                            h = a["href"].strip()
                            if not h or h.startswith(("#", "mailto:", "tel:", "javascript:")): continue
                            full = urljoin(page_url, h)
                            r = _skip_reason(full, base_host)
                            if r: skip(full, r); continue
                            before = len(page_queue)
                            add_page(full, depth + 1, "link")
                            nlinks += len(page_queue) - before
                    stats["pages"].append({"label": label, "outcome": "fetched", "new_links": nlinks, "source": source})
                    continue

                js_url, source, depth = js_queue.pop(0)
                if not stats["pages"]: return "FETCH_FAILED", [], [], stats
                n0 = len(stats["files"])
                lab = _js_label(js_url)
                if not host_is_public(urlparse(js_url).hostname, resolver):
                    stats["skipped"] += 1
                    stats["files"].append({"label": lab, "outcome": "skipped", "source": source})
                    continue
                try:
                    kw = {"allow_redirects": False} if source == "js-ref" else {}
                    async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=10), **kw) as js_res:
                        if js_res.status != 200:
                            stats["failed"] += 1
                            stats["files"].append({"label": lab, "outcome": "http_error", "status": js_res.status, "source": source})
                            continue
                        js_content = (await js_res.text())[:MAX_TEXT]
                        stats["fetched"] += 1
                        rec = {"label": lab, "outcome": "fetched", "source": source, "size": len(js_content.encode("utf-8", "ignore")), "secrets": 0, "endpoints": 0}
                        stats["files"].append(rec)
                        for name, pattern in SECRET_PATTERNS.items():
                            for match in re.findall(pattern, js_content):
                                rec["endpoints" if name == "Hidden Endpoint" else "secrets"] += 1
                                match_str = match if isinstance(match, str) else match[-1]
                                if name == "Hidden Endpoint":
                                    endpoints.add(urljoin(url, match_str))
                                else:
                                    secrets_found.append(f"🚨 [{name}] في {lab.split('/')[-1]} (القيمة لا تُعرض، راجع الملف يدوياً)")
                        if depth < MAX_DEPTH and _same_site(js_url, base_host):
                            harvest_refs(js_content, js_url, depth, lab)
                except Exception:
                    stats["failed"] += 1
                    if len(stats["files"]) == n0:
                        stats["files"].append({"label": lab, "outcome": "failed", "source": source})
                    continue
            if not stats["pages"]: return "FETCH_FAILED", [], [], stats
            if not stats["files"]: stats["scripts"] = 0; return "NO_SCRIPTS", [], [], stats
    except Exception:
        stats["scripts"] = len(js_seen)
        return "ERROR", list(endpoints), secrets_found, stats

    stats["scripts"] = len(js_seen)
    if stats["fetched"] == 0:
        return "FAILED", list(endpoints), secrets_found, stats
    if stats["failed"] or stats["skipped"]:
        return "PARTIAL", list(endpoints), secrets_found, stats
    return "OK", list(endpoints), secrets_found, stats

# ---------- 2. الزحف (Katana) ----------
async def crawl(url, runner=run_command, resolver=resolve_all, finder=None):
    finder = finder or find_tool
    exe = finder("katana")
    if not exe: return "NOT_CONFIGURED", [url]
    cmd = [exe, "-u", url, "-d", "2", "-silent", "-jc", "-headless", "-fs", "fqdn"]
    status, out = await runner(cmd, KATANA_TIMEOUT)
    if status != "SUCCESS": return "FAILED", [url]
    found = {l.strip() for l in out.splitlines() if l.strip()}
    safe = {l for l in found if urlparse(l).hostname == urlparse(url).hostname}
    safe.discard(url)
    return ("SUCCESS" if safe else "EMPTY"), [url] + list(safe)[:MAX_LINKS-1]

# ---------- 3. الفحص (Nuclei) ----------
async def scan_nuclei(urls, runner=run_command, finder=None):
    if not urls: return "SKIPPED", [], 0
    finder = finder or find_tool
    exe = finder("nuclei")
    if not exe: return "NOT_CONFIGURED", [], 0
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            path = f.name
            f.write("\n".join(urls) + "\n")
        cmd = [exe, "-l", path, "-severity", SEVERITIES, "-tags", NUCLEI_TAGS, "-jsonl", "-silent", "-duc", "-rate-limit", "50", "-c", "10"]
        status, out = await runner(cmd, NUCLEI_TIMEOUT)
        if status not in ("SUCCESS", "TIMEOUT"): return status, [], 0
        if status == "TIMEOUT" and not out: return status, [], 0

        findings, bad = [], 0
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                d = json.loads(line)
                info = d.get("info", {})
                findings.append({
                    "name": str(info.get("name", "Unknown"))[:100],
                    "severity": str(info.get("severity", "unknown")).upper(),
                    "url": str(d.get("matched-at", ""))
                })
            except: bad += 1
        return status, findings, bad
    finally:
        if path and os.path.exists(path): os.remove(path)


# ---------- ملخص منظم أعلى التقرير (ترتيب العرض فقط، بدون أي فحص إضافي) ----------
ISSUE_KEYS = ("ناقصة", "ينقصه", "يكشف الإصدار", "منتهية", "تنتهي خلال", "بدون تحويل")
MAX_HINTS_SHOWN = 10

def _stage0_notes(s0):
    notes, bad = [], []
    for name, st, lines in s0:
        if st != "OK":
            bad.append(f"{name}: فشل ولم يكتمل")
            continue
        for l in lines:
            if any(k in l for k in ISSUE_KEYS): notes.append(l)
    return notes, bad

def build_summary(s0, deep, js_state=None, js_stats=None, secrets=(), endpoints=(), cstate=None, links=(), sstate=None, findings=(), bad=0):
    """يعيد (summary_lines). كل مرحلة: اكتملت / غير مكتملة / فشلت / لم تعمل. لا يُقال أبداً إن غياب النتائج أمان."""
    stages, problems = [], []
    notes, s0bad = _stage0_notes(s0)
    if s0bad:
        stages.append("❌ المرحلة 0 (TLS/هيدرز/تحويل): " + "، ".join(s0bad)); problems += s0bad
    else:
        stages.append("✅ المرحلة 0 (TLS/هيدرز/تحويل): اكتملت")
    if not deep:
        stages.append("⏭ المراحل 1-3 (JS/الزحف/Nuclei): لم تعمل (ENABLE_ACTIVE_SCAN=false)")
        problems.append("الفحص العميق لم يعمل")
    else:
        n = len((js_stats or {}).get("files", []))
        fetched = (js_stats or {}).get("fetched", 0)
        npg = len([p for p in (js_stats or {}).get("pages", []) if p["outcome"] == "fetched"])
        if (js_stats or {}).get("limits"): problems.append("التتبع وصل لحد الصفحات/الملفات")
        if js_state == "OK": stages.append(f"✅ المرحلة 1 (JS): اكتملت، قُرئ {fetched} ملف من {npg} صفحة (تتبع محدود)")
        elif js_state == "NO_SCRIPTS": stages.append("ℹ️ المرحلة 1 (JS): الصفحة الرئيسية لا تحتوي ملفات script خارجية")
        elif js_state == "PARTIAL":
            stages.append(f"⚠️ المرحلة 1 (JS): غير مكتملة، قُرئ {fetched} من {n} ملف"); problems.append("تحليل JS جزئي")
        else:
            stages.append("❌ المرحلة 1 (JS): فشلت أو لم تبدأ"); problems.append("تحليل JS فشل")
        if cstate == "NOT_CONFIGURED":
            stages.append("⏭ المرحلة 2 (Katana): لم تعمل (الأداة غير ظاهرة للبوت)"); problems.append("Katana لم يعمل")
        elif cstate == "FAILED":
            stages.append("❌ المرحلة 2 (Katana): فشلت"); problems.append("Katana فشل")
        else:
            stages.append(f"✅ المرحلة 2 (Katana): انتهت، {len(links)} رابط (يغطي ما وجده الزاحف فقط)")
        if sstate == "NOT_CONFIGURED":
            stages.append("⏭ المرحلة 3 (Nuclei): لم تعمل (الأداة غير ظاهرة للبوت)"); problems.append("Nuclei لم يعمل")
        elif sstate == "TIMEOUT":
            stages.append("⚠️ المرحلة 3 (Nuclei): غير مكتملة (انتهت المهلة)" + (f"، {len(findings)} نتيجة جزئية" if findings else "") + "، لا يمكن اعتبارها سليمة"); problems.append("Nuclei انتهت مهلته")
        elif sstate == "ERROR":
            stages.append("❌ المرحلة 3 (Nuclei): خطأ، لم تكتمل"); problems.append("Nuclei خطأ")
        elif sstate == "SKIPPED":
            stages.append("ℹ️ المرحلة 3 (Nuclei): لا روابط صالحة لفحصها")
        else:
            extra = f"، وفشل تحليل {bad} سطر" if bad else ""
            stages.append(f"✅ المرحلة 3 (Nuclei): انتهت{extra}، {len(findings)} نتيجة")
            if bad: problems.append("جزء من نتائج Nuclei لم يُحلَّل")
    out = ["📋 **الملخص**"]
    out.append("الحالة العامة: ⚠️ غير مكتمل (" + "، ".join(problems) + ")" if problems else "الحالة العامة: اكتمل ضمن حدود الأدوات المفعّلة (وهذا لا يعني أن الموقع آمن)")
    out += stages
    out.append("")
    out.append("✅ **ملاحظات مؤكدة (قياس مباشر من الفحوصات السلبية):**")
    out += [f"• {x}" for x in notes] if notes else ["• لا ملاحظات من الفحوصات السلبية التي اكتملت."]
    if findings:
        out.append("🚨 **نتائج أبلغت عنها أداة Nuclei (راجعها يدوياً قبل الحكم):** " + str(len(findings)))
    if secrets:
        out.append(f"🔎 **{len(secrets)} تطابق نمط أسرار محتمل في JS (إشارة تحتاج مراجعة يدوية، وليست إثباتاً)**")
    eps = list(endpoints)
    if eps or links:
        out.append("")
        out.append("🔗 **إشارات فقط (ليست ثغرات):**")
        if eps:
            out.append(f"• مسارات مذكورة داخل ملفات JS: {len(eps)}")
            out += [f"   - {e}" for e in sorted(eps)[:MAX_HINTS_SHOWN]]
            if len(eps) > MAX_HINTS_SHOWN: out.append(f"   … و{len(eps) - MAX_HINTS_SHOWN} مسار إضافي لم يُعرض")
        if links: out.append(f"• روابط وجدها الزاحف: {len(links)}")
    out.append("═" * 30)
    out.append("📑 **التفاصيل:**")
    return out

def assemble_report(rep, summary):
    return "\n".join(rep[:3] + summary + rep[3:])

# ---------- المحرك الرئيسي: الفحوصات السلبية دائماً، والعميق لو مفعّل ----------
async def run_scan(host, ips, cfg, runner=run_command, resolver=resolve_all, fetchers=None):
    url = f"https://{host}"
    rep = [f"🎯 الهدف: {url}", BOT_VERSION, "═"*30]

    # المرحلة 0: الفحوصات السلبية المبدئية (تعمل دائماً)
    rep.append("🔎 **المرحلة 0: الفحوصات السلبية المبدئية (TLS + الهيدرز + الكوكيز + التحويل)**")
    f = fetchers or {}
    ip = ips[0]
    s0 = []
    for name, stage in (("TLS", stage_tls), ("Headers", stage_headers), ("Redirect", stage_redirect)):
        st, lines = await stage(host, ip, f.get({"TLS": "tls", "Headers": "get", "Redirect": "http"}[name]))
        rep.append(f"[{name}: {st}]")
        rep.extend(lines)
        s0.append((name, st, lines))

    if not cfg["active_scan"]:
        rep.append("\nℹ️ الفحص العميق مقفول (ENABLE_ACTIVE_SCAN=false): لم يتم تحليل JS ولا الزحف ولا Nuclei في هذه الجولة.")
        rep.append("═"*30)
        rep.append("🛑 *هذا تقرير مبدئي محدود. «لا نتائج» لا تعني الأمان ولا غياب الملفات المكشوفة أو الأسرار.*")
        return assemble_report(rep, build_summary(s0, False))

    # المرحلة 1: صيد الأسرار (JS)
    rep.append("\n🕵️ **المرحلة 1: تحليل الجافاسكريبت (Secret Hunter)...**")
    js_state, js_endpoints, secrets, js_stats = await analyze_javascript(url, resolver)
    if js_state == "FETCH_FAILED":
        rep.append("⚠️ تعذر جلب الصفحة الرئيسية، فمرحلة تحليل JavaScript لم تبدأ أصلاً.")
    elif js_state == "NO_SCRIPTS":
        rep.append("ℹ️ الصفحة الرئيسية لا تشير إلى ملفات JavaScript خارجية، فلا يوجد ما تحلله هذه المرحلة.")
    elif js_state in ("FAILED", "PARTIAL", "ERROR"):
        rep.append(f"⚠️ تحليل JavaScript غير مكتمل: تم جلب {js_stats['fetched']} من {js_stats['scripts']} ملف (فشل {js_stats['failed']}، تخطّي {js_stats['skipped']}). النتائج أدناه جزئية.")
    rep.extend(format_discovery(js_stats))
    rep.extend(format_js_coverage(js_stats.get("files", [])))
    if secrets:
        rep.append(f"🚨 **تم اكتشاف {len(secrets)} تسريب محتمل:**")
        rep.extend(secrets[:10])
    elif js_state == "OK":
        rep.append(f"✅ لا تطابقات أسرار في {js_stats['fetched']} ملف JS اتقرأ (التفاصيل أعلاه). هذا لا يغطي ملفات لم تُذكر في القائمة.")

    if js_endpoints:
        rep.append(f"🔗 عثر البوت على {len(js_endpoints)} مسار API مذكور داخل ملفات JS (مثل: {js_endpoints[0]}). هذه مجرد إشارات في الكود، وليست بالضرورة مسارات مخفية أو ثغرات.")

    # المرحلة 2: الزحف (Katana)
    rep.append("\n🕸️ **المرحلة 2: الزحف (Katana)...**")
    cstate, links = await crawl(url, runner, resolver)
    if cstate == "NOT_CONFIGURED": rep.append("⚠️ Katana غير مثبت أو غير ظاهر للبوت، فمرحلة الزحف لم تعمل. راجع /status.")
    elif cstate == "FAILED": rep.append("⚠️ فشل الزاحف، سيتم الاعتماد على الروابط المكتشفة يدوياً.")
    else: rep.append(f"✅ تم اكتشاف {len(links)} رابط.")

    # دمج الروابط
    all_targets = list(set(links + js_endpoints))
    rep.append(f"*(إجمالي الروابط التي سيتم فحصها بـ Nuclei: {len(all_targets)})*")

    # المرحلة 3: Nuclei
    rep.append("\n🪲 **المرحلة 3: فحص الثغرات (Nuclei)...**")
    sstate, findings, bad = await scan_nuclei(all_targets, runner)

    if sstate == "NOT_CONFIGURED":
        rep.append("⚠️ Nuclei غير مثبت أو غير ظاهر للبوت، فمرحلة فحص الثغرات لم تعمل. راجع /status.")
    elif sstate == "TIMEOUT":
        rep.append("⚠️ انتهت مهلة الفحص، فنتائج هذه المرحلة غير مكتملة.")
        d = LAST_TOOL_DIAG.get("nuclei") or {}
        rep.append(f"تفاصيل: المهلة {NUCLEI_TIMEOUT} ثانية، عدد الأهداف {len(all_targets)}، وسوم القوالب: {NUCLEI_TAGS}." + (f" مدة التشغيل الفعلية {d['seconds']} ثانية." if d.get("seconds") else ""))
        if d.get("stderr_lines"):
            cats = "، ".join(d.get("stderr_categories", [])) or "غير مصنّفة"
            rep.append(f"مخرجات خطأ من الأداة: {d['stderr_lines']} سطر، فئات: {cats} (النص الخام غير معروض لحماية أي قيم حساسة؛ راجع السيرفر يدوياً).")
        else: rep.append("لا مخرجات خطأ من الأداة؛ السبب غير محدد (قد يكون بطء قوالب أو الشبكة أو الموقع).")
        if findings:
            rep.append(f"🚨 نتائج جزئية وصلت قبل المهلة ({len(findings)}):")
            for fnd in findings[:MAX_FINDINGS]: rep.append(f"[{fnd['severity']}] {fnd['name']}\n📍 {fnd['url']}")
    elif sstate == "ERROR":
        rep.append("⚠️ خطأ في Nuclei، فلم تكتمل هذه المرحلة.")
    elif sstate == "SKIPPED":
        rep.append("ℹ️ لا توجد روابط صالحة لفحصها في هذه المرحلة.")
    else:
        if not findings:
            if bad:
                rep.append(f"⚠️ فشل تحليل {bad} سطر من نتائج Nuclei، فلا يمكن الجزم بعدم وجود ثغرات.")
            else:
                rep.append("✅ لم يكتشف Nuclei ثغرات معروفة في المسارات التي تم فحصها.")
        else:
            rep.append(f"🚨 **تم اكتشاف {len(findings)} ثغرة:**")
            for fnd in findings[:MAX_FINDINGS]:
                rep.append(f"[{fnd['severity']}] {fnd['name']}\n📍 {fnd['url']}")
            if bad:
                rep.append(f"⚠️ كما فشل تحليل {bad} سطر من النتائج، فالقائمة أعلاه قد تكون غير مكتملة.")

    rep.append("\n" + "═"*30)
    rep.append("🛑 *هذا تقرير تحليلي. راجع النتائج يدوياً. غياب النتائج لا يعني الأمان ولا اكتشاف كل الملفات المكشوفة أو الأسرار.*")
    return assemble_report(rep, build_summary(s0, True, js_state, js_stats, secrets, js_endpoints, cstate, (links if cstate not in ("NOT_CONFIGURED", "FAILED") else []), sstate, findings if sstate not in ("NOT_CONFIGURED", "ERROR", "SKIPPED") else [], bad))

# ---------- تليجرام ----------
def build_handlers(cfg, resolver=resolve_all, fetchers=None, zap_runner=None, obs_post=None, runner=run_command, deps_checker=None):
    cfg.setdefault("dynamic_targets", set())
    pending = {}  # owner-private: hostname awaiting explicit consent for the hosted check
    def is_owner(u): return u.effective_user and u.effective_user.id == cfg["owner_id"] and u.effective_chat.type == "private"
    async def send(update, text):
        for i in range(0, len(text), 4000): await update.message.reply_text(text[i:i+4000], disable_web_page_preview=True)
    def arg(context, update):
        a = getattr(context, "args", None)
        if a: return a[0]
        t = (update.message.text or "").split(None, 1)
        return t[1] if len(t) > 1 else ""

    async def start(update, context):
        if is_owner(update): await send(update, f"{BOT_VERSION} جاهز.\n{HELP}")

    async def do_scan(update, raw):
        ok, host, ips = admit_target(raw, cfg, resolver)
        if not ok:
            await send(update, f"🛑 تم رفض الهدف: {host}")
            return
        msg = await update.message.reply_text(f"⏳ جاري فحص `{host}`... (قد يستغرق دقائق)")
        try:
            report = await run_scan(host, ips, cfg, runner, resolver, fetchers)
            await send(update, report)
        except Exception as e:
            await send(update, f"⚠️ خطأ غير متوقع: {type(e).__name__}")
        try: await msg.delete()
        except Exception: pass

    async def scan(update, context):
        if not is_owner(update): return
        await do_scan(update, arg(context, update))

    async def text(update, context):
        if not is_owner(update) or not update.message or not update.message.text: return
        t = update.message.text.strip()
        if not t or t.startswith("/"): return
        await do_scan(update, t)

    async def zap(update, context):
        if not is_owner(update): return
        ok, host, ips = admit_target(arg(context, update), cfg, resolver)
        if not ok: return await send(update, f"🛑 تم رفض الهدف: {host}")
        await send(update, "⏳ ZAP قد يأخذ دقائق...")
        st = await stage_zap(host, cfg["zap"], zap_runner)
        await send(update, fmt(host, [("ZAP", st)]))

    async def observatory(update, context):
        if not is_owner(update): return
        if not cfg["observatory"]: return await send(update, "الفحص الخارجي مقفول (ENABLE_OBSERVATORY=true في .env).")
        ok, host, ips = admit_target(arg(context, update), cfg, resolver)
        if not ok: return await send(update, f"🛑 تم رفض الهدف: {host}")
        pending[update.effective_user.id] = host
        await send(update, f"⚠️ هذا فحص خارجي: سيتم إرسال اسم الدومين {host} إلى Mozilla (MDN HTTP Observatory). للموافقة أرسل: /confirm")

    async def confirm(update, context):
        if not is_owner(update): return
        host = pending.pop(update.effective_user.id, None)
        if not host: return await send(update, "لا يوجد فحص خارجي معلّق.")
        await send(update, fmt(host, [("Observatory", await stage_observatory(host, obs_post))]))

    async def status(update, context):
        if not is_owner(update): return
        rep = await asyncio.to_thread(deps_checker or check_dependencies, cfg)
        await send(update, "\n".join(fmt_deps(rep)))

    return {"start": start, "scan": scan, "zap": zap, "observatory": observatory, "confirm": confirm, "status": status, "text": text}, pending

def main():
    if not ensure_env_file():
        raise SystemExit("تم إنشاء ملف .env بقيم توضيحية. املأ BOT_TOKEN و OWNER_ID ثم أعد تشغيل نفس الأمر.")
    cfg = load_config(merged_env())
    cfg["dynamic_targets"] = load_dynamic_targets()
    lock_fd = obtain_lock()
    ensure_runtime()

    from telegram.ext import Application, CommandHandler, MessageHandler, filters

    dep_report = check_dependencies(cfg)
    for line in fmt_deps(dep_report): print(line)

    hs, _ = build_handlers(cfg)
    app = Application.builder().token(cfg["token"]).build()
    for name in ("start", "scan", "zap", "observatory", "confirm", "status"):
        app.add_handler(CommandHandler(name, hs[name]))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, hs["text"]))
    print(f"{BOT_VERSION} running...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
