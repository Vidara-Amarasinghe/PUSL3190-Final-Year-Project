import re
import time
import math
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone
from database import init_db, insert_event, insert_alert
from ml_model import load_model, predict
from adaptive_model import load_adaptive_model, adaptive_predict

# ─── Configuration ───────────────────────────────────────
LOG_FILE = "/var/log/syslog"

ALLOWLIST = [
    # Core
    'mydns.test', 'ns1.mydns.test', 'ns2.mydns.test',
    # Web
    'www.mydns.test', 'web.mydns.test', 'http.mydns.test',
    # Mail
    'mail.mydns.test', 'smtp.mydns.test', 'pop.mydns.test',
    'pop3.mydns.test', 'imap.mydns.test', 'webmail.mydns.test',
    # Remote
    'ftp.mydns.test', 'sftp.mydns.test', 'vpn.mydns.test',
    'remote.mydns.test', 'rdp.mydns.test',
    # Application
    'api.mydns.test', 'app.mydns.test', 'portal.mydns.test',
    'gateway.mydns.test',
    # Development
    'dev.mydns.test', 'test.mydns.test', 'staging.mydns.test',
    'uat.mydns.test', 'qa.mydns.test',
    # Database
    'db.mydns.test', 'database.mydns.test',
    'mysql.mydns.test', 'postgres.mydns.test',
    # Infrastructure
    'admin.mydns.test', 'monitor.mydns.test', 'backup.mydns.test',
    'storage.mydns.test', 'ntp.mydns.test', 'proxy.mydns.test',
    'firewall.mydns.test', 'router.mydns.test',
    # Business
    'shop.mydns.test', 'store.mydns.test', 'blog.mydns.test',
    'news.mydns.test', 'media.mydns.test', 'cdn.mydns.test',
    'static.mydns.test',
    # Security
    'auth.mydns.test', 'login.mydns.test', 'sso.mydns.test',
    'ldap.mydns.test',
    # Aliases
    'docs.mydns.test', 'help.mydns.test', 'support.mydns.test',
    'sip.mydns.test',
]

ALERT_FILE           = "/home/student/dns-anomaly/alerts.log"
WINDOW_SECONDS       = 10
THRESHOLD            = 20
ENTROPY_THRESHOLD    = 3.6
SUBDOMAIN_THRESHOLD  = 4

# ─── Storage ─────────────────────────────────────────────
query_timestamps = defaultdict(deque)
query_types      = defaultdict(Counter)

# ─── Regex ───────────────────────────────────────────────
QUERY_RE = re.compile(
    r'client\s+\S+\s+([\d\.]+)#\d+\s+\(([^)]+)\):\s+query:\s+\S+\s+IN\s+(\w+).*\+',
    re.IGNORECASE
)

# ─── Feature Functions ────────────────────────────────────
def shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    n    = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def subdomain_depth(domain):
    return len(domain.strip('.').split('.'))

def now_utc():
    from datetime import timedelta
    sri_lanka = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(sri_lanka).isoformat(timespec="seconds")

# ─── Severity Classification ──────────────────────────────
def get_severity(reason, value):
    if reason == "HIGH_QUERY_RATE":
        if value >= 50:
            return "High"
        elif value >= 30:
            return "Medium"
        else:
            return "Low"
    elif reason == "HIGH_ENTROPY":
        if value >= 4.0:
            return "High"
        else:
            return "Medium"
    elif reason == "DEEP_SUBDOMAIN":
        return "Medium"
    return "Low"

# ─── Alert Writer ─────────────────────────────────────────
def write_alert(reason, ip, domain, extra="", value=0):
    severity = get_severity(reason, value)
    ts = now_utc()
    msg = (f"[{ts}] ALERT | {severity} | {reason} | "
           f"IP={ip} | Domain={domain} | {extra}\n")
    print(msg.strip())
    with open(ALERT_FILE, "a") as f:
        f.write(msg)
    insert_alert(ts, ip, domain, reason, severity, extra)

# ─── Main Detection Loop ──────────────────────────────────
def monitor():
    init_db()
    model, scaler = load_model()
    adaptive_model = load_adaptive_model()

    print(f"Detector started. Watching {LOG_FILE} ...")
    print(f"Window={WINDOW_SECONDS}s | Threshold={THRESHOLD} queries")
    print(f"Entropy threshold   = {ENTROPY_THRESHOLD}")
    print(f"Subdomain threshold = {SUBDOMAIN_THRESHOLD}")
    print(f"Alerts -> {ALERT_FILE}\n")

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            match = QUERY_RE.search(line)
            if not match:
                continue

            client_ip = match.group(1)
            domain    = match.group(2)
            qtype     = match.group(3)
            ts        = now_utc()

            now = time.time()

            # ── Sliding window ──
            dq = query_timestamps[client_ip]
            dq.append(now)
            while dq and dq[0] < now - WINDOW_SECONDS:
                dq.popleft()
            count = len(dq)

            # ── Query type tracking ──
            query_types[client_ip][qtype] += 1

            # ── Feature extraction ──
            entropy = shannon_entropy(domain)
            depth   = subdomain_depth(domain)
            length  = len(domain)

            print(f"DEBUG | IP={client_ip} | Domain={domain} | "
                  f"Type={qtype} | Entropy={entropy:.2f} | "
                  f"Depth={depth} | Len={length} | Count={count}")

            # ── Save event to database ──
            insert_event(ts, client_ip, domain, qtype,
                        round(entropy, 2), depth, length, count)

            # ── ML Anomaly Score ──
            if model and scaler:
                is_anomaly, ml_score = predict(
                    model, scaler, entropy, depth, length, count)
            else:
                is_anomaly, ml_score = False, 0.0

            # ── Adaptive Learning Score ──
            adap_anomaly, adap_score = adaptive_predict(
                adaptive_model, entropy, depth, length, count)

            # ── Detection Rules ──
            if count >= THRESHOLD and domain not in ALLOWLIST:
                write_alert("HIGH_QUERY_RATE", client_ip, domain,
                           f"count={count}/{WINDOW_SECONDS}s", count)

            if entropy >= ENTROPY_THRESHOLD and domain not in ALLOWLIST:
                write_alert("HIGH_ENTROPY", client_ip, domain,
                           f"entropy={entropy:.2f}", entropy)

            if depth >= SUBDOMAIN_THRESHOLD and domain not in ALLOWLIST:
                write_alert("DEEP_SUBDOMAIN", client_ip, domain,
                           f"depth={depth}", depth)

            if is_anomaly and ml_score < -0.63 and domain not in ALLOWLIST:
                write_alert("ML_ANOMALY", client_ip, domain,
                           f"ml_score={ml_score}", abs(ml_score))

            if adap_anomaly and domain not in ALLOWLIST:
                write_alert("ADAPTIVE_ANOMALY", client_ip, domain,
                           f"adap_score={adap_score}", adap_score)

if __name__ == "__main__":
    monitor()
