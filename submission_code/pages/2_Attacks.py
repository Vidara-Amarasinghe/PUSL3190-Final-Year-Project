import streamlit as st
import warnings
warnings.filterwarnings('ignore')
import sqlite3
import pandas as pd
import plotly.express as px
import subprocess
import time

DB_FILE = "/home/student/dns-anomaly/dns_anomaly.db"

ATTACK_INFO = {
    "HIGH_ENTROPY": {
        "name":        "DGA / DNS Tunneling Attack",
        "icon":        "~",
        "description": "Domain names with high randomness detected. "
                       "This indicates Domain Generation Algorithm (DGA) "
                       "malware or DNS tunneling used for data exfiltration.",
        "how_it_works": [
            "Malware generates random domain names automatically",
            "Used to communicate with Command and Control (C2) servers",
            "Data can be exfiltrated by encoding it in DNS queries",
            "Hard to block because domains change constantly"
        ],
        "mitigation": [
            "Block the source IP address immediately",
            "Investigate the client device for malware infection",
            "Add entropy-based filtering rules to firewall",
            "Enable DNS Security Extensions (DNSSEC)",
            "Monitor for continued high-entropy queries from same IP"
        ],
        "severity_color": "#dc2626"
    },
    "HIGH_QUERY_RATE": {
        "name":        "DNS Flood / DoS Attack",
        "icon":        "x",
        "description": "Abnormally high number of DNS queries from a single "
                       "IP in a short time window. This indicates a DNS "
                       "Denial of Service or reconnaissance attack.",
        "how_it_works": [
            "Attacker sends hundreds of queries per second",
            "Overloads the DNS server resources",
            "Can cause legitimate queries to be dropped",
            "Often used as a distraction for other attacks"
        ],
        "mitigation": [
            "Rate limit queries from the source IP",
            "Enable DNS rate limiting on BIND9 server",
            "Add firewall rule to block the IP temporarily",
            "Monitor if attack continues from different IPs",
            "Consider implementing Response Rate Limiting (RRL)"
        ],
        "severity_color": "#ea580c"
    },
    "ML_ANOMALY": {
        "name":        "Machine Learning Anomaly",
        "icon":        "o",
        "description": "Isolation Forest ML model detected abnormal DNS "
                       "behavior that does not match normal traffic patterns. "
                       "Query features deviate significantly from baseline.",
        "how_it_works": [
            "Query features such as entropy, length and rate are abnormal",
            "Pattern does not match known legitimate traffic",
            "Could be a new or evolving attack technique",
            "ML model flagged it as a statistical outlier"
        ],
        "mitigation": [
            "Investigate the flagged domain manually",
            "Check if domain is a known legitimate service",
            "Temporarily block if confirmed suspicious",
            "Review query patterns from the source IP",
            "Mark as false positive if traffic is legitimate"
        ],
        "severity_color": "#7c3aed"
    },
    "ADAPTIVE_ANOMALY": {
        "name":        "Adaptive Learning Anomaly",
        "icon":        "a",
        "description": "River adaptive model detected a query that deviates "
                       "from learned normal behavior. The system has "
                       "identified this as unusual based on past traffic.",
        "how_it_works": [
            "Query pattern differs from learned baseline",
            "Adaptive model flagged as unusual behavior",
            "Could indicate a new attack vector",
            "System continuously learns and updates detection"
        ],
        "mitigation": [
            "Investigate source IP behavior history",
            "Compare with baseline traffic patterns",
            "Block the IP if confirmed malicious",
            "Mark as false positive if legitimate to improve model",
            "Document findings for future reference"
        ],
        "severity_color": "#16a34a"
    },
    "DEEP_SUBDOMAIN": {
        "name":        "DNS Tunneling Attack",
        "icon":        "v",
        "description": "Abnormally deep subdomain structure detected. "
                       "Attackers use deep subdomains to encode and "
                       "exfiltrate data through DNS queries.",
        "how_it_works": [
            "Data is encoded in subdomain labels",
            "Each DNS query carries a hidden payload",
            "Bypasses traditional firewalls",
            "Used for covert command and control communication"
        ],
        "mitigation": [
            "Block source IP immediately",
            "Add firewall rule for deep subdomain queries",
            "Investigate what data may have been exfiltrated",
            "Implement subdomain depth limits on DNS server",
            "Deploy DNS inspection tools for ongoing monitoring"
        ],
        "severity_color": "#d97706"
    }
}

st.set_page_config(
    page_title="Attack Management",
    page_icon="shield",
    layout="wide"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .main { background-color: #111318; }
    [data-testid="stSidebar"] {
        background-color: #0d0f14;
        border-right: 1px solid #1e2230;
    }
    [data-testid="metric-container"] {
        background-color: #161923;
        border: 1px solid #1e2230;
        border-radius: 8px;
        padding: 16px;
    }
    .section-title {
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        color: #6b7280;
        margin: 20px 0 10px 0;
        padding-bottom: 6px;
        border-bottom: 1px solid #1e2230;
    }
    .alert-card {
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 6px;
        border: 1px solid #1e2230;
    }
    .section-active {
        background-color: #1f0a0a;
        border: 1px solid #dc2626;
        border-radius: 6px;
        padding: 10px 16px;
        margin: 12px 0 8px 0;
        font-size: 13px;
        font-weight: 600;
        color: #dc2626;
    }
    .section-closed {
        background-color: #0a1a0e;
        border: 1px solid #16a34a;
        border-radius: 6px;
        padding: 10px 16px;
        margin: 12px 0 8px 0;
        font-size: 13px;
        font-weight: 600;
        color: #16a34a;
    }
    #MainMenu { visibility: hidden; }
    footer    { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Helper Functions ──
def load_alerts(limit=9999999):
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query(
            f"""SELECT * FROM alerts
                WHERE domain NOT LIKE '%in-addr.arpa%'
                AND domain NOT LIKE '%ip6.arpa%'
                ORDER BY id DESC LIMIT {limit}""", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def get_real_counts():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='Open'")
        open_c = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='Investigating'")
        inv_c = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='Resolved'")
        res_c = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status='False Positive'")
        fp_c = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'")
        high_c = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='Medium'")
        med_c = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity='Low'")
        low_c = cursor.fetchone()[0]
        conn.close()
        return total, open_c, inv_c, res_c, fp_c, high_c, med_c, low_c
    except:
        return 0, 0, 0, 0, 0, 0, 0, 0

def update_alert_status(alert_id, new_status):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET status=? WHERE id=?',
                      (new_status, alert_id))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def block_ip(ip):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT',
                       '-s', ip, '-j', 'DROP'], capture_output=True)
        return True
    except:
        return False

def unblock_ip(ip):
    try:
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT',
                       '-s', ip, '-j', 'DROP'], capture_output=True)
        return True
    except:
        return False

def get_blocked_ips():
    try:
        result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-n'],
                               capture_output=True, text=True)
        blocked = []
        for line in result.stdout.split('\n'):
            if 'DROP' in line:
                parts = line.split()
                if len(parts) >= 4:
                    blocked.append(parts[3])
        return blocked
    except:
        return []

def render_alert_card(alert):
    reason = alert['reason']
    info   = ATTACK_INFO.get(reason, {
        "name": reason, "icon": "!",
        "description": "Unknown attack type",
        "how_it_works": [], "mitigation": [],
        "severity_color": "#6b7280"
    })
    color        = info['severity_color']
    time_short   = str(alert['timestamp'])[11:19]
    domain_short = str(alert['domain'])[:50] + '...' \
        if len(str(alert['domain'])) > 50 else str(alert['domain'])

    sev_bg = {'High': '#1f0a0a', 'Medium': '#1a0f00', 'Low': '#0a1a0e'}
    bg = sev_bg.get(alert['severity'], '#161923')

    st.markdown(f"""
    <div style="background:{bg}; border-left:4px solid {color};
                border-radius:0 6px 6px 0; padding:14px 18px;
                margin-bottom:4px;">
        <div style="display:flex; justify-content:space-between;
                    align-items:center; flex-wrap:wrap;">
            <div>
                <span style="color:{color}; font-size:14px;
                             font-weight:600;">
                    {info['name']}
                </span>
                <span style="background:{color}; color:#fff;
                             border-radius:4px; padding:2px 8px;
                             font-size:10px; font-weight:600;
                             margin-left:8px;">
                    {alert['severity'].upper()}
                </span>
            </div>
            <span style="color:#4b5563; font-size:11px;
                         font-family: JetBrains Mono, monospace;">
                {time_short} &nbsp;|&nbsp; {alert['status']}
            </span>
        </div>
        <div style="margin-top:8px; font-size:12px;
                    font-family: JetBrains Mono, monospace;">
            <span style="color:#6b7280;">IP &nbsp;&nbsp;&nbsp;</span>
            <span style="color:#e2e8f0;">{alert['client_ip']}</span>
            <span style="color:#374151;">&nbsp;&nbsp;|&nbsp;&nbsp;</span>
            <span style="color:#6b7280;">Domain &nbsp;</span>
            <span style="color:#94a3b8;">{domain_short}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("View Details and Mitigate"):
        left_col, right_col = st.columns([1, 1])

        with left_col:
            st.markdown(f"""
            <div style="background:#0d0f14; border:1px solid #1e2230;
                        border-radius:6px; padding:14px 16px;">
                <div style="color:{color}; font-size:12px;
                            font-weight:600; margin-bottom:8px;
                            text-transform:uppercase; letter-spacing:1px;">
                    What is this attack?
                </div>
                <div style="color:#94a3b8; font-size:12px;
                            line-height:1.6; margin-bottom:14px;">
                    {info['description']}
                </div>
                <div style="color:{color}; font-size:12px;
                            font-weight:600; margin-bottom:8px;
                            text-transform:uppercase; letter-spacing:1px;">
                    How it works
                </div>
            </div>
            """, unsafe_allow_html=True)
            for point in info['how_it_works']:
                st.markdown(
                    f"<div style='color:#94a3b8; font-size:12px;"
                    f"padding:3px 0 3px 12px; line-height:1.5;'>"
                    f"— {point}</div>",
                    unsafe_allow_html=True)

        with right_col:
            st.markdown(f"""
            <div style="background:#0d0f14; border:1px solid #1e2230;
                        border-radius:6px; padding:14px 16px;">
                <div style="color:#16a34a; font-size:12px;
                            font-weight:600; margin-bottom:8px;
                            text-transform:uppercase; letter-spacing:1px;">
                    How to mitigate
                </div>
            </div>
            """, unsafe_allow_html=True)
            for step in info['mitigation']:
                st.markdown(
                    f"<div style='color:#94a3b8; font-size:12px;"
                    f"padding:3px 0 3px 12px; line-height:1.5;'>"
                    f"+ {step}</div>",
                    unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("""
            <div style='font-size:12px; font-weight:600;
                        color:#6b7280; text-transform:uppercase;
                        letter-spacing:1px; margin-bottom:8px;'>
                Take Action
            </div>
            """, unsafe_allow_html=True)

            b1, b2 = st.columns(2)
            with b1:
                if st.button("Investigate",
                            key=f"inv_{alert['id']}",
                            use_container_width=True):
                    update_alert_status(alert['id'], 'Investigating')
                    st.success("Moved to Investigating!")
                    time.sleep(1)
                    st.rerun()
            with b2:
                if st.button("Resolve",
                            key=f"res_{alert['id']}",
                            use_container_width=True):
                    update_alert_status(alert['id'], 'Resolved')
                    st.success("Moved to Closed!")
                    time.sleep(1)
                    st.rerun()
            b3, b4 = st.columns(2)
            with b3:
                if st.button("False Positive",
                            key=f"fp_{alert['id']}",
                            use_container_width=True):
                    update_alert_status(alert['id'], 'False Positive')
                    st.warning("Moved to Closed!")
                    time.sleep(1)
                    st.rerun()
            with b4:
                if st.button("Block IP",
                            key=f"blk_{alert['id']}",
                            use_container_width=True):
                    if block_ip(alert['client_ip']):
                        update_alert_status(alert['id'], 'Resolved')
                        st.error(f"IP {alert['client_ip']} BLOCKED!")
                        time.sleep(1)
                        st.rerun()

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style='padding:16px 0 8px 0;'>
        <div style='font-size:18px; font-weight:700;
                    color:#f1f5f9; letter-spacing:0.5px;'>
            Attack Management
        </div>
        <div style='font-size:11px; color:#6b7280; margin-top:2px;'>
            Review and Mitigate Threats
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Display
    </div>
    """, unsafe_allow_html=True)
    alert_limit = st.selectbox(
        "Show Alerts",
        [20, 50, 100, 250, 500, 9999999],
        index=1,
        format_func=lambda x:
            f"Latest {x}" if x < 9999999 else "All Alerts")

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Quick Filter
    </div>
    """, unsafe_allow_html=True)
    quick_filter = st.radio(
        "Show",
        ["All", "Open Only", "High Severity"],
        index=0, label_visibility="collapsed")

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Bulk Actions
    </div>
    """, unsafe_allow_html=True)

    if st.button("Mark All Investigating", use_container_width=True):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status='Investigating' WHERE status='Open'")
        conn.commit()
        conn.close()
        st.success("Done!")
        time.sleep(1)
        st.rerun()

    if st.button("Mark All Resolved", use_container_width=True):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status='Resolved' WHERE status='Open'")
        conn.commit()
        conn.close()
        st.success("Done!")
        time.sleep(1)
        st.rerun()

    if st.button("Mark All False Positive", use_container_width=True):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status='False Positive' WHERE status='Open'")
        conn.commit()
        conn.close()
        st.success("Done!")
        time.sleep(1)
        st.rerun()

# ── Load Data ──
all_alerts_df = load_alerts()
real_total, open_a, inv_a, res_a, fp_a, \
    high_a, med_a, low_a = get_real_counts()

display_df = all_alerts_df.head(
    alert_limit if alert_limit < 9999999 else len(all_alerts_df))

# ── Header ──
st.markdown(f"""
<div style='background-color:#161923; border:1px solid #1e2230;
            border-radius:8px; padding:20px 24px; margin-bottom:16px;'>
    <div style='font-size:20px; font-weight:700; color:#f1f5f9;'>
        Attack Management and Mitigation
    </div>
    <div style='font-size:12px; color:#6b7280; margin-top:4px;'>
        Review detected threats and take remediation action
    </div>
</div>
""", unsafe_allow_html=True)

if all_alerts_df.empty:
    st.markdown("""
    <div style='background:#0a1a0e; border:1px solid #16a34a;
                border-radius:8px; padding:24px; text-align:center;
                color:#16a34a; font-size:14px; font-weight:600;'>
        No attacks detected — system is clean
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Metrics ──
st.markdown("""
<div class='section-title'>Alert Overview</div>
""", unsafe_allow_html=True)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Alerts",   real_total)
m2.metric("Open",           open_a)
m3.metric("Investigating",  inv_a)
m4.metric("Resolved",       res_a)
m5.metric("False Positive", fp_a)

m6, m7, m8 = st.columns(3)
m6.metric("High Severity",   high_a)
m7.metric("Medium Severity", med_a)
m8.metric("Low Severity",    low_a)

st.markdown(f"""
<div style='background:#161923; border:1px solid #1e2230;
            border-radius:6px; padding:10px 16px;
            margin:8px 0; color:#6b7280; font-size:12px;
            font-family: JetBrains Mono, monospace;'>
    Showing latest
    <span style='color:#60a5fa;'>
        {alert_limit if alert_limit < 9999999 else "all"}
    </span>
    of
    <span style='color:#f1f5f9;'>{real_total}</span>
    total alerts in database
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Filters ──
st.markdown("""
<div class='section-title'>Filter</div>
""", unsafe_allow_html=True)

fc1, fc2, fc3 = st.columns(3)
with fc1:
    filter_severity = st.selectbox("Severity",
        ["All", "High", "Medium", "Low"])
with fc2:
    filter_reason = st.selectbox("Attack Type",
        ["All", "HIGH_ENTROPY", "HIGH_QUERY_RATE",
         "ML_ANOMALY", "ADAPTIVE_ANOMALY", "DEEP_SUBDOMAIN"])
with fc3:
    filter_status = st.selectbox("Status",
        ["All", "Open", "Investigating", "Resolved", "False Positive"],
        index=0)

filtered_df = display_df.copy()
if quick_filter == "Open Only":
    filtered_df = filtered_df[filtered_df['status'] == 'Open']
elif quick_filter == "High Severity":
    filtered_df = filtered_df[filtered_df['severity'] == 'High']
if filter_severity != "All":
    filtered_df = filtered_df[filtered_df['severity'] == filter_severity]
if filter_reason != "All":
    filtered_df = filtered_df[filtered_df['reason'] == filter_reason]
if filter_status != "All":
    filtered_df = filtered_df[filtered_df['status'] == filter_status]

st.caption(f"Showing {len(filtered_df)} alerts")
st.divider()

# ── Alert Cards ──
st.markdown("""
<div class='section-title'>Attack Details and Mitigation</div>
""", unsafe_allow_html=True)

if filtered_df.empty:
    st.info("No alerts match the current filter.")
else:
    open_df = filtered_df[filtered_df['status'] == 'Open']
    inv_df  = filtered_df[filtered_df['status'] == 'Investigating']
    res_df  = filtered_df[filtered_df['status'] == 'Resolved']
    fp_df   = filtered_df[filtered_df['status'] == 'False Positive']

    st.markdown(f"""
    <div class='section-active'>
        Active Alerts
        <span style='font-size:11px; font-weight:400;
                     color:#9ca3af; margin-left:8px;'>
            Require immediate attention
        </span>
    </div>
    """, unsafe_allow_html=True)

    if not open_df.empty:
        with st.expander(f"Open  ({len(open_df)})", expanded=True):
            for _, alert in open_df.iterrows():
                render_alert_card(alert)
    else:
        st.markdown("""
        <div style='color:#6b7280; font-size:13px; padding:8px 0;'>
            No open alerts
        </div>
        """, unsafe_allow_html=True)

    if not inv_df.empty:
        with st.expander(f"Investigating  ({len(inv_df)})", expanded=True):
            for _, alert in inv_df.iterrows():
                render_alert_card(alert)

    st.markdown(f"""
    <div class='section-closed'>
        Closed Alerts
        <span style='font-size:11px; font-weight:400;
                     color:#9ca3af; margin-left:8px;'>
            Resolved and dismissed
        </span>
    </div>
    """, unsafe_allow_html=True)

    if not res_df.empty:
        with st.expander(f"Resolved  ({len(res_df)})", expanded=False):
            for _, alert in res_df.iterrows():
                render_alert_card(alert)
    else:
        st.markdown("""
        <div style='color:#6b7280; font-size:13px; padding:8px 0;'>
            No resolved alerts yet
        </div>
        """, unsafe_allow_html=True)

    if not fp_df.empty:
        with st.expander(f"False Positives  ({len(fp_df)})", expanded=False):
            for _, alert in fp_df.iterrows():
                render_alert_card(alert)

st.divider()

# ── Blocked IPs ──
st.markdown("""
<div class='section-title'>Blocked IPs</div>
""", unsafe_allow_html=True)

blocked = get_blocked_ips()
if blocked:
    for ip in blocked:
        bc1, bc2 = st.columns([4, 1])
        bc1.markdown(f"""
        <div style='background:#1f0a0a; border:1px solid #dc2626;
                    border-radius:6px; padding:10px 14px;
                    font-family: JetBrains Mono, monospace;
                    font-size:13px; color:#fca5a5;'>
            {ip} — BLOCKED
        </div>
        """, unsafe_allow_html=True)
        with bc2:
            if st.button("Unblock", key=f"unb_{ip}",
                        use_container_width=True):
                unblock_ip(ip)
                st.success(f"{ip} unblocked!")
                time.sleep(1)
                st.rerun()
else:
    st.markdown("""
    <div style='color:#6b7280; font-size:13px; padding:4px 0;'>
        No IPs currently blocked
    </div>
    """, unsafe_allow_html=True)

st.divider()

# ── Attack Analytics Charts ──
st.markdown("""
<div class='section-title'>Attack Analytics</div>
""", unsafe_allow_html=True)

ac1, ac2 = st.columns(2)

with ac1:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Attack Type Distribution
    </div>
    """, unsafe_allow_html=True)
    if not all_alerts_df.empty:
        ac = all_alerts_df['reason'].value_counts().reset_index()
        ac.columns = ['Attack Type', 'Count']
        fig = px.bar(ac, x='Attack Type', y='Count',
            color='Attack Type',
            color_discrete_map={
                'HIGH_ENTROPY':     '#dc2626',
                'HIGH_QUERY_RATE':  '#ea580c',
                'ML_ANOMALY':       '#7c3aed',
                'ADAPTIVE_ANOMALY': '#16a34a',
                'DEEP_SUBDOMAIN':   '#d97706'})
        fig.update_layout(
            showlegend=False,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            font_family='Inter',
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis=dict(gridcolor='#1e2230', title=''),
            yaxis=dict(gridcolor='#1e2230', title='Count'))
        fig.update_traces(marker_line_width=0)
        st.plotly_chart(fig, use_container_width=True,
                       config={'displayModeBar': False})

with ac2:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Alert Status Overview
    </div>
    """, unsafe_allow_html=True)
    if not all_alerts_df.empty:
        sc = all_alerts_df['status'].value_counts().reset_index()
        sc.columns = ['Status', 'Count']
        fig = px.pie(sc, names='Status', values='Count',
            color='Status', hole=0.5,
            color_discrete_map={
                'Open':           '#dc2626',
                'Investigating':  '#ea580c',
                'Resolved':       '#16a34a',
                'False Positive': '#6366f1'})
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            font_family='Inter',
            margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig, use_container_width=True,
                       config={'displayModeBar': False})

st.divider()

csv = all_alerts_df.to_csv(index=False)
st.download_button(
    "Export All Alerts CSV",
    data=csv,
    file_name="dns_alerts_full.csv",
    mime="text/csv")

st.markdown("<br>", unsafe_allow_html=True)
st.markdown(f"""
<div style='text-align:center; color:#374151; font-size:11px;
            padding:12px; border-top:1px solid #1e2230;
            font-family: JetBrains Mono, monospace;'>
    Adaptive DNS Anomaly Detection System &nbsp;|&nbsp;
    {pd.Timestamp.now(tz='Asia/Colombo').strftime('%Y-%m-%d %H:%M:%S')} IST
</div>
""", unsafe_allow_html=True)

time.sleep(10)
st.rerun()
