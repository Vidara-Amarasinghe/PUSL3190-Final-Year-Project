import streamlit as st
import warnings
warnings.filterwarnings('ignore')
import logging
logging.getLogger('streamlit').setLevel(logging.ERROR)
import sqlite3
import pandas as pd
import plotly.express as px
import subprocess
import time

DB_FILE    = "/home/student/dns-anomaly/dns_anomaly.db"
ALERTS_LOG = "/home/student/dns-anomaly/alerts.log"
DETECTOR   = "/home/student/dns-anomaly/detector.py"

KNOWN_LEGITIMATE = [
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

st.set_page_config(
    page_title="DNS Anomaly Detection System",
    page_icon="shield",
    layout="wide"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    .main {
        background-color: #111318;
    }
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
    .top-bar {
        background-color: #161923;
        border: 1px solid #1e2230;
        border-radius: 8px;
        padding: 16px 24px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .status-ok {
        background-color: #0a1f14;
        border: 1px solid #16a34a;
        border-radius: 6px;
        padding: 10px 20px;
        color: #16a34a;
        font-weight: 600;
        font-size: 14px;
        text-align: center;
        margin-bottom: 12px;
    }
    .status-alert {
        background-color: #1f0a0a;
        border: 2px solid #dc2626;
        border-radius: 6px;
        padding: 10px 20px;
        color: #dc2626;
        font-weight: 600;
        font-size: 14px;
        text-align: center;
        margin-bottom: 12px;
        animation: blink 1s step-start infinite;
    }
    .new-alert-flash {
        background-color: #1f0a0a;
        border: 1px solid #f87171;
        border-radius: 6px;
        padding: 8px 16px;
        color: #f87171;
        font-size: 13px;
        text-align: center;
        margin-bottom: 8px;
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
    .monospace {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
    }
    @keyframes blink {
        50% { opacity: 0.4; }
    }
    #MainMenu { visibility: hidden; }
    footer    { visibility: hidden; }
    [data-testid="stDataFrame"] {
        border: 1px solid #1e2230;
        border-radius: 8px;
    }
    .plotly-toolbar { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ── Helper Functions ──
def is_detector_running():
    result = subprocess.run(
        ['pgrep', '-f', 'detector.py'],
        capture_output=True, text=True)
    return result.returncode == 0

def load_events(limit=100):
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query(
            f"""SELECT * FROM dns_events
                WHERE domain NOT LIKE '%in-addr.arpa%'
                AND domain NOT LIKE '%ip6.arpa%'
                ORDER BY id DESC LIMIT {limit}""", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

def load_alerts(limit=100):
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

def get_total_counts():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM dns_events')
        total_events = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        conn.close()
        return total_events, total_alerts
    except:
        return 0, 0

def get_alerted_domains():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT domain FROM alerts')
        domains = set(row[0] for row in cursor.fetchall())
        conn.close()
        return domains
    except:
        return set()

def get_latest_alert_id():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT MAX(id) FROM alerts')
        result = cursor.fetchone()[0]
        conn.close()
        return result or 0
    except:
        return 0

# ── Session State ──
if 'last_alert_id' not in st.session_state:
    st.session_state.last_alert_id = get_latest_alert_id()
if 'attack_count' not in st.session_state:
    st.session_state.attack_count = 0

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style='padding:16px 0 8px 0;'>
        <div style='font-size:18px; font-weight:700;
                    color:#f1f5f9; letter-spacing:0.5px;'>
            DNS Guard
        </div>
        <div style='font-size:11px; color:#6b7280;
                    margin-top:2px;'>
            Anomaly Detection System
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    running = is_detector_running()
    if running:
        st.markdown("""
        <div style='display:flex; align-items:center; gap:8px;
                    padding:8px 12px; background:#0a1f14;
                    border:1px solid #16a34a; border-radius:6px;
                    margin-bottom:8px;'>
            <div style='width:8px; height:8px;
                        background:#16a34a; border-radius:50%;'></div>
            <span style='color:#16a34a; font-size:12px;
                         font-weight:600;'>DETECTOR RUNNING</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='display:flex; align-items:center; gap:8px;
                    padding:8px 12px; background:#1f0a0a;
                    border:1px solid #dc2626; border-radius:6px;
                    margin-bottom:8px;'>
            <div style='width:8px; height:8px;
                        background:#dc2626; border-radius:50%;'></div>
            <span style='color:#dc2626; font-size:12px;
                         font-weight:600;'>DETECTOR STOPPED</span>
        </div>
        """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    if c1.button("Start", width="stretch"):
        if not is_detector_running():
            subprocess.Popen(
                ['sudo', 'python3', DETECTOR],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            time.sleep(2)
            st.rerun()
    if c2.button("Stop", width="stretch"):
        subprocess.run(['sudo', 'pkill', '-f', 'detector.py'])
        time.sleep(1)
        st.rerun()

    st.divider()
    if st.button("Clear All Data", width="stretch"):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM dns_events')
        cursor.execute('DELETE FROM alerts')
        cursor.execute('DELETE FROM sqlite_sequence')
        conn.commit()
        conn.close()
        open(ALERTS_LOG, 'w').close()
        st.session_state.last_alert_id = 0
        st.session_state.attack_count  = 0
        st.success("Cleared!")
        time.sleep(1)
        st.rerun()

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280;
                font-weight:600; letter-spacing:1px;
                text-transform:uppercase; margin-bottom:8px;'>
        Configuration
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div style='font-family: JetBrains Mono, monospace;
                font-size:11px; color:#94a3b8;
                line-height:1.8;'>
        Server &nbsp;&nbsp;&nbsp;127.0.0.1<br>
        Zone &nbsp;&nbsp;&nbsp;&nbsp;mydns.test<br>
        Window &nbsp;&nbsp;10 seconds<br>
        Rate &nbsp;&nbsp;&nbsp;&nbsp;&gt;20 / 10s<br>
        Entropy &nbsp;&gt;3.5<br>
        Depth &nbsp;&nbsp;&nbsp;&gt;4 levels
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    refresh = st.slider("Refresh interval (s)", 3, 30, 5)

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280;
                font-weight:600; letter-spacing:1px;
                text-transform:uppercase; margin-bottom:8px;'>
        Display
    </div>
    """, unsafe_allow_html=True)
    event_limit = st.selectbox(
        "DNS Events",
        [100, 250, 500, 1000, 9999999],
        format_func=lambda x:
            f"Latest {x}" if x < 9999999 else "All")
    alert_limit = st.selectbox(
        "Alerts",
        [100, 250, 500, 1000, 9999999],
        format_func=lambda x:
            f"Latest {x}" if x < 9999999 else "All")

# ── Load Data ──
events_df        = load_events(event_limit)
alerts_df        = load_alerts(alert_limit)
total_events, total_alerts = get_total_counts()
alerted_domains  = get_alerted_domains()
all_alerts       = load_alerts(999999)
current_alert_id = get_latest_alert_id()
new_alerts       = current_alert_id - st.session_state.last_alert_id

if new_alerts > 0:
    st.session_state.attack_count  += new_alerts
    st.session_state.last_alert_id  = current_alert_id

high_c   = len(all_alerts[all_alerts['severity'] == 'High'])   if not all_alerts.empty else 0
medium_c = len(all_alerts[all_alerts['severity'] == 'Medium']) if not all_alerts.empty else 0
low_c    = len(all_alerts[all_alerts['severity'] == 'Low'])    if not all_alerts.empty else 0

# ── Top Bar ──
now_str = pd.Timestamp.now(tz='Asia/Colombo').strftime('%Y-%m-%d  %H:%M:%S')
st.markdown(f"""
<div style='background-color:#161923; border:1px solid #1e2230;
            border-radius:8px; padding:14px 24px;
            display:flex; align-items:center;
            justify-content:space-between; margin-bottom:16px;'>
    <div>
        <div style='font-size:20px; font-weight:700;
                    color:#f1f5f9; letter-spacing:0.3px;'>
            Adaptive DNS Anomaly Detection System
        </div>
        <div style='font-size:12px; color:#6b7280; margin-top:3px;'>
            Zone: mydns.test
        </div>
    </div>
    <div style='text-align:right;'>
        <div style='font-family: JetBrains Mono, monospace;
                    font-size:14px; color:#94a3b8;'>
            {now_str} IST
        </div>
        <div style='font-size:11px; color:#16a34a;
                    font-weight:600; margin-top:2px;'>
            {"MONITORING ACTIVE" if is_detector_running() else "DETECTOR OFFLINE"}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Status Banner ──
if st.session_state.attack_count > 0:
    st.markdown(f"""
    <div class='status-alert'>
        ACTIVE THREAT DETECTED — {st.session_state.attack_count} alert(s) — Navigate to Attack Management to mitigate
    </div>
    """, unsafe_allow_html=True)
    if new_alerts > 0:
        st.markdown(f"""
        <div class='new-alert-flash'>
            {new_alerts} NEW ALERT(S) JUST ARRIVED
        </div>
        <script>
        (function() {{
            try {{
                var AudioContext = window.AudioContext || window.webkitAudioContext;
                var ctx = new AudioContext();
                [880,440,880,440,880].forEach(function(f,i){{
                    var o = ctx.createOscillator();
                    var g = ctx.createGain();
                    o.connect(g); g.connect(ctx.destination);
                    o.frequency.value = f; o.type = 'square';
                    g.gain.setValueAtTime(0.1, ctx.currentTime + i*0.15);
                    g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i*0.15+0.1);
                    o.start(ctx.currentTime + i*0.15);
                    o.stop(ctx.currentTime + i*0.15+0.1);
                }});
            }} catch(e) {{}}
        }})();
        </script>
        """, unsafe_allow_html=True)
    col1, col2 = st.columns([6, 1])
    with col2:
        if st.button("Acknowledge"):
            st.session_state.attack_count  = 0
            st.session_state.last_alert_id = current_alert_id
            st.rerun()
else:
    st.markdown("""
    <div class='status-ok'>
        SYSTEM SECURE — No active threats detected
    </div>
    """, unsafe_allow_html=True)

# ── Metrics ──
st.markdown("""
<div class='section-title'>System Overview</div>
""", unsafe_allow_html=True)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Events",    total_events)
m2.metric("Total Alerts",    total_alerts)
m3.metric("High Severity",   high_c)
m4.metric("Medium Severity", medium_c)
m5.metric("Low Severity",    low_c)

if total_alerts > total_events:
    st.markdown("""
    <div style='background:#161923; border-left:3px solid #d97706;
                border-radius:0 6px 6px 0; padding:8px 14px;
                margin:4px 0; color:#94a3b8; font-size:11px;
                font-family: JetBrains Mono, monospace;'>
        Total Alerts exceeds Total Events because one DNS query can
        trigger multiple alerts simultaneously
        (HIGH_ENTROPY + ML_ANOMALY + ADAPTIVE_ANOMALY = 3 alerts from 1 query)
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Live Query Feed ──
st.markdown(f"""
<div class='section-title'>
    Live DNS Query Feed
    <span style='font-size:11px; color:#4b5563; font-weight:400;
                 text-transform:none; letter-spacing:0;'>
        — {len(events_df)} of {total_events} queries
    </span>
</div>
""", unsafe_allow_html=True)

if not events_df.empty:
    def classify_event(row):
        if row['domain'] in KNOWN_LEGITIMATE:
            return 'Legitimate'
        if row['domain'] in alerted_domains:
            return 'Attack'
        if row['entropy'] >= 3.6:
            return 'Attack'
        if row['length'] >= 20:
            return 'Attack'
        if 'mydns.test' not in row['domain']:
            return 'Attack'
        return 'Legitimate'

    events_df['Status']        = events_df.apply(classify_event, axis=1)
    events_df['Entropy Level'] = events_df['entropy'].apply(
        lambda e: 'High' if e >= 4.0 else ('Medium' if e >= 3.5 else 'Normal'))

    # Color rows based on status
    def color_rows(row):
        if row['Status'] == 'Attack':
            return ['background-color: #1f0a0a; color: #fca5a5'] * len(row)
        else:
            return ['background-color: #0a1a0e; color: #86efac'] * len(row)

    styled_df = events_df[['timestamp', 'client_ip', 'domain',
                            'query_type', 'entropy',
                            'Entropy Level', 'query_count',
                            'Status']].style.apply(color_rows, axis=1)
    st.dataframe(styled_df, width="stretch", height=280)
else:
    st.markdown("""
    <div style='background:#161923; border:1px solid #1e2230;
                border-radius:8px; padding:24px; text-align:center;
                color:#6b7280; font-size:13px;'>
        No DNS queries captured yet.<br>
        <span style='font-family: JetBrains Mono, monospace;
                     font-size:12px; color:#4b5563;'>
            dig @127.0.0.1 www.mydns.test A
        </span>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Charts — Keep only 2 best ──
st.markdown("""
<div class='section-title'>Detection Analytics</div>
""", unsafe_allow_html=True)

ch1, ch2 = st.columns(2)

with ch1:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Alert Types Breakdown
    </div>
    """, unsafe_allow_html=True)
    if not alerts_df.empty:
        ac = alerts_df['reason'].value_counts().reset_index()
        ac.columns = ['Type', 'Count']
        fig = px.bar(ac, x='Type', y='Count', color='Type',
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
        st.plotly_chart(fig, width="stretch",
                       config={'displayModeBar': False})
    else:
        st.info("No alerts yet.")

with ch2:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Entropy Distribution
    </div>
    """, unsafe_allow_html=True)
    if not events_df.empty:
        fig = px.histogram(events_df, x='entropy', nbins=20,
            color_discrete_sequence=['#3b82f6'])
        fig.add_vline(x=3.5, line_dash="dash",
            line_color="#dc2626", line_width=2,
            annotation_text="Attack Threshold (3.6)",
            annotation_font_color="#dc2626",
            annotation_font_size=11)
        fig.update_layout(
            xaxis_title="Entropy Score",
            yaxis_title="Query Count",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            font_family='Inter',
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis=dict(gridcolor='#1e2230'),
            yaxis=dict(gridcolor='#1e2230'))
        fig.update_traces(marker_line_width=0)
        st.plotly_chart(fig, width="stretch",
                       config={'displayModeBar': False})
    else:
        st.info("No events yet.")

st.markdown("<br>", unsafe_allow_html=True)

# ── Alert Log ──
st.markdown(f"""
<div class='section-title'>
    Alert Log
    <span style='font-size:11px; color:#4b5563; font-weight:400;
                 text-transform:none; letter-spacing:0;'>
        — {len(alerts_df)} of {total_alerts} total
    </span>
</div>
""", unsafe_allow_html=True)

if not alerts_df.empty:
    st.dataframe(
        alerts_df[['timestamp', 'client_ip', 'domain',
                   'reason', 'severity', 'status']],
        width="stretch", height=250)
    csv = alerts_df.to_csv(index=False)
    st.download_button(
        "Export Alerts as CSV",
        data=csv,
        file_name="dns_alerts.csv",
        mime="text/csv")
else:
    st.markdown("""
    <div style='background:#0a1a0e; border:1px solid #16a34a;
                border-radius:8px; padding:16px; text-align:center;
                color:#16a34a; font-size:13px;'>
        No alerts recorded — system is clean
    </div>
    """, unsafe_allow_html=True)

# ── Footer ──
st.markdown("<br>", unsafe_allow_html=True)
st.markdown(f"""
<div style='text-align:center; color:#374151; font-size:11px;
            padding:12px; border-top:1px solid #1e2230;
            font-family: JetBrains Mono, monospace;'>
    Adaptive DNS Anomaly Detection System &nbsp;|&nbsp;
    Refreshing every {refresh}s &nbsp;|&nbsp;
    {pd.Timestamp.now(tz='Asia/Colombo').strftime('%Y-%m-%d %H:%M:%S')} IST
</div>
""", unsafe_allow_html=True)

time.sleep(refresh)
st.rerun()
