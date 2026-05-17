import streamlit as st
import warnings
warnings.filterwarnings('ignore')
import sqlite3
import pandas as pd
import plotly.express as px
import re
import math
from collections import Counter
import time

DB_FILE = "/home/student/dns-anomaly/dns_anomaly.db"

st.set_page_config(
    page_title="Log File Analysis",
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
    .upload-area {
        background-color: #161923;
        border: 2px dashed #1e2230;
        border-radius: 8px;
        padding: 32px;
        text-align: center;
        margin: 12px 0;
    }
    .result-clean {
        background-color: #0a1a0e;
        border: 1px solid #16a34a;
        border-radius: 6px;
        padding: 12px 18px;
        color: #16a34a;
        font-size: 13px;
        font-weight: 600;
        margin: 8px 0;
    }
    .result-threat {
        background-color: #1f0a0a;
        border: 1px solid #dc2626;
        border-radius: 6px;
        padding: 12px 18px;
        color: #dc2626;
        font-size: 13px;
        font-weight: 600;
        margin: 8px 0;
    }
    #MainMenu { visibility: hidden; }
    footer    { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Feature Extraction ──
def shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def subdomain_depth(domain):
    return len(domain.strip('.').split('.'))

QUERY_RE = re.compile(
    r'client\s+\S+\s+([\d\.]+)#\d+\s+\(([^)]+)\):'
    r'\s+query:\s+\S+\s+IN\s+(\w+).*\+',
    re.IGNORECASE
)

def parse_log_line(line):
    match = QUERY_RE.search(line)
    if not match:
        return None
    return {
        'client_ip':  match.group(1),
        'domain':     match.group(2),
        'query_type': match.group(3),
        'entropy':    round(shannon_entropy(match.group(2)), 2),
        'depth':      subdomain_depth(match.group(2)),
        'length':     len(match.group(2))
    }

KNOWN_LEGIT_LOG = [
    'mydns.test', 'ns1.mydns.test', 'ns2.mydns.test',
    'www.mydns.test', 'web.mydns.test', 'http.mydns.test',
    'mail.mydns.test', 'smtp.mydns.test', 'pop.mydns.test',
    'pop3.mydns.test', 'imap.mydns.test', 'webmail.mydns.test',
    'ftp.mydns.test', 'sftp.mydns.test', 'vpn.mydns.test',
    'remote.mydns.test', 'rdp.mydns.test',
    'api.mydns.test', 'app.mydns.test', 'portal.mydns.test',
    'gateway.mydns.test', 'dev.mydns.test', 'test.mydns.test',
    'staging.mydns.test', 'uat.mydns.test', 'qa.mydns.test',
    'db.mydns.test', 'database.mydns.test',
    'mysql.mydns.test', 'postgres.mydns.test',
    'admin.mydns.test', 'monitor.mydns.test', 'backup.mydns.test',
    'storage.mydns.test', 'ntp.mydns.test', 'proxy.mydns.test',
    'firewall.mydns.test', 'router.mydns.test',
    'shop.mydns.test', 'store.mydns.test', 'blog.mydns.test',
    'news.mydns.test', 'media.mydns.test', 'cdn.mydns.test',
    'static.mydns.test', 'auth.mydns.test', 'login.mydns.test',
    'sso.mydns.test', 'ldap.mydns.test',
    'docs.mydns.test', 'help.mydns.test', 'support.mydns.test',
    'sip.mydns.test',
]

def classify_query(row):
    # Known legitimate domains are always normal
    if row['domain'] in KNOWN_LEGIT_LOG:
        return 'Normal', 'None'
    reasons = []
    if row['entropy'] >= 3.6:
        reasons.append('HIGH_ENTROPY')
    if row['depth'] >= 4:
        reasons.append('DEEP_SUBDOMAIN')
    if row['length'] >= 40:
        reasons.append('LONG_DOMAIN')
    if reasons:
        return 'Suspicious', ', '.join(reasons)
    return 'Normal', 'None'

def analyze_log(content):
    lines   = content.decode('utf-8', errors='ignore').splitlines()
    records = []
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            records.append(parsed)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    ip_counts = df['client_ip'].value_counts()
    df['query_count'] = df['client_ip'].map(ip_counts)
    df[['Classification', 'Reason']] = df.apply(
        lambda row: pd.Series(classify_query(row)), axis=1)
    high_rate = (df['query_count'] >= 100) & (~df['domain'].isin(KNOWN_LEGIT_LOG))
    df.loc[high_rate, 'Classification'] = 'Suspicious'
    df.loc[high_rate, 'Reason'] = df.loc[high_rate, 'Reason'].astype(str) + ', HIGH_QUERY_RATE'
    return df

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style='padding:16px 0 8px 0;'>
        <div style='font-size:18px; font-weight:700;
                    color:#f1f5f9; letter-spacing:0.5px;'>
            Log Analysis
        </div>
        <div style='font-size:11px; color:#6b7280; margin-top:2px;'>
            Batch DNS Log Detection
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Supported Formats
    </div>
    <div style='font-family: JetBrains Mono, monospace;
                font-size:11px; color:#94a3b8; line-height:1.8;'>
        .log &nbsp;&nbsp;&nbsp;BIND9 query log<br>
        .txt &nbsp;&nbsp;&nbsp;Text log file<br>
        .syslog &nbsp;System log
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Detection Thresholds
    </div>
    <div style='font-family: JetBrains Mono, monospace;
                font-size:11px; color:#94a3b8; line-height:1.8;'>
        Entropy &nbsp;&nbsp;&nbsp;&nbsp;&gt; 3.6<br>
        Depth &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&gt; 4<br>
        Length &nbsp;&nbsp;&nbsp;&nbsp;&gt; 40<br>
        Query Rate &nbsp;&gt; 20
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Live System Stats
    </div>
    """, unsafe_allow_html=True)
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM dns_events')
        total_live = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts_live = cursor.fetchone()[0]
        conn.close()
        st.metric("Live Events", total_live)
        st.metric("Live Alerts", total_alerts_live)
    except:
        pass

# ── Header ──
st.markdown(f"""
<div style='background-color:#161923; border:1px solid #1e2230;
            border-radius:8px; padding:20px 24px; margin-bottom:16px;'>
    <div style='font-size:20px; font-weight:700; color:#f1f5f9;'>
        DNS Log File Analysis
    </div>
    <div style='font-size:12px; color:#6b7280; margin-top:4px;'>
        Upload a BIND9 log file for batch anomaly detection
    </div>
</div>
""", unsafe_allow_html=True)

# ── Upload Section ──
st.markdown("""
<div class='section-title'>Upload DNS Log File</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class='upload-area'>
    <div style='font-size:36px; margin-bottom:8px;'>&#128193;</div>
    <div style='color:#6b7280; font-size:13px; margin-bottom:4px;'>
        Upload your BIND9 DNS query log file for analysis
    </div>
    <div style='font-family: JetBrains Mono, monospace;
                color:#4b5563; font-size:11px;'>
        Supported: .log &nbsp;|&nbsp; .txt &nbsp;|&nbsp; .syslog
    </div>
</div>
""", unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Choose a DNS log file",
    type=["log", "txt", "syslog"],
    label_visibility="collapsed"
)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("""
<div class='section-title'>Or Analyze Live System Log</div>
""", unsafe_allow_html=True)

col1, col2 = st.columns([2, 5])
with col1:
    analyze_live = st.button(
        "Analyze Current /var/log/syslog",
        width="stretch")

if analyze_live:
    try:
        with open("/var/log/syslog", "rb") as f:
            content = f.read()
        st.session_state['syslog_content'] = content
        st.markdown("""
        <div class='result-clean'>
            Syslog loaded successfully
        </div>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error reading syslog: {e}")

# ── Analysis ──
content  = None
filename = ""

if uploaded_file is not None:
    content  = uploaded_file.read()
    filename = uploaded_file.name
elif 'syslog_content' in st.session_state:
    content  = st.session_state['syslog_content']
    filename = "/var/log/syslog (live system)"

if content:
    st.markdown(f"""
    <div class='section-title'>
        Analysis Results — {filename}
    </div>
    """, unsafe_allow_html=True)

    with st.spinner("Analyzing log file for anomalies..."):
        df = analyze_log(content)
        time.sleep(0.5)

    if df.empty:
        st.warning("No DNS queries found in this log file. "
                   "Please ensure it is a valid BIND9 query log.")
    else:
        total   = len(df)
        sus     = len(df[df['Classification'] == 'Suspicious'])
        normal  = len(df[df['Classification'] == 'Normal'])
        sus_pct = round((sus / total) * 100, 1) if total else 0

        if sus > 0:
            st.markdown(f"""
            <div class='result-threat'>
                {sus} suspicious queries detected
                ({sus_pct}% of total traffic)
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class='result-clean'>
                No suspicious queries detected — log file appears clean
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div class='section-title'>Analysis Summary</div>
        """, unsafe_allow_html=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Queries",   total)
        m2.metric("Normal",          normal)
        m3.metric("Suspicious",      sus)
        m4.metric("Suspicion Rate",  f"{sus_pct}%")

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("""
        <div class='section-title'>Analysis Charts</div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            <div style='font-size:13px; font-weight:600;
                        color:#94a3b8; margin-bottom:8px;'>
                Query Classification
            </div>
            """, unsafe_allow_html=True)
            cc = df['Classification'].value_counts().reset_index()
            cc.columns = ['Type', 'Count']
            fig = px.pie(cc, names='Type', values='Count',
                color='Type', hole=0.5,
                color_discrete_map={
                    'Normal':     '#16a34a',
                    'Suspicious': '#dc2626'})
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#94a3b8',
                font_family='Inter',
                margin=dict(t=10, b=10, l=10, r=10))
            st.plotly_chart(fig, width="stretch",
                           config={'displayModeBar': False})

        with col2:
            st.markdown("""
            <div style='font-size:13px; font-weight:600;
                        color:#94a3b8; margin-bottom:8px;'>
                Entropy Distribution
            </div>
            """, unsafe_allow_html=True)
            fig = px.histogram(df, x='entropy', nbins=20,
                color_discrete_sequence=['#3b82f6'])
            fig.add_vline(x=3.6, line_dash="dash",
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



        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("""
        <div class='section-title'>Suspicious Queries Detected</div>
        """, unsafe_allow_html=True)

        sus_df = df[df['Classification'] == 'Suspicious']
        if not sus_df.empty:
            st.dataframe(
                sus_df[['client_ip', 'domain', 'query_type',
                        'entropy', 'depth', 'length',
                        'query_count', 'Reason']],
                width="stretch", height=300)
            csv = sus_df.to_csv(index=False)
            st.download_button(
                "Export Suspicious Queries CSV",
                data=csv,
                file_name="suspicious_queries.csv",
                mime="text/csv")
        else:
            st.markdown("""
            <div class='result-clean'>
                No suspicious queries found
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        with st.expander("View All Parsed Queries"):
            st.dataframe(
                df[['client_ip', 'domain', 'query_type',
                    'entropy', 'depth', 'length',
                    'query_count', 'Classification', 'Reason']],
                width="stretch", height=400)
            csv_all = df.to_csv(index=False)
            st.download_button(
                "Export All Queries CSV",
                data=csv_all,
                file_name="all_queries.csv",
                mime="text/csv")
else:
    st.markdown("""
    <div style='background:#161923; border:1px solid #1e2230;
                border-radius:8px; padding:48px;
                text-align:center; color:#6b7280;'>
        <div style='font-size:48px; margin-bottom:12px;'>&#128193;</div>
        <div style='font-size:14px;'>
            Upload a log file or click Analyze Current Syslog to begin
        </div>
        <div style='font-family: JetBrains Mono, monospace;
                    font-size:12px; color:#4b5563; margin-top:8px;'>
            Supported formats: .log &nbsp;|&nbsp; .txt &nbsp;|&nbsp; .syslog
        </div>
    </div>
    """, unsafe_allow_html=True)

# ── Footer ──
st.markdown("<br>", unsafe_allow_html=True)
st.markdown(f"""
<div style='text-align:center; color:#374151; font-size:11px;
            padding:12px; border-top:1px solid #1e2230;
            font-family: JetBrains Mono, monospace;'>
    Adaptive DNS Anomaly Detection System &nbsp;|&nbsp;
    {pd.Timestamp.now(tz='Asia/Colombo').strftime('%Y-%m-%d %H:%M:%S')} IST
</div>
""", unsafe_allow_html=True)
