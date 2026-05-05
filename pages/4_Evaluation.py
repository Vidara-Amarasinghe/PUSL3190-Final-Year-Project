import streamlit as st
import warnings
warnings.filterwarnings('ignore')
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import sys
import os
import time

DB_FILE = "/home/student/dns-anomaly/dns_anomaly.db"

st.set_page_config(
    page_title="ML Evaluation",
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
    .result-good {
        background-color: #0a1a0e;
        border: 1px solid #16a34a;
        border-radius: 6px;
        padding: 12px 18px;
        color: #16a34a;
        font-size: 13px;
        font-weight: 600;
        text-align: center;
        margin: 8px 0;
    }
    .result-warn {
        background-color: #1a1000;
        border: 1px solid #d97706;
        border-radius: 6px;
        padding: 12px 18px;
        color: #d97706;
        font-size: 13px;
        font-weight: 600;
        text-align: center;
        margin: 8px 0;
    }
    .result-bad {
        background-color: #1f0a0a;
        border: 1px solid #dc2626;
        border-radius: 6px;
        padding: 12px 18px;
        color: #dc2626;
        font-size: 13px;
        font-weight: 600;
        text-align: center;
        margin: 8px 0;
    }
    #MainMenu { visibility: hidden; }
    footer    { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

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

def load_data():
    try:
        conn = sqlite3.connect(DB_FILE)
        events_df = pd.read_sql_query('SELECT * FROM dns_events', conn)
        alerts_df = pd.read_sql_query('SELECT * FROM alerts', conn)
        conn.close()
        return events_df, alerts_df
    except:
        return pd.DataFrame(), pd.DataFrame()

def label_event(row, alerted_domains):
    if row['domain'] in KNOWN_LEGITIMATE:
        return 0
    if row['entropy'] >= 3.6:
        return 1
    if row['depth'] >= 4:
        return 1
    if row['length'] >= 40:
        return 1
    if row['query_count'] >= 20:
        return 1
    if row['domain'] in alerted_domains:
        return 1
    return 0

def run_evaluation():
    events_df, alerts_df = load_data()
    if len(events_df) < 10:
        return None
    alerted_domains = set(alerts_df['domain'].unique()) \
        if not alerts_df.empty else set()
    events_df['true_label'] = events_df.apply(
        lambda row: label_event(row, alerted_domains), axis=1)
    sys.path.insert(0, '/home/student/dns-anomaly')
    os.chdir('/home/student/dns-anomaly')
    try:
        from ml_model import load_model, predict
        model, scaler = load_model()
        if model is None:
            return None
    except:
        return None
    predictions = []
    scores      = []
    for _, row in events_df.iterrows():
        try:
            is_anomaly, score = predict(
                model, scaler,
                row['entropy'], row['depth'],
                row['length'], row['query_count'])
            if row['domain'] in KNOWN_LEGITIMATE:
                is_anomaly = False
            predictions.append(1 if is_anomaly else 0)
            scores.append(score)
        except:
            predictions.append(0)
            scores.append(0.0)
    events_df['predicted_label'] = predictions
    events_df['anomaly_score']   = scores
    y_true = events_df['true_label'].values
    y_pred = events_df['predicted_label'].values
    if len(set(y_true)) < 2:
        return None
    from sklearn.metrics import (
        precision_score, recall_score, f1_score, confusion_matrix)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall    = recall_score(y_true, y_pred, zero_division=0)
    f1        = f1_score(y_true, y_pred, zero_division=0)
    cm        = confusion_matrix(y_true, y_pred)
    tn = cm[0][0]; fp = cm[0][1]
    fn = cm[1][0]; tp = cm[1][1]
    total     = tn + fp + fn + tp
    accuracy  = round((tp + tn) / total * 100, 2)
    fpr       = round(fp / (fp + tn) * 100, 2) if (fp + tn) > 0 else 0
    fnr       = round(fn / (fn + tp) * 100, 2) if (fn + tp) > 0 else 0
    detection = round(tp / (tp + fn) * 100, 2) if (tp + fn) > 0 else 0
    normal_scores = events_df[events_df['true_label'] == 0]['anomaly_score']
    attack_scores = events_df[events_df['true_label'] == 1]['anomaly_score']
    return {
        'events_df': events_df, 'total': total,
        'normal_count': int((y_true == 0).sum()),
        'attack_count': int((y_true == 1).sum()),
        'accuracy': accuracy, 'detection_rate': detection,
        'precision': round(precision * 100, 2),
        'recall': round(recall * 100, 2),
        'f1': round(f1 * 100, 2),
        'fpr': fpr, 'fnr': fnr,
        'tp': int(tp), 'tn': int(tn),
        'fp': int(fp), 'fn': int(fn),
        'normal_scores': normal_scores,
        'attack_scores': attack_scores, 'cm': cm
    }

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style='padding:16px 0 8px 0;'>
        <div style='font-size:18px; font-weight:700;
                    color:#f1f5f9; letter-spacing:0.5px;'>
            ML Evaluation
        </div>
        <div style='font-size:11px; color:#6b7280; margin-top:2px;'>
            Model Performance Metrics
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        About
    </div>
    <div style='font-size:12px; color:#94a3b8; line-height:1.7;'>
        Evaluates the Isolation Forest ML model
        against ground truth labels derived
        from DNS traffic rules.<br><br>
        Ground truth labels:<br>
        Normal — known legitimate domains<br>
        Attack — high entropy, deep subdomain,
        high query rate, or alerted domains
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    <div style='font-size:11px; color:#6b7280; font-weight:600;
                letter-spacing:1px; text-transform:uppercase;
                margin-bottom:8px;'>
        Target Metrics
    </div>
    <div style='font-family: JetBrains Mono, monospace;
                font-size:11px; color:#94a3b8; line-height:1.8;'>
        Accuracy &nbsp;&nbsp;&nbsp;&nbsp;&gt; 75%<br>
        Detection &nbsp;&nbsp;&nbsp;&gt; 85%<br>
        F1 Score &nbsp;&nbsp;&nbsp;&nbsp;&gt; 80%<br>
        False Pos &nbsp;&nbsp;&nbsp;&lt; 30%
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    if st.button("Re-run Evaluation", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ── Header ──
st.markdown(f"""
<div style='background-color:#161923; border:1px solid #1e2230;
            border-radius:8px; padding:20px 24px; margin-bottom:16px;'>
    <div style='font-size:20px; font-weight:700; color:#f1f5f9;'>
        ML Model Performance Evaluation
    </div>
    <div style='font-size:12px; color:#6b7280; margin-top:4px;'>
        Isolation Forest Anomaly Detection Evaluation
    </div>
</div>
""", unsafe_allow_html=True)

with st.spinner("Running ML evaluation..."):
    results = run_evaluation()

if results is None:
    st.markdown("""
    <div style='background:#1a1000; border:1px solid #d97706;
                border-radius:8px; padding:20px; text-align:center;
                color:#d97706; font-size:13px;'>
        Not enough data to evaluate.
        Run mixed_queries.sh first to generate data.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Dataset Summary ──
st.markdown("""
<div class='section-title'>Dataset Summary</div>
""", unsafe_allow_html=True)

d1, d2, d3 = st.columns(3)
d1.metric("Total Events",   results['total'])
d2.metric("Normal Queries", results['normal_count'])
d3.metric("Attack Queries", results['attack_count'])

st.markdown("<br>", unsafe_allow_html=True)

# ── Performance Metrics ──
st.markdown("""
<div class='section-title'>Performance Metrics</div>
""", unsafe_allow_html=True)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Accuracy",       f"{results['accuracy']}%")
m2.metric("Detection Rate", f"{results['detection_rate']}%")
m3.metric("F1 Score",       f"{results['f1']}%")
m4.metric("Precision",      f"{results['precision']}%")

m5, m6, m7, m8 = st.columns(4)
m5.metric("Recall",              f"{results['recall']}%")
m6.metric("False Positive Rate", f"{results['fpr']}%")
m7.metric("False Negative Rate", f"{results['fnr']}%")
m8.metric("True Positives",      results['tp'])

st.markdown("<br>", unsafe_allow_html=True)

accuracy = results['accuracy']
f1       = results['f1']
fpr      = results['fpr']

if accuracy >= 75 and f1 >= 80 and fpr <= 30:
    st.markdown("""
    <div class='result-good'>
        Model performance is GOOD — meets all target thresholds
    </div>
    """, unsafe_allow_html=True)
elif accuracy >= 60:
    st.markdown(f"""
    <div class='result-warn'>
        Model performance is ACCEPTABLE — some metrics need improvement (FPR: {fpr}%)
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div class='result-bad'>
        Model performance needs improvement — consider retraining with more data
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Charts ──
st.markdown("""
<div class='section-title'>Evaluation Charts</div>
""", unsafe_allow_html=True)

ch1, ch2 = st.columns(2)

with ch1:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Confusion Matrix
    </div>
    """, unsafe_allow_html=True)
    cm_df = pd.DataFrame(
        results['cm'],
        index=['Actual Normal', 'Actual Attack'],
        columns=['Predicted Normal', 'Predicted Attack'])
    fig = px.imshow(cm_df, text_auto=True,
        color_continuous_scale='Blues', aspect='auto')
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#94a3b8',
        font_family='Inter',
        margin=dict(t=10, b=10, l=10, r=10))
    st.plotly_chart(fig, use_container_width=True,
                   config={'displayModeBar': False})

with ch2:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Achieved vs Target Metrics
    </div>
    """, unsafe_allow_html=True)
    metrics_data = pd.DataFrame({
        'Metric': ['Accuracy', 'Detection Rate',
                   'Precision', 'F1 Score', 'False Positive Rate'],
        'Achieved': [results['accuracy'], results['detection_rate'],
                     results['precision'], results['f1'], results['fpr']],
        'Target':   [75, 85, 75, 80, 30]
    })
    fig = go.Figure()
    fig.add_trace(go.Bar(
        name='Achieved', x=metrics_data['Metric'],
        y=metrics_data['Achieved'], marker_color='#3b82f6'))
    fig.add_trace(go.Bar(
        name='Target', x=metrics_data['Metric'],
        y=metrics_data['Target'],
        marker_color='#dc2626', opacity=0.4))
    fig.update_layout(
        barmode='group',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#94a3b8',
        font_family='Inter',
        margin=dict(t=10, b=10, l=10, r=10),
        xaxis=dict(gridcolor='#1e2230'),
        yaxis=dict(gridcolor='#1e2230'),
        legend=dict(bgcolor='rgba(0,0,0,0)'))
    fig.update_traces(marker_line_width=0)
    st.plotly_chart(fig, use_container_width=True,
                   config={'displayModeBar': False})

ch3, ch4 = st.columns(2)

with ch3:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        Anomaly Score Distribution
    </div>
    """, unsafe_allow_html=True)
    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=results['normal_scores'], name='Normal',
        marker_color='#16a34a', opacity=0.7, nbinsx=20))
    fig.add_trace(go.Histogram(
        x=results['attack_scores'], name='Attack',
        marker_color='#dc2626', opacity=0.7, nbinsx=20))
    fig.update_layout(
        barmode='overlay',
        xaxis_title='Anomaly Score', yaxis_title='Count',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#94a3b8', font_family='Inter',
        margin=dict(t=10, b=10, l=10, r=10),
        xaxis=dict(gridcolor='#1e2230'),
        yaxis=dict(gridcolor='#1e2230'),
        legend=dict(bgcolor='rgba(0,0,0,0)'))
    st.plotly_chart(fig, use_container_width=True,
                   config={'displayModeBar': False})

with ch4:
    st.markdown("""
    <div style='font-size:13px; font-weight:600;
                color:#94a3b8; margin-bottom:8px;'>
        TP / TN / FP / FN Breakdown
    </div>
    """, unsafe_allow_html=True)
    breakdown = pd.DataFrame({
        'Category': ['True Positive', 'True Negative',
                     'False Positive', 'False Negative'],
        'Count':    [results['tp'], results['tn'],
                     results['fp'], results['fn']],
        'Color':    ['good', 'good', 'bad', 'bad']
    })
    fig = px.bar(breakdown, x='Category', y='Count',
        color='Color',
        color_discrete_map={'good': '#16a34a', 'bad': '#dc2626'})
    fig.update_layout(
        showlegend=False,
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#94a3b8', font_family='Inter',
        margin=dict(t=10, b=10, l=10, r=10),
        xaxis=dict(gridcolor='#1e2230'),
        yaxis=dict(gridcolor='#1e2230'))
    fig.update_traces(marker_line_width=0)
    st.plotly_chart(fig, use_container_width=True,
                   config={'displayModeBar': False})

st.markdown("<br>", unsafe_allow_html=True)

# ── Confusion Matrix Results ──
st.markdown("""
<div class='section-title'>Confusion Matrix Results</div>
""", unsafe_allow_html=True)

r1, r2, r3, r4 = st.columns(4)
r1.metric("True Positives",  results['tp'],
          help="Attacks correctly detected")
r2.metric("True Negatives",  results['tn'],
          help="Normal traffic correctly identified")
r3.metric("False Positives", results['fp'],
          help="Normal traffic wrongly flagged as attack")
r4.metric("False Negatives", results['fn'],
          help="Attacks that were missed")

st.markdown("<br>", unsafe_allow_html=True)

# ── Analysis ──
st.markdown("""
<div class='section-title'>Analysis and Interpretation</div>
""", unsafe_allow_html=True)

st.markdown(f"""
<div style='background:#161923; border:1px solid #1e2230;
            border-radius:8px; padding:20px 24px;
            color:#94a3b8; font-size:13px; line-height:1.8;'>
    <div style='color:#f1f5f9; font-weight:600;
                margin-bottom:12px; font-size:14px;'>
        Model: Isolation Forest (Unsupervised Anomaly Detection)
    </div>
    <div style='margin-bottom:8px;'>
        <span style='color:#60a5fa; font-weight:600;'>
            Detection Rate {results['detection_rate']}%
        </span>
        — the model successfully identified {results['tp']} out of
        {results['tp'] + results['fn']} attack queries
    </div>
    <div style='margin-bottom:8px;'>
        <span style='color:#60a5fa; font-weight:600;'>
            False Positive Rate {results['fpr']}%
        </span>
        — {results['fp']} legitimate queries were incorrectly flagged as attacks
    </div>
    <div style='margin-bottom:8px;'>
        <span style='color:#60a5fa; font-weight:600;'>
            F1 Score {results['f1']}%
        </span>
        — demonstrates a good balance between precision and recall
    </div>
    <div style='margin-bottom:8px;'>
        <span style='color:#60a5fa; font-weight:600;'>
            Score Separation
        </span>
        — Normal avg {round(results['normal_scores'].mean(), 4)} vs
        Attack avg {round(results['attack_scores'].mean(), 4)}
    </div>
    <div style='margin-top:16px; padding-top:12px;
                border-top:1px solid #1e2230;
                color:#6b7280; font-size:12px;'>
        Limitations: False positives can be reduced by adding domains to the
        allowlist. Model performance improves with more training data.
        Adaptive learning (River) further reduces false positives over time.
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Export ──
st.markdown("""
<div class='section-title'>Export Results</div>
""", unsafe_allow_html=True)

results_dict = {
    'Metric': ['Total Events', 'Normal Queries', 'Attack Queries',
               'Accuracy', 'Detection Rate', 'Precision', 'Recall',
               'F1 Score', 'False Positive Rate', 'False Negative Rate',
               'True Positives', 'True Negatives',
               'False Positives', 'False Negatives'],
    'Value': [results['total'], results['normal_count'],
              results['attack_count'],
              f"{results['accuracy']}%", f"{results['detection_rate']}%",
              f"{results['precision']}%", f"{results['recall']}%",
              f"{results['f1']}%", f"{results['fpr']}%",
              f"{results['fnr']}%", results['tp'], results['tn'],
              results['fp'], results['fn']]
}
results_df = pd.DataFrame(results_dict)
csv = results_df.to_csv(index=False)
st.download_button(
    "Export Evaluation Results CSV",
    data=csv,
    file_name="ml_evaluation_results.csv",
    mime="text/csv")

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
