import sqlite3
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from ml_model import load_model, predict
import sys
import os

DB_FILE = "/home/student/dns-anomaly/dns_anomaly.db"

print("=" * 60)
print("  DNS Anomaly Detection System — ML Evaluation")
print("  University of Plymouth | BSc Computer Security")
print("=" * 60)

# ── Step 1: Load data from database ──
print("\n[1/6] Loading data from database...")
conn = sqlite3.connect(DB_FILE)

events_df = pd.read_sql_query(
    'SELECT * FROM dns_events', conn)
alerts_df = pd.read_sql_query(
    'SELECT * FROM alerts', conn)
conn.close()

print(f"      Total DNS events : {len(events_df)}")
print(f"      Total alerts     : {len(alerts_df)}")

if len(events_df) < 10:
    print("\n❌ Not enough data to evaluate.")
    print("   Run mixed_queries.sh first to generate data.")
    sys.exit(1)

# ── Step 2: Create ground truth labels ──
print("\n[2/6] Creating ground truth labels...")

# Known legitimate domains
KNOWN_LEGITIMATE = [
    'www.mydns.test', 'mydns.test',
    'mail.mydns.test', 'ns1.mydns.test'
]

# Get domains that triggered alerts
alerted_domains = set(alerts_df['domain'].unique()) \
    if not alerts_df.empty else set()

# Label each event
def label_event(row):
    # Known legitimate → 0 (normal)
    if row['domain'] in KNOWN_LEGITIMATE:
        return 0
    # High entropy → 1 (attack)
    if row['entropy'] >= 3.6:
        return 1
    # Deep subdomain → 1 (attack)
    if row['depth'] >= 4:
        return 1
    # Long domain → 1 (attack)
    if row['length'] >= 40:
        return 1
    # High query rate → 1 (attack)
    if row['query_count'] >= 20:
        return 1
    # In alerted domains → 1 (attack)
    if row['domain'] in alerted_domains:
        return 1
    # Otherwise → 0 (normal)
    return 0

events_df['true_label'] = events_df.apply(
    label_event, axis=1)

normal_count = len(events_df[events_df['true_label'] == 0])
attack_count = len(events_df[events_df['true_label'] == 1])

print(f"      Normal queries   : {normal_count}")
print(f"      Attack queries   : {attack_count}")
print(f"      Attack rate      : "
      f"{round(attack_count/len(events_df)*100, 1)}%")

# ── Step 3: Load ML model ──
print("\n[3/6] Loading ML model...")
os.chdir('/home/student/dns-anomaly')
model, scaler = load_model()

if model is None:
    print("❌ No model found. Train it first:")
    print("   python3 ml_model.py")
    sys.exit(1)

print("      ✅ Model loaded successfully")

# ── Step 4: Run predictions ──
print("\n[4/6] Running predictions on all events...")

predictions = []
scores      = []

for _, row in events_df.iterrows():
    is_anomaly, score = predict(
        model, scaler,
        row['entropy'],
        row['depth'],
        row['length'],
        row['query_count']
    )
    # Apply allowlist — known legitimate domains never flagged
    if row['domain'] in KNOWN_LEGITIMATE:
        is_anomaly = False
    predictions.append(1 if is_anomaly else 0)
    scores.append(score)

events_df['predicted_label'] = predictions
events_df['anomaly_score']   = scores

pred_normal = predictions.count(0)
pred_attack = predictions.count(1)
print(f"      Predicted normal : {pred_normal}")
print(f"      Predicted attack : {pred_attack}")

# ── Step 5: Calculate metrics ──
print("\n[5/6] Calculating performance metrics...")

y_true = events_df['true_label'].values
y_pred = events_df['predicted_label'].values

# Handle edge cases
if len(set(y_true)) < 2:
    print("⚠️  Only one class in data.")
    print("   Run more varied queries first.")
    sys.exit(1)

precision  = precision_score(y_true, y_pred,
                             zero_division=0)
recall     = recall_score(y_true, y_pred,
                          zero_division=0)
f1         = f1_score(y_true, y_pred,
                      zero_division=0)
cm         = confusion_matrix(y_true, y_pred)

# Extract confusion matrix values
tn = cm[0][0]  # True Negative  (normal, predicted normal)
fp = cm[0][1]  # False Positive (normal, predicted attack)
fn = cm[1][0]  # False Negative (attack, predicted normal)
tp = cm[1][1]  # True Positive  (attack, predicted attack)

total      = tn + fp + fn + tp
accuracy   = round((tp + tn) / total * 100, 2)
fpr        = round(fp / (fp + tn) * 100, 2) \
             if (fp + tn) > 0 else 0
fnr        = round(fn / (fn + tp) * 100, 2) \
             if (fn + tp) > 0 else 0
detection  = round(tp / (tp + fn) * 100, 2) \
             if (tp + fn) > 0 else 0

# ── Step 6: Print results ──
print("\n[6/6] Evaluation Complete!")
print()
print("=" * 60)
print("  📊 ML MODEL PERFORMANCE METRICS")
print("=" * 60)
print()
print(f"  Overall Accuracy      : {accuracy}%")
print(f"  Detection Rate        : {detection}%")
print(f"  Precision             : {round(precision*100, 2)}%")
print(f"  Recall                : {round(recall*100, 2)}%")
print(f"  F1 Score              : {round(f1*100, 2)}%")
print(f"  False Positive Rate   : {fpr}%")
print(f"  False Negative Rate   : {fnr}%")
print()
print("=" * 60)
print("  🔢 CONFUSION MATRIX")
print("=" * 60)
print()
print("                    Predicted")
print("                 Normal    Attack")
print(f"  Actual Normal  | {tn:5d}  | {fp:5d}  |")
print(f"  Actual Attack  | {fn:5d}  | {tp:5d}  |")
print()
print("  TP = True Positive  (Attack correctly detected)")
print("  TN = True Negative  (Normal correctly identified)")
print("  FP = False Positive (Normal wrongly flagged)")
print("  FN = False Negative (Attack missed)")
print()
print("=" * 60)
print("  📋 DETAILED CLASSIFICATION REPORT")
print("=" * 60)
print()
print(classification_report(
    y_true, y_pred,
    target_names=['Normal', 'Attack']
))

print("=" * 60)
print("  📈 ANOMALY SCORE ANALYSIS")
print("=" * 60)
print()
normal_scores = events_df[
    events_df['true_label'] == 0]['anomaly_score']
attack_scores = events_df[
    events_df['true_label'] == 1]['anomaly_score']

print(f"  Normal queries avg score  : "
      f"{round(normal_scores.mean(), 4)}")
print(f"  Attack queries avg score  : "
      f"{round(attack_scores.mean(), 4)}")
print(f"  Score separation          : "
      f"{round(abs(normal_scores.mean() - attack_scores.mean()), 4)}")
print()
print("  Note: More negative score = more anomalous")
print("  Good separation = model distinguishes well")
print()
print("=" * 60)
print("  🔍 SAMPLE MISCLASSIFICATIONS")
print("=" * 60)

# Show false positives
fp_df = events_df[
    (events_df['true_label'] == 0) &
    (events_df['predicted_label'] == 1)
].head(5)

if not fp_df.empty:
    print(f"\n  False Positives (Normal flagged as Attack):")
    for _, row in fp_df.iterrows():
        print(f"    Domain: {row['domain'][:40]} | "
              f"Entropy: {row['entropy']} | "
              f"Score: {round(row['anomaly_score'], 4)}")
else:
    print("\n  ✅ No False Positives found!")

# Show false negatives
fn_df = events_df[
    (events_df['true_label'] == 1) &
    (events_df['predicted_label'] == 0)
].head(5)

if not fn_df.empty:
    print(f"\n  False Negatives (Attack missed):")
    for _, row in fn_df.iterrows():
        print(f"    Domain: {row['domain'][:40]} | "
              f"Entropy: {row['entropy']} | "
              f"Score: {round(row['anomaly_score'], 4)}")
else:
    print("\n  ✅ No False Negatives found!")

print()
print("=" * 60)
print("  ✅ Evaluation Complete!")
print("=" * 60)

# ── Save results ──
results = {
    'Total Events':        total,
    'Normal Queries':      normal_count,
    'Attack Queries':      attack_count,
    'Accuracy':            f"{accuracy}%",
    'Detection Rate':      f"{detection}%",
    'Precision':           f"{round(precision*100, 2)}%",
    'Recall':              f"{round(recall*100, 2)}%",
    'F1 Score':            f"{round(f1*100, 2)}%",
    'False Positive Rate': f"{fpr}%",
    'False Negative Rate': f"{fnr}%",
    'True Positives':      tp,
    'True Negatives':      tn,
    'False Positives':     fp,
    'False Negatives':     fn
}

results_df = pd.DataFrame(
    results.items(),
    columns=['Metric', 'Value'])
results_df.to_csv(
    '/home/student/dns-anomaly/evaluation_results.csv',
    index=False)
print(f"\n  📥 Results saved to evaluation_results.csv")
