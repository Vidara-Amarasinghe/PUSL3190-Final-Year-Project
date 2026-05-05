#!/bin/bash
clear
echo "=================================================="
echo "  🛡️  Adaptive DNS Anomaly Detection System"
echo "=================================================="
echo ""
# ── Step 1: Cleanup ──
echo "[1/5] Cleaning up previous sessions..."
sudo pkill -f detector.py  2>/dev/null
sudo pkill -f streamlit    2>/dev/null
sleep 2
echo "      ✅ Done"
# ── Step 2: Fix permissions ──
echo ""
echo "[2/5] Fixing permissions..."
sudo chown student:student \
    /home/student/dns-anomaly/alerts.log 2>/dev/null
sudo chown student:student \
    /home/student/dns-anomaly/dns_anomaly.db 2>/dev/null
echo "      ✅ Done"
# ── Step 3: Start Dashboard ──
echo ""
echo "[3/5] Starting dashboard..."
streamlit run /home/student/dns-anomaly/app.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --logger.level error \
    2>/dev/null &
sleep 4
echo "      ✅ Dashboard running!"
# ── Step 4: Start Detector ──
echo ""
echo "[4/5] Starting detection engine..."
sudo python3 /home/student/dns-anomaly/detector.py \
    > /dev/null 2>&1 &
sleep 3
echo "      ✅ Detector is LIVE!"
# ── Step 5: Show Access Info ──
echo ""
echo "[5/5] System ready!"
echo ""
echo "=================================================="
echo "  🌐 Open your browser:"
echo ""
echo "  http://192.168.56.10:8501"
echo ""
echo "  Pages available:"
echo "  🛡️  Dashboard      — Live DNS monitoring"
echo "  🚨  Attack Mgmt   — Review & mitigate threats"
echo "  📂  Log Analysis  — Upload logs for analysis"
echo "=================================================="
echo ""
read -p "  Press ENTER when browser is open to start queries..."
# ── Run Mixed Queries ──
clear
echo "=================================================="
echo "  🔄 RUNNING MIXED DNS QUERIES"
echo "  Legitimate + Attack queries combined"
echo "  Watch the dashboard detect attacks in real time!"
echo "=================================================="
echo ""
bash /home/student/dns-anomaly/mixed_queries.sh
echo ""
echo "=================================================="
echo "  ✅ Demo Complete!"
echo ""
echo "   Dashboard : http://192.168.56.10:8501"
echo "   Alerts    : ~/dns-anomaly/alerts.log"
echo "  Database  : ~/dns-anomaly/dns_anomaly.db"
echo "=================================================="
