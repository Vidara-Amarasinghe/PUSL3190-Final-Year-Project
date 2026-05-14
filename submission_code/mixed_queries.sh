#!/bin/bash
clear
echo "========================================"
echo "  Mixed DNS Query Simulator"
echo "  Legitimate + Attack queries mixed!"
echo "  Watch dashboard detect attacks in real time!"
echo "========================================"
echo ""
echo "  Sending 60 mixed queries..."
echo "  Watch dashboard classify each one!"
echo ""

for i in {1..60}; do
    echo "  Query $i/60:"
    RAND=$((RANDOM % 10))

    if [ $RAND -lt 4 ]; then
        LEGIT_DOMAINS=(
            "www.mydns.test A"
            "mydns.test MX"
            "mydns.test SOA"
            "mail.mydns.test A"
            "mydns.test NS"
            "ftp.mydns.test A"
            "vpn.mydns.test A"
            "api.mydns.test A"
            "dev.mydns.test A"
            "shop.mydns.test A"
            "smtp.mydns.test A"
            "imap.mydns.test A"
            "webmail.mydns.test A"
            "rdp.mydns.test A"
            "portal.mydns.test A"
            "staging.mydns.test A"
            "db.mydns.test A"
            "mysql.mydns.test A"
            "admin.mydns.test A"
            "monitor.mydns.test A"
            "auth.mydns.test A"
            "login.mydns.test A"
            "blog.mydns.test A"
            "cdn.mydns.test A"
            "mydns.test TXT"
            "docs.mydns.test CNAME"
        )
        RANDOM_LEGIT=${LEGIT_DOMAINS[$RANDOM % ${#LEGIT_DOMAINS[@]}]}
        DOMAIN=$(echo $RANDOM_LEGIT | cut -d' ' -f1)
        TYPE=$(echo $RANDOM_LEGIT | cut -d' ' -f2)
        dig @127.0.0.1 $DOMAIN $TYPE > /dev/null
        echo "      ✅ LEGITIMATE | $DOMAIN ($TYPE)"
    else
        ATTACK_TYPE=$((RANDOM % 4))

        if [ $ATTACK_TYPE -eq 0 ]; then
            DOMAIN=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 12).mydns.test
            dig @127.0.0.1 $DOMAIN A > /dev/null
            echo "      🚨 ATTACK DGA        | $DOMAIN"

        elif [ $ATTACK_TYPE -eq 1 ]; then
            DOMAIN=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 30).mydns.test
            dig @127.0.0.1 $DOMAIN TXT > /dev/null
            echo "      🚨 ATTACK TUNNEL     | $DOMAIN"

        elif [ $ATTACK_TYPE -eq 2 ]; then
            DOMAINS=("evil-c2.net" "malware.xyz" "randomdomain123.com" "fake-update.net" "c2server.xyz" "botnet-cmd.org" "exfil-data.net" "ransom-pay.xyz")
            DOMAIN=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
            dig @127.0.0.1 $DOMAIN A > /dev/null
            echo "      🚨 ATTACK FOREIGN    | $DOMAIN"

        else
            SUB1=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
            SUB2=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
            SUB3=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
            DOMAIN=$SUB1.$SUB2.$SUB3.mydns.test
            dig @127.0.0.1 $DOMAIN A > /dev/null
            echo "      🚨 ATTACK DEEP SUB   | $DOMAIN"
        fi
    fi
    sleep 0.8
done

echo ""
echo "========================================"
echo "  SIMULATION COMPLETE"
echo "========================================"
python3 -c "
import sqlite3
conn = sqlite3.connect('/home/student/dns-anomaly/dns_anomaly.db')
cursor = conn.cursor()
print('')
cursor.execute('SELECT COUNT(*) FROM dns_events')
print(f'  Total events monitored : {cursor.fetchone()[0]}')
cursor.execute('SELECT COUNT(*) FROM alerts')
print(f'  Total alerts generated : {cursor.fetchone()[0]}')
print('')
print('  Alert breakdown:')
cursor.execute('SELECT reason, COUNT(*) FROM alerts GROUP BY reason')
for row in cursor.fetchall():
    print(f'    {row[0]}: {row[1]}')
print('')
print('  Severity breakdown:')
cursor.execute('SELECT severity, COUNT(*) FROM alerts GROUP BY severity')
for row in cursor.fetchall():
    print(f'    {row[0]}: {row[1]}')
conn.close()
"
echo ""
echo "  Check dashboard: http://localhost:8501"
echo "========================================"
