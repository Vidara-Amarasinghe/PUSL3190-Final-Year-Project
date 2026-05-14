import sqlite3
import time

DB_FILE = "/home/student/dns-anomaly/dns_anomaly.db"

# ✅ Improved connection (WAL + timeout)
def get_connection():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            client_ip   TEXT NOT NULL,
            domain      TEXT NOT NULL,
            query_type  TEXT NOT NULL,
            entropy     REAL,
            depth       INTEGER,
            length      INTEGER,
            query_count INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            client_ip   TEXT NOT NULL,
            domain      TEXT NOT NULL,
            reason      TEXT NOT NULL,
            severity    TEXT NOT NULL,
            extra       TEXT,
            status      TEXT DEFAULT 'Open'
        )
    ''')

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_FILE}")


# ✅ Insert event (with retry)
def insert_event(timestamp, client_ip, domain, query_type,
                 entropy, depth, length, query_count):

    for _ in range(5):  # retry mechanism
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO dns_events 
                (timestamp, client_ip, domain, query_type, 
                 entropy, depth, length, query_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, client_ip, domain, query_type,
                  entropy, depth, length, query_count))

            conn.commit()
            conn.close()
            return

        except sqlite3.OperationalError as e:
            if "locked" in str(e):
                time.sleep(0.2)
            else:
                raise


# ✅ Insert alert (FIXED + retry + commit)
def insert_alert(timestamp, client_ip, domain,
                 reason, severity, extra):

    for _ in range(5):
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO alerts
                (timestamp, client_ip, domain, reason, severity, extra)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, client_ip, domain, reason, severity, extra))

            conn.commit()   # 🔥 IMPORTANT FIX
            conn.close()
            return

        except sqlite3.OperationalError as e:
            if "locked" in str(e):
                time.sleep(0.2)
            else:
                raise


def get_recent_events(limit=100):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM dns_events 
        ORDER BY id DESC LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()
    return rows


def get_recent_alerts(limit=50):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM alerts 
        ORDER BY id DESC LIMIT ?
    ''', (limit,))

    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    init_db()
