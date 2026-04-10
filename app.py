
from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devkey")


# ---------------- DB ----------------
def get_db_connection():
    conn = sqlite3.connect('database/db.sqlite3')
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- INIT DB ----------------
def init_db():
    conn = get_db_connection()

    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        type TEXT,
        severity TEXT,
        description TEXT,
        status TEXT,
        reported_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        username TEXT,
        incident_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        severity TEXT,
        source TEXT,
        description TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        username TEXT,
        source_ip TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    admin_pass = generate_password_hash('admin123')
    user_pass = generate_password_hash('user123')

    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin',?,'admin')", (admin_pass,))
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'user',?,'user')", (user_pass,))
    

    conn.commit()
    conn.close()


init_db()


# ---------------- RULE ENGINE ----------------
def check_rules():
    conn = get_db_connection()

    failed = conn.execute('''
        SELECT COUNT(*) as count FROM events
        WHERE event_type='login_failed'
        AND timestamp >= datetime('now','-1 minute')
    ''').fetchone()

    if failed['count'] >= 5:

        existing = conn.execute('''
            SELECT * FROM alerts
            WHERE type='Brute Force Attempt'
            AND timestamp >= datetime('now','-1 minute')
        ''').fetchone()

        if not existing:

            conn.execute('''
                INSERT INTO alerts (type, severity, source, description)
                VALUES (?,?,?,?)
            ''', (
                "Brute Force Attempt",
                "High",
                "Auth System",
                "Multiple failed login attempts detected"
            ))

            incident_cursor = conn.execute('''
                INSERT INTO incidents
                (title, type, severity, description, status, reported_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                "Brute Force Attack Detected",
                "Authentication Attack",
                "High",
                "Auto-generated from alert",
                "Open",
                "system"
            ))

            incident_id = incident_cursor.lastrowid

            conn.execute('''
                INSERT INTO logs (action, username, incident_id)
                VALUES (?, ?, ?)
            ''', (
                "Auto Incident Created from Alert",
                "system",
                incident_id
            ))

    conn.commit()
    conn.close()


# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username=?',
            (request.form['username'],)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], request.form['password']):
            session['user'] = user['username']
            session['role'] = user['role']
            return redirect('/')
        return "Invalid credentials"

    return render_template('login.html')


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ---------------- HOME ----------------
@app.route('/')
def home():
    if 'user' not in session:
        return redirect('/login')

    conn = get_db_connection()

    if session['role'] == 'admin':
        incidents_rows = conn.execute('SELECT * FROM incidents').fetchall()
        logs_rows = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10').fetchall()
    else:
        incidents_rows = conn.execute(
            'SELECT * FROM incidents WHERE reported_by=?',
            (session['user'],)
        ).fetchall()
        logs_rows = conn.execute(
            'SELECT * FROM logs WHERE username=? ORDER BY timestamp DESC LIMIT 10',
            (session['user'],)
        ).fetchall()

    alerts_rows = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10').fetchall()
    events_rows = conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT 10').fetchall()

    # ---------------- THREAT SCORE ----------------
    severity_map = {"Low":1, "Medium":2, "High":3, "Critical":4}

    incidents = [dict(r) for r in incidents_rows]

    # SORT BY PRIORITY
    incidents = sorted(
        incidents,
        key=lambda x: severity_map.get(x['severity'],0),
        reverse=True
    )

    total_threat_score = sum(severity_map.get(i['severity'],0) for i in incidents)

    logs = [dict(l) for l in logs_rows]
    alerts = [dict(a) for a in alerts_rows]
    events = [dict(e) for e in events_rows]

    # MTTR
    times = []
    for i in incidents:
        if i['resolved_at']:
            row = conn.execute(
                "SELECT (julianday(resolved_at)-julianday(created_at))*86400 as diff FROM incidents WHERE id=?",
                (i['id'],)
            ).fetchone()
            if row['diff']:
                times.append(row['diff'])

    mttr = int(sum(times)/len(times)) if times else 0

    conn.close()

    return render_template('index.html',
        incidents=incidents,
        all_incidents=incidents,
        logs=logs,
        alerts=alerts,
        events=events,
        mttr=mttr,
        total_threat_score=total_threat_score,
        user=session['user'],
        role=session['role']
    )


# ---------------- REPORT ----------------
@app.route('/report', methods=['POST'])
def report():
    if 'user' not in session:
        return redirect('/login')

    conn = get_db_connection()

    cur = conn.execute('''
        INSERT INTO incidents (title,type,severity,description,status,reported_by)
        VALUES (?,?,?,?,?,?)
    ''', (
        request.form['title'],
        request.form['type'],
        request.form['severity'],
        request.form['description'],
        'Open',
        session['user']
    ))

    iid = cur.lastrowid

    conn.execute('INSERT INTO logs (action,username,incident_id) VALUES (?,?,?)',
                 ('Created Incident', session['user'], iid))

    conn.commit()
    conn.close()

    return redirect('/')


# ---------------- STATUS ----------------
@app.route('/update_status/<int:id>/<new_status>')
def update_status(id, new_status):
    if session.get('role') != 'admin':
        return "Unauthorized"

    conn = get_db_connection()

    if new_status == "Resolved":
        conn.execute(
            'UPDATE incidents SET status=?, resolved_at=CURRENT_TIMESTAMP WHERE id=?',
            (new_status, id)
        )
    else:
        conn.execute(
            'UPDATE incidents SET status=? WHERE id=?',
            (new_status, id)
        )

    conn.execute('INSERT INTO logs VALUES (NULL,?,?,?,CURRENT_TIMESTAMP)',
                 (f'Status -> {new_status}', session['user'], id))

    conn.commit()
    conn.close()

    return redirect('/')


# ---------------- EVENTS ----------------
@app.route('/generate_event')
def generate_event():
    conn = get_db_connection()

    event = random.choice(["login_success","login_failed","file_access"])

    conn.execute('INSERT INTO events (event_type,username,source_ip) VALUES (?,?,?)',
                 (event, session['user'], f"192.168.1.{random.randint(1,255)}"))

    conn.commit()
    conn.close()

    check_rules()

    return redirect('/')


# ---------------- ALERT ----------------
@app.route('/generate_alert')
def generate_alert():
    conn = get_db_connection()

    conn.execute('INSERT INTO alerts (type,severity,source,description) VALUES (?,?,?,?)',
                 ("Manual Alert","Medium","System","Manual trigger"))

    conn.commit()
    conn.close()

    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)