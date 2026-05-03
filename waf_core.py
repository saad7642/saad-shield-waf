import os
import re
import urllib.parse
import threading
import requests
import sqlite3
import bcrypt
from datetime import datetime
from flask import Flask, request, abort, render_template_string, redirect, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "saad-shield-secret-2026")

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('waf_logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        attack_type TEXT,
        payload TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY,
        password_hash TEXT
    )''')
    existing = c.execute("SELECT * FROM admin").fetchone()
    if not existing:
        default_pass = os.environ.get("DASHBOARD_PASSWORD", "saadshield123")
        hashed = bcrypt.hashpw(default_pass.encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO admin (id, password_hash) VALUES (1, ?)", (hashed,))
    conn.commit()
    conn.close()

def verify_password(password):
    conn = sqlite3.connect('waf_logs.db')
    c = conn.cursor()
    row = c.execute("SELECT password_hash FROM admin WHERE id=1").fetchone()
    conn.close()
    if row:
        return bcrypt.checkpw(password.encode(), row[0].encode())
    return False

def change_password(new_password):
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    conn = sqlite3.connect('waf_logs.db')
    c = conn.cursor()
    c.execute("UPDATE admin SET password_hash=? WHERE id=1", (hashed,))
    conn.commit()
    conn.close()

def log_attack(ip, attack_type, payload):
    conn = sqlite3.connect('waf_logs.db')
    c = conn.cursor()
    c.execute("INSERT INTO attacks (timestamp, ip, attack_type, payload) VALUES (?, ?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, attack_type, payload[:200]))
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect('waf_logs.db')
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
    recent = c.execute("SELECT timestamp, ip, attack_type, payload FROM attacks ORDER BY id DESC LIMIT 50").fetchall()
    by_type = c.execute("SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type ORDER BY COUNT(*) DESC").fetchall()
    by_ip = c.execute("SELECT ip, COUNT(*) FROM attacks GROUP BY ip ORDER BY COUNT(*) DESC LIMIT 10").fetchall()
    conn.close()
    return total, recent, by_type, by_ip

# --- SECURITY RULES ---
SECURITY_RULES = [
    (r"<script.*?>", "XSS - Script Tag"),
    (r"alert\(", "XSS - Alert"),
    (r"onerror=", "XSS - Event Handler"),
    (r"onload=", "XSS - Event Handler"),
    (r"union\s+select", "SQL Injection - Union"),
    (r"insert\s+into", "SQL Injection - Insert"),
    (r"drop\s+table", "SQL Injection - Drop"),
    (r"'.*?or.*?1\s*=\s*1", "SQL Injection - Boolean"),
    (r"'.*?--", "SQL Injection - Comment"),
    (r"\d+\s*=\s*\d+", "SQL Injection - Tautology"),
    (r"\.\./\.\./", "Path Traversal"),
    (r"/etc/passwd", "Path Traversal - Passwd"),
    (r";\s*cat\s+", "Command Injection"),
    (r";\s*whoami", "Command Injection"),
    (r"\bwhoami\b", "Command Injection - Whoami"),
    (r"\{\s*\"\$[a-z]+\"", "NoSQL Injection"),
    (r"javascript\s*:", "XSS - JS Protocol"),
    (r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t", "XSS - Spaced JS"),
    (r"&#[\dx]+;", "XSS - Entity Encoding"),
    (r"%26%23", "XSS - Double URL Encode"),
    (r"<\s*img[^>]+src\s*=", "XSS - IMG Src"),
    (r"&#\d+", "XSS - Decimal Entity"),
    (r"&\s*#", "XSS - Entity Bypass"),
]

# --- TEMPLATES ---
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Saad-Shield | Security Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: radial-gradient(ellipse at top, #0d1f3c 0%, #0d1117 70%); color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { background: #161b22; padding: 45px 40px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px #30363d; text-align: center; width: 440px; }
        .shield-icon { font-size: 52px; margin-bottom: 10px; filter: drop-shadow(0 0 20px #58a6ff88); }
        h1 { color: #58a6ff; font-size: 30px; font-weight: 700; margin-bottom: 8px; }
        .status-badge { background: rgba(35,134,54,0.15); color: #3fb950; padding: 6px 16px; border-radius: 20px; font-size: 13px; display: inline-flex; align-items: center; gap: 6px; border: 1px solid #238636; margin-bottom: 20px; }
        .dot { width: 7px; height: 7px; background: #3fb950; border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        .desc { color: #8b949e; font-size: 14px; line-height: 1.6; margin-bottom: 28px; }
        .dash-btn { display: inline-flex; align-items: center; gap: 8px; background: linear-gradient(135deg, #1f6feb, #388bfd); color: white; padding: 13px 30px; border-radius: 10px; text-decoration: none; font-size: 15px; font-weight: 600; transition: all 0.2s; box-shadow: 0 4px 15px rgba(56,139,253,0.3); width: 100%; justify-content: center; }
        .dash-btn:hover { background: linear-gradient(135deg, #388bfd, #58a6ff); transform: translateY(-1px); box-shadow: 0 6px 20px rgba(56,139,253,0.4); }
        .divider { border: none; border-top: 1px solid #30363d; margin: 25px 0; }
        .footer { font-size: 12px; color: #484f58; }
        .footer b { color: #58a6ff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-icon">🛡️</div>
        <h1>Saad-Shield</h1>
        <div class="status-badge">
            <div class="dot"></div>
            System Live & Protected
        </div>
        <p class="desc">WAF is actively monitoring all traffic.<br>Security rules are being enforced in real-time.</p>
        <a href="/dashboard" class="dash-btn">📊 View Dashboard</a>
        <hr class="divider">
        <div class="footer">
            Developed by <b>Muhammad Saad</b><br>
            SQA & Cyber Security Specialist
        </div>
    </div>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Saad-Shield | Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: radial-gradient(ellipse at top, #0d1f3c 0%, #0d1117 70%); color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { background: #161b22; padding: 45px 40px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px #30363d; text-align: center; width: 400px; }
        .lock-icon { font-size: 48px; margin-bottom: 12px; }
        h2 { color: #58a6ff; font-size: 24px; font-weight: 700; margin-bottom: 6px; }
        .subtitle { color: #484f58; font-size: 13px; margin-bottom: 28px; }
        .input-group { margin-bottom: 16px; text-align: left; }
        label { font-size: 12px; color: #8b949e; display: block; margin-bottom: 6px; font-weight: 500; letter-spacing: 0.5px; text-transform: uppercase; }
        .input-wrap { position: relative; }
        input { width: 100%; padding: 12px 44px 12px 16px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #c9d1d9; font-size: 14px; transition: border-color 0.2s; }
        input:focus { border-color: #58a6ff; outline: none; box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
        .toggle-eye { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #484f58; font-size: 16px; user-select: none; transition: color 0.2s; }
        .toggle-eye:hover { color: #8b949e; }
        .login-btn { width: 100%; padding: 13px; background: linear-gradient(135deg, #1f6feb, #388bfd); border: none; border-radius: 10px; color: white; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 15px rgba(56,139,253,0.3); margin-top: 5px; }
        .login-btn:hover { background: linear-gradient(135deg, #388bfd, #58a6ff); transform: translateY(-1px); }
        .login-btn:active { transform: translateY(0); }
        .error { color: #f85149; font-size: 13px; margin-top: 14px; padding: 10px; background: rgba(248,81,73,0.1); border-radius: 6px; border: 1px solid rgba(248,81,73,0.2); display: none; }
        .back-link { display: block; margin-top: 20px; color: #484f58; font-size: 13px; text-decoration: none; }
        .back-link:hover { color: #8b949e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="lock-icon">🔐</div>
        <h2>Dashboard Login</h2>
        <p class="subtitle">Enter your password to access the security dashboard</p>
        <div class="input-group">
            <label>Password</label>
            <div class="input-wrap">
                <input type="password" id="pwd" placeholder="••••••••••••" onkeypress="if(event.key=='Enter') login()">
                <span class="toggle-eye" onclick="toggleEye('pwd', this)">👁️</span>
            </div>
        </div>
        <button class="login-btn" onclick="login()">🔓 Login to Dashboard</button>
        <div class="error" id="err">❌ Wrong password! Please try again.</div>
        <a href="/" class="back-link">← Back to Home</a>
    </div>
    <script>
        function toggleEye(inputId, icon) {
            const input = document.getElementById(inputId);
            if (input.type === 'password') {
                input.type = 'text';
                icon.innerText = '🙈';
            } else {
                input.type = 'password';
                icon.innerText = '👁️';
            }
        }
        function login() {
            const btn = document.querySelector('.login-btn');
            btn.innerText = 'Logging in...';
            btn.disabled = true;
            fetch('/dashboard/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({password: document.getElementById('pwd').value})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    btn.innerText = '✅ Success! Redirecting...';
                    window.location.href = '/dashboard';
                } else {
                    document.getElementById('err').style.display = 'block';
                    btn.innerText = '🔓 Login to Dashboard';
                    btn.disabled = false;
                }
            });
        }
    </script>
</body>
</html>
"""

CHANGE_PASSWORD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Saad-Shield | Change Password</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: radial-gradient(ellipse at top, #0d1f3c 0%, #0d1117 70%); color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .container { background: #161b22; padding: 45px 40px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px #30363d; text-align: center; width: 400px; }
        .key-icon { font-size: 48px; margin-bottom: 12px; }
        h2 { color: #58a6ff; font-size: 24px; font-weight: 700; margin-bottom: 6px; }
        .subtitle { color: #484f58; font-size: 13px; margin-bottom: 28px; }
        .input-group { margin-bottom: 16px; text-align: left; }
        label { font-size: 12px; color: #8b949e; display: block; margin-bottom: 6px; font-weight: 500; letter-spacing: 0.5px; text-transform: uppercase; }
        .input-wrap { position: relative; }
        input { width: 100%; padding: 12px 44px 12px 16px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; color: #c9d1d9; font-size: 14px; transition: border-color 0.2s; }
        input:focus { border-color: #58a6ff; outline: none; box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
        .toggle-eye { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #484f58; font-size: 16px; user-select: none; transition: color 0.2s; }
        .toggle-eye:hover { color: #8b949e; }
        .update-btn { width: 100%; padding: 13px; background: linear-gradient(135deg, #238636, #2ea043); border: none; border-radius: 10px; color: white; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 15px rgba(46,160,67,0.3); margin-top: 5px; }
        .update-btn:hover { background: linear-gradient(135deg, #2ea043, #3fb950); transform: translateY(-1px); }
        .update-btn:active { transform: translateY(0); }
        .msg { font-size: 13px; margin-top: 14px; padding: 10px; border-radius: 6px; display: none; }
        .msg.error { color: #f85149; background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.2); }
        .msg.success { color: #3fb950; background: rgba(63,185,80,0.1); border: 1px solid rgba(63,185,80,0.2); }
        .back-link { display: block; margin-top: 20px; color: #484f58; font-size: 13px; text-decoration: none; }
        .back-link:hover { color: #8b949e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="key-icon">🔑</div>
        <h2>Change Password</h2>
        <p class="subtitle">Update your dashboard access password</p>
        <div class="input-group">
            <label>Current Password</label>
            <div class="input-wrap">
                <input type="password" id="old_pwd" placeholder="••••••••••••">
                <span class="toggle-eye" onclick="toggleEye('old_pwd', this)">👁️</span>
            </div>
        </div>
        <div class="input-group">
            <label>New Password</label>
            <div class="input-wrap">
                <input type="password" id="new_pwd" placeholder="••••••••••••">
                <span class="toggle-eye" onclick="toggleEye('new_pwd', this)">👁️</span>
            </div>
        </div>
        <div class="input-group">
            <label>Confirm New Password</label>
            <div class="input-wrap">
                <input type="password" id="confirm_pwd" placeholder="••••••••••••">
                <span class="toggle-eye" onclick="toggleEye('confirm_pwd', this)">👁️</span>
            </div>
        </div>
        <button class="update-btn" onclick="changePass()">🔒 Update Password</button>
        <div class="msg" id="msg"></div>
        <a href="/dashboard" class="back-link">← Back to Dashboard</a>
    </div>
    <script>
        function toggleEye(inputId, icon) {
            const input = document.getElementById(inputId);
            if (input.type === 'password') {
                input.type = 'text';
                icon.innerText = '🙈';
            } else {
                input.type = 'password';
                icon.innerText = '👁️';
            }
        }
        function changePass() {
            const old_pwd = document.getElementById('old_pwd').value;
            const new_pwd = document.getElementById('new_pwd').value;
            const confirm_pwd = document.getElementById('confirm_pwd').value;
            const msg = document.getElementById('msg');
            const btn = document.querySelector('.update-btn');
            msg.style.display = 'none';
            if(new_pwd !== confirm_pwd) {
                msg.className = 'msg error';
                msg.innerText = '❌ New passwords do not match!';
                msg.style.display = 'block';
                return;
            }
            if(new_pwd.length < 6) {
                msg.className = 'msg error';
                msg.innerText = '❌ Password must be at least 6 characters!';
                msg.style.display = 'block';
                return;
            }
            btn.innerText = 'Updating...';
            btn.disabled = true;
            fetch('/dashboard/change-password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({old_password: old_pwd, new_password: new_pwd})
            }).then(r => r.json()).then(d => {
                if(d.success) {
                    msg.className = 'msg success';
                    msg.innerText = '✅ Password changed successfully! Logging out...';
                    msg.style.display = 'block';
                    setTimeout(() => window.location.href = '/dashboard/logout', 1500);
                } else {
                    msg.className = 'msg error';
                    msg.innerText = '❌ ' + (d.message || 'Error occurred!');
                    msg.style.display = 'block';
                    btn.innerText = '🔒 Update Password';
                    btn.disabled = false;
                }
            });
        }
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Saad-Shield | Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
        .navbar { background: #161b22; padding: 15px 30px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { color: #58a6ff; font-size: 20px; }
        .nav-links { display: flex; align-items: center; gap: 8px; }
        .live-badge { background: rgba(63,185,80,0.15); color: #3fb950; padding: 5px 12px; border-radius: 20px; font-size: 12px; border: 1px solid #238636; display: flex; align-items: center; gap: 5px; }
        .dot { width: 6px; height: 6px; background: #3fb950; border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        .nav-btn { padding: 7px 14px; border-radius: 8px; font-size: 13px; text-decoration: none; font-weight: 500; transition: all 0.2s; }
        .nav-btn.change-pwd { background: rgba(88,166,255,0.1); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }
        .nav-btn.change-pwd:hover { background: rgba(88,166,255,0.2); }
        .nav-btn.logout { background: rgba(248,81,73,0.1); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
        .nav-btn.logout:hover { background: rgba(248,81,73,0.2); }
        .content { padding: 25px 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 22px; text-align: center; }
        .stat-card .number { font-size: 38px; font-weight: 700; }
        .stat-card .label { font-size: 12px; color: #8b949e; margin-top: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
        .section { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 22px; margin-bottom: 20px; }
        .section h3 { color: #c9d1d9; margin-bottom: 15px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #21262d; color: #8b949e; padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
        td { padding: 10px 12px; border-bottom: 1px solid #21262d; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #21262d55; }
        .badge { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
        .xss { background: rgba(248,81,73,0.15); color: #f85149; }
        .sql { background: rgba(255,166,0,0.15); color: #ffa600; }
        .cmd { background: rgba(88,166,255,0.15); color: #58a6ff; }
        .path { background: rgba(63,185,80,0.15); color: #3fb950; }
        .other { background: rgba(139,148,158,0.15); color: #8b949e; }
        .type-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #21262d; font-size: 13px; }
        .type-row:last-child { border-bottom: none; }
        .count-badge { background: rgba(88,166,255,0.1); color: #58a6ff; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .refresh { font-size: 12px; color: #484f58; text-align: right; margin-bottom: 15px; }
        .empty { color: #484f58; text-align: center; padding: 20px; font-size: 13px; }
    </style>
    <meta http-equiv="refresh" content="30">
</head>
<body>
    <div class="navbar">
        <h1>🛡️ Saad-Shield Dashboard</h1>
        <div class="nav-links">
            <div class="live-badge"><div class="dot"></div> Live</div>
            <a href="/dashboard/change-password" class="nav-btn change-pwd">🔑 Change Password</a>
            <a href="/dashboard/logout" class="nav-btn logout">⏻ Logout</a>
        </div>
    </div>
    <div class="content">
        <div class="refresh">🔄 Auto refresh every 30 seconds</div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number" style="color:#58a6ff;">{{ total }}</div>
                <div class="label">Total Attacks Blocked</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#f85149;">{{ xss_count }}</div>
                <div class="label">XSS Attacks</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#ffa600;">{{ sql_count }}</div>
                <div class="label">SQL Injection</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#3fb950;">{{ other_count }}</div>
                <div class="label">Other Attacks</div>
            </div>
        </div>
        <div class="section">
            <h3>📊 Attack Types Breakdown</h3>
            {% for atype, count in by_type %}
            <div class="type-row">
                <span>{{ atype }}</span>
                <span class="count-badge">{{ count }}</span>
            </div>
            {% endfor %}
            {% if not by_type %}
            <div class="empty">No attacks recorded yet</div>
            {% endif %}
        </div>
        <div class="section">
            <h3>🌐 Top Attacker IPs</h3>
            <table>
                <tr><th>IP Address</th><th>Attack Count</th></tr>
                {% for ip, count in by_ip %}
                <tr><td>{{ ip }}</td><td><span class="count-badge">{{ count }}</span></td></tr>
                {% endfor %}
                {% if not by_ip %}
                <tr><td colspan="2"><div class="empty">No data yet</div></td></tr>
                {% endif %}
            </table>
        </div>
        <div class="section">
            <h3>🔴 Recent Attacks (Last 50)</h3>
            <table>
                <tr><th>Timestamp</th><th>IP</th><th>Type</th><th>Payload</th></tr>
                {% for timestamp, ip, atype, payload in recent %}
                <tr>
                    <td>{{ timestamp }}</td>
                    <td>{{ ip }}</td>
                    <td>
                        <span class="badge {% if 'XSS' in atype %}xss{% elif 'SQL' in atype %}sql{% elif 'Command' in atype %}cmd{% elif 'Path' in atype %}path{% else %}other{% endif %}">
                            {{ atype }}
                        </span>
                    </td>
                    <td style="color:#8b949e;">{{ payload[:80] }}{% if payload|length > 80 %}...{% endif %}</td>
                </tr>
                {% endfor %}
                {% if not recent %}
                <tr><td colspan="4"><div class="empty">No attacks yet</div></td></tr>
                {% endif %}
            </table>
        </div>
    </div>
</body>
</html>
"""

# --- EMAIL TASK ---
def send_mail_task(ip, reason, payload):
    api_key = os.environ.get("RESEND_API_KEY")
    to_email = os.environ.get("GMAIL_USER")
    if not api_key or not to_email:
        print(f"[-] ERROR: RESEND_API_KEY ya GMAIL_USER missing hai")
        return
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "from": "WAF Alert <onboarding@resend.dev>",
                "to": to_email,
                "subject": f"WAF ALERT: {reason}",
                "text": f"Saad Bhai, Attack Blocked!\n\nIP: {ip}\nType: {reason}\nPayload: {payload}"
            },
            timeout=10
        )
        if response.status_code == 200:
            print(f"[+] SUCCESS: Email sent!")
        else:
            print(f"[-] FAILED: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[-] ERROR: {type(e).__name__}: {str(e)}")

# --- SECURITY HEADERS ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# --- WAF MIDDLEWARE ---
@app.before_request
def smart_waf():
    excluded = ['/favicon.ico', '/dashboard', '/dashboard/login',
                '/dashboard/logout', '/dashboard/change-password']
    if any(request.path.startswith(p) for p in excluded):
        return None
    client_ip = request.remote_addr
    to_scan = [
        urllib.parse.unquote(request.url).lower(),
        urllib.parse.unquote(request.get_data(as_text=True)).lower(),
        request.headers.get('User-Agent', '').lower()
    ]
    for content in to_scan:
        for pattern, attack_type in SECURITY_RULES:
            if re.search(pattern, content):
                print(f"[!] THREAT DETECTED: {attack_type}")
                log_attack(client_ip, attack_type, content[:200])
                threading.Thread(
                    target=send_mail_task,
                    args=(client_ip, attack_type, content[:150])
                ).start()
                return abort(403)
    return None

# --- ROUTES ---
@app.route('/')
def home():
    return render_template_string(UI_HTML)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return render_template_string(LOGIN_HTML)
    total, recent, by_type, by_ip = get_stats()
    xss_count = sum(c for t, c in by_type if 'XSS' in t)
    sql_count = sum(c for t, c in by_type if 'SQL' in t)
    other_count = total - xss_count - sql_count
    return render_template_string(DASHBOARD_HTML,
        total=total, recent=recent, by_type=by_type, by_ip=by_ip,
        xss_count=xss_count, sql_count=sql_count, other_count=other_count)

@app.route('/dashboard/login', methods=['POST'])
def dashboard_login():
    data = request.get_json()
    if data and verify_password(data.get('password', '')):
        session['logged_in'] = True
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/dashboard/change-password', methods=['GET', 'POST'])
def dashboard_change_password():
    if not session.get('logged_in'):
        return redirect('/dashboard')
    if request.method == 'GET':
        return render_template_string(CHANGE_PASSWORD_HTML)
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid request'})
    if not verify_password(data.get('old_password', '')):
        return jsonify({'success': False, 'message': 'Current password is wrong!'})
    change_password(data.get('new_password', ''))
    return jsonify({'success': True})

@app.route('/dashboard/logout')
def dashboard_logout():
    session.clear()
    return redirect('/')

# --- MAIN ---
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)