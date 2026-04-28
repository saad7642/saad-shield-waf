from flask import Flask, request, abort
from urllib.parse import unquote
import json
import datetime
import smtplib
import re
import time
import os # Cloud settings ke liye zaroori hai
from email.mime.text import MIMEText

app = Flask(__name__)

# --- 1. CONFIGURATION (Cloud Environment Friendly) ---
# Render par deploy karte waqt ye variables kaam aayenge
EMAIL_SENDER = "ss9235229@gmail.com"
EMAIL_RECEIVER = "ss9235229@gmail.com"
EMAIL_PASSWORD = "cdhkaubfeukslmhq"

attack_history = {}

# --- 2. ALERT SYSTEM ---
def log_and_alert(ip, reason, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {reason} | IP: {ip} | Details: {details}\n"
    
    # Local logging (Render par temporary hoti hai, lekin debugging ke liye achi hai)
    with open("logs.txt", "a") as f:
        f.write(log_entry)
    
    # Professional Email Alert
    msg = MIMEText(f"🚨 REAL-WORLD ATTACK BLOCKED!\n\nReason: {reason}\nIP: {ip}\nTime: {timestamp}\nData: {details}")
    msg['Subject'] = f'🛡️ SHIELD ALERT: {reason} from {ip}'
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
    except Exception as e:
        print(f"Email Error: {e}")

# --- 3. THE SECURITY ENGINE ---
@app.before_request
def security_check():
    client_ip = request.remote_addr
    curr_time = time.time()
    
    # A. Rate Limiting (Production level: 2 requests per second max)
    if client_ip in attack_history and curr_time - attack_history[client_ip] < 0.5:
        return "<h1>429 Too Many Requests</h1><p>Slow down, buddy.</p>", 429

    # B. Master Payload Extraction (URL + Body + Headers)
    url_path = request.path.lower()
    url_full = unquote(request.url).lower()
    body_data = request.get_data().decode('utf-8', errors='ignore').lower() if request.get_data() else ""
    
    header_data = ""
    for header, value in request.headers.items():
        header_data += f"{header}:{value} ".lower()

    master_payload = url_full + body_data + header_data

    # C. HoneyPot Logic
    honeypots = ['/admin', '/.env', '/config', '/wp-admin', '/setup.php']
    if any(hp in url_path for hp in honeypots):
        log_and_alert(client_ip, "HoneyPot Trap", f"Accessed: {url_path}")
        return "<h1>Forbidden</h1><p>Intrusion detected.</p>", 403

    # D. Hardened Attack Patterns
    patterns = {
        "SQL Injection": r"(union|select|drop|'|--|#|concat|sleep|benchmark)",
        "XSS": r"(<script|alert\(|onerror|eval\(|javascript:|<img|<svg)",
        "Command Injection": r"(\||&|;|`|\$\(|whoami|ls -la|net user|cat /etc)",
        "Path Traversal": r"(\.\.\/|\/etc\/passwd|c:\\windows|/etc/shadow)",
        "Hacking Tool": r"(sqlmap|nikto|nmap|dirbuster|gobuster|acunetix)"
    }

    for name, pattern in patterns.items():
        if re.search(pattern, master_payload):
            attack_history[client_ip] = curr_time
            log_and_alert(client_ip, name, f"Payload: {master_payload}")
            return f"<h1>Security Violation</h1><p>{name} has been blocked and reported.</p>", 400

# --- 4. ROUTES ---
@app.route('/', methods=['GET', 'POST'])
def home():
    return """
    <h1>Military Grade Shield V6.0 - LIVE</h1>
    <p>Status: <span style='color: green;'>ACTIVE</span></p>
    <p>Monitoring all traffic for SQLi, XSS, and Malicious Bots.</p>
    """

# --- 5. PRODUCTION SERVER SETTINGS ---
if __name__ == '__main__':
    # 'os.environ.get' Render ya kisi bhi cloud provider ki port auto-pick kar lega
    port = int(os.environ.get("PORT", 8080))
    print(f"[*] Shield deploying on port {port}...")
    # Production mein '0.0.0.0' hona zaroori hai taake bahar se traffic aa sake
    app.run(host='0.0.0.0', port=port)