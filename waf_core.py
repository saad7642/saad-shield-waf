from flask import Flask, request, abort
from urllib.parse import unquote
import json
import datetime
import smtplib
import re
import time
import os  # System se variables uthane ke liye
from email.mime.text import MIMEText

app = Flask(__name__)

# --- 1. CONFIGURATION (RENDER ENVIRONMENT VARIABLES) ---
# Ye values ab seedha Render ki settings se ayengi
EMAIL_SENDER = os.environ.get("MY_EMAIL")
EMAIL_RECEIVER = os.environ.get("MY_EMAIL")
EMAIL_PASSWORD = os.environ.get("MY_GMAIL_PASS")

attack_history = {}

# --- 2. ALERT SYSTEM ---
def log_and_alert(ip, reason, details):
    # Agar Render par variables set nahi hain toh alert nahi jayega
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        print(f"⚠️ Alert skipped: Environment variables not set.")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {reason} | IP: {ip} | Details: {details}\n"
    
    # Cloud logs mein print hoga (Render dashboard par nazar ayega)
    print(log_entry)
    
    # Professional Email Alert
    msg = MIMEText(f"🚨 CLOUD SHIELD ALERT!\n\nReason: {reason}\nIP: {ip}\nTime: {timestamp}\nData: {details}")
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
    
    # Rate Limiting
    if client_ip in attack_history and curr_time - attack_history[client_ip] < 0.5:
        return "<h1>429 Too Many Requests</h1>", 429

    # Payload Extraction
    url_full = unquote(request.url).lower()
    body_data = request.get_data().decode('utf-8', errors='ignore').lower() if request.get_data() else ""
    header_data = "".join([f"{k}:{v} " for k, v in request.headers.items()]).lower()

    master_payload = url_full + body_data + header_data

    # Attack Patterns
    patterns = {
        "SQL Injection": r"(union|select|drop|'|--|#|concat|sleep|benchmark)",
        "XSS": r"(<script|alert\(|onerror|eval\(|javascript:|<img|<svg)",
        "Command Injection": r"(\||&|;|`|\$\(|whoami|ls -la|cat /etc)",
        "Path Traversal": r"(\.\.\/|\/etc\/passwd|c:\\)",
        "Hacking Tool": r"(sqlmap|nikto|nmap|dirbuster|acunetix)"
    }

    for name, pattern in patterns.items():
        if re.search(pattern, master_payload):
            attack_history[client_ip] = curr_time
            log_and_alert(client_ip, name, f"Payload: {master_payload}")
            return f"<h1>Security Violation</h1><p>{name} Blocked.</p>", 400

# --- 4. ROUTES ---
@app.route('/')
def home():
    return "<h1>Shield Status: ACTIVE (Secure Mode)</h1>"

# --- 5. DEPLOYMENT ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)