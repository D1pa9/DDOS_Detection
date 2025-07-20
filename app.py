from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

import os
import time
import base64
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

traffic_data = []  # Stores traffic data (IP and timestamp)
ddos_ips = {}  # Dictionary to store IPs and their DDoS attempt counts

# ✅ Gmail API Configuration
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CREDENTIALS_FILE = "C:/Users/asus/Desktop/ddos_project/client_secret.json"  # Ensure correct filename!
TOKEN_FILE = "C:/Users/asus/Desktop/ddos_project/token.json"
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "alert_recipient@gmail.com")

# ✅ Function to Authenticate Gmail API
def authenticate_gmail():
    creds = None

    # Check if token file exists
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # If credentials are missing or expired
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  # Refresh token
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=8080, access_type="offline", prompt="consent")

        # Save new credentials
        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

    # ✅ Create Gmail API Service
    return build("gmail", "v1", credentials=creds)

# ✅ Function to Send Email Alerts
def send_email_alert(ip):
    """Sends an email alert when a DDoS attack is detected."""
    service = authenticate_gmail()

    message_text = f"🚨 A DDoS attack has been detected from IP: {ip}. Please investigate immediately."
    message = MIMEText(message_text)
    message["to"] = ALERT_EMAIL
    message["from"] = "dipasharma817@gmail.com"  # 🔹 Replace with your email
    message["subject"] = "🚨 DDoS Attack Detected!"
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        print(f"✅ Email alert sent successfully to {ALERT_EMAIL}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# ✅ Function to Detect DDoS Attacks
def detect_ddos(ip):
    current_time = time.time()
    recent_traffic = [data for data in traffic_data if current_time - data['timestamp'] < 30 and data['ip'] == ip]

    # If more than 2 requests from the same IP within 30 sec
    if len(recent_traffic) > 2:
        ddos_ips[ip] = ddos_ips.get(ip, 0) + 1
        send_email_alert(ip)
        return True
    return False

# ✅ Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    username = request.form['username']
    password = request.form['password']
    if username == "admin" and password == "password123":
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/traffic', methods=['POST'])
def log_traffic():
    ip = request.json.get('ip')
    timestamp = time.time()

    # Log traffic
    traffic_data.append({'ip': ip, 'timestamp': timestamp})

    # Check if DDoS detected
    is_ddos = detect_ddos(ip)

    return jsonify({
        'is_ddos': is_ddos,
        'message': "DDoS Attack Detected!" if is_ddos else "Normal Traffic",
        'ddos_count': len(ddos_ips),
        'ddos_ips': list(ddos_ips.keys())
    })

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# ✅ Run Flask App
if __name__ == '__main__':
    app.run(debug=True, port=8000)
