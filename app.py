import random
import os
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response
from rules import check_phishing
from models import (
    init_db, save_email, get_stats_by_method, get_recent_emails,
    delete_email, email_exists, add_to_blacklist, is_blacklisted,
    get_blacklist, delete_blacklist_entry
)
import joblib
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import timedelta

import email
import dkim
from email import policy
from email.parser import BytesParser


UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


app = Flask(__name__)
app.secret_key = "supersecretkey"

# ------------------ SESSION EXPIRY ------------------
app.permanent_session_lifetime = timedelta(minutes=90)  # expire after 90 minutes

@app.before_request
def make_session_permanent():
    session.permanent = True
    if request.endpoint not in ('login', 'home', 'static'):
        if 'user' not in session and 'pending_user' not in session:
            return render_template("login.html", error="Session expired, please log in again.")
# ----------------------------------------------------

init_db()

# Load ML model + vectorizer
ml_model = joblib.load("phishing_model.pkl")
ml_vectorizer = joblib.load("vectorizer.pkl")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])

def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']

        if not user or not pwd:
            return render_template("login.html", error="Please fill in both email and password.")
        if "@gmail.com" not in user:
            return render_template("login.html", error="Username must be a valid Gmail address.")

        if 'login_attempts' not in session:
            session['login_attempts'] = 0

        if user == "admin@gmail.com" and pwd == "AdminPass123!":
            session['login_attempts'] = 0
            session['pending_user'] = user
            session.permament=True
            otp_code = str(random.randint(100000, 999999))
            session['otp_code'] = otp_code
            session['otp_attempts'] = 0
            print("Demo OTP:", otp_code)
            return redirect(url_for('otp_verify'))
        else:
            session['login_attempts'] += 1
            remaining = 3 - session['login_attempts']
            if remaining <= 0:
                session.pop('login_attempts', None)
                return render_template("login.html", error="Too many failed login attempts. Access blocked.")
            else:
                return render_template("login.html", error=f"Invalid credentials. {remaining} attempt(s) left.")
    return render_template('login.html')


def analyze_email_headers(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        'From': msg['From'],
        'To': msg['To'],
        'Subject': msg['Subject'],
        'Return-Path': msg['Return-Path'],
        'Message-ID': msg['Message-ID'],
        'Received': msg.get_all('Received'),
        'Received-SPF': msg['Received-SPF'],
        'Authentication-Results': msg['Authentication-Results'],
        'DKIM-Signature': msg['DKIM-Signature']
    }

    verdicts = []

    # Basic checks
    if headers['From'] and "@" not in headers['From']:
        verdicts.append("Suspicious sender format")
    if headers['Return-Path'] and headers['From'] and headers['Return-Path'] != headers['From']:
        verdicts.append("Return-Path mismatch with From")
    if headers['Received'] and len(headers['Received']) > 5:
        verdicts.append("Too many hops in Received headers")

    # SPF check
    if headers['Received-SPF']:
        if "fail" in headers['Received-SPF'].lower():
            verdicts.append("SPF validation failed")
        elif "pass" in headers['Received-SPF'].lower():
            verdicts.append("SPF validation passed")

    # DMARC check
    if headers['Authentication-Results']:
        if "dmarc=fail" in headers['Authentication-Results'].lower():
            verdicts.append("DMARC validation failed")
        elif "dmarc=pass" in headers['Authentication-Results'].lower():
            verdicts.append("DMARC validation passed")

    # DKIM check
    if headers['DKIM-Signature']:
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
            if dkim.verify(raw_data):
                verdicts.append("DKIM signature valid")
            else:
                verdicts.append("DKIM signature invalid")
        except Exception as e:
            verdicts.append(f"DKIM check error: {str(e)}")

    return headers, verdicts

@app.route('/otp', methods=['GET','POST'])
def otp_verify():
    if request.method == 'POST':
        otp = request.form['otp']
        session['otp_attempts'] = session.get('otp_attempts', 0) + 1

        if otp == session.get('otp_code'):
            session['user'] = session.pop('pending_user', None)
            session.pop('otp_code', None)
            session.pop('otp_attempts', None)
            return redirect(url_for('upload_form'))
        else:
            new_otp = str(random.randint(100000, 999999))
            session['otp_code'] = new_otp
            print("New OTP generated:", new_otp)

            remaining = 3 - session['otp_attempts']
            if remaining <= 0:
                session.pop('pending_user', None)
                session.pop('otp_code', None)
                session.pop('otp_attempts', None)
                return render_template("otp.html", error="Too many failed OTP attempts. Login blocked.")
            return render_template("otp.html",
                                   error=f"Invalid OTP. A new OTP has been generated. {remaining} attempt(s) left.",
                                   demo_otp=session.get('otp_code'))
    return render_template("otp.html", demo_otp=session.get('otp_code'))

@app.route('/regen_otp')
def regen_otp():
    if 'pending_user' not in session:
        return redirect(url_for('login'))
    otp_code = str(random.randint(100000, 999999))
    session['otp_code'] = otp_code
    session['otp_attempts'] = 0
    print("New OTP:", otp_code)
    return render_template("otp.html", demo_otp=otp_code, message="New OTP generated.")

@app.route('/upload')
def upload_form():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('upload.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    email_text = request.form['email_text']
    sender = request.form['sender']
    links = request.form['links'].split(",") if request.form['links'] else []
    attachments = request.form['attachments'].split(",") if request.form['attachments'] else []

    # 🚫 Check if blacklisted
    if is_blacklisted(sender, email_text):
        return render_template('result.html',
                               verdict_rule="Blacklisted",
                               verdict_ml="Blacklisted",
                               confidence=100,
                               risk_score="Blocked",
                               duplicate_message="This email is blacklisted and blocked.")

    if email_exists(email_text, sender):
        return render_template('result.html',
                               verdict_rule="Already analyzed",
                               verdict_ml="Already analyzed",
                               confidence=0,
                               risk_score="Duplicate Entry",
                               duplicate_message="This email has already been analyzed.")

    verdict_rule = check_phishing(email_text, links, sender, attachments)
    save_email(email_text, sender, verdict_rule, "Rule")

    X = ml_vectorizer.transform([email_text])
    proba = ml_model.predict_proba(X)[0]
    verdict_ml = ml_model.classes_[proba.argmax()]
    confidence = round(proba.max() * 100, 2)

    risk_score = "High Risk" if confidence < 40 or confidence > 70 else "Low Risk"

    save_email(email_text, sender, verdict_ml, "ML")

    # 🚫 If phishing, add to blacklist
    if verdict_rule == "Phishing" or verdict_ml == "Phishing":
        add_to_blacklist(sender, email_text)

    return render_template('result.html',
                           verdict_rule=verdict_rule,
                           verdict_ml=verdict_ml,
                           confidence=confidence,
                           risk_score=risk_score)

@app.route('/analyze_headers', methods=['POST'])
def analyze_headers():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files['email_file']
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    headers, verdicts = analyze_email_headers(file_path)

    return render_template("results_headers.html",
                           headers=headers,
                           verdicts=verdicts)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    stats_rule = get_stats_by_method("Rule")
    stats_ml = get_stats_by_method("ML")
    recent_emails = get_recent_emails()
    return render_template('dashboard.html',
                           stats_rule=stats_rule,
                           stats_ml=stats_ml,
                           recent_emails=recent_emails)

@app.route('/delete/<int:email_id>', methods=['POST'])
def delete_email_route(email_id):
    delete_email(email_id)
    stats_rule = get_stats_by_method("Rule")
    stats_ml = get_stats_by_method("ML")
    recent_emails = get_recent_emails()
    return render_template('dashboard.html',
                           stats_rule=stats_rule,
                           stats_ml=stats_ml,
                           recent_emails=recent_emails,
                           deleted=True)

@app.route('/blacklist')
def view_blacklist():
    if 'user' not in session:
        return redirect(url_for('login'))
    blocked = get_blacklist()
    return render_template('blacklist.html', blocked=blocked)

@app.route('/blacklist/delete/<int:entry_id>', methods=['POST'])
def delete_blacklist(entry_id):
    delete_blacklist_entry(entry_id)
    blocked = get_blacklist()
    return render_template('blacklist.html', blocked=blocked, deleted=True)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

# ------------------ API ENDPOINT ------------------
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    email_text = data.get('email_text', '')
    sender = data.get('sender', '')
    links = data.get('links', [])
    attachments = data.get('attachments', [])

    verdict_rule = check_phishing(email_text, links, sender, attachments)

    X = ml_vectorizer.transform([email_text])
    proba = ml_model.predict_proba(X)[0]
    verdict_ml = ml_model.classes_[proba.argmax()]
    confidence = round(proba.max() * 100, 2)
    risk_score = "High Risk" if confidence < 40 or confidence > 70 else "Low Risk"

    return jsonify({
        "verdict_rule": verdict_rule,
        "verdict_ml": verdict_ml,
        "confidence": confidence,
        "risk_score": risk_score
    })

# ------------------ REPORT ROUTES ------------------
@app.route('/report')
def generate_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    stats_rule = get_stats_by_method("Rule")
    stats_ml = get_stats_by_method("ML")
    recent_emails = get_recent_emails()
    return render_template('report.html',
                           stats_rule=stats_rule,
                           stats_ml=stats_ml,
                           recent_emails=recent_emails)

@app.route('/report/pdf')
def report_pdf():
    if 'user' not in session:
        return redirect(url_for('login'))

    stats_rule = get_stats_by_method("Rule")
    stats_ml = get_stats_by_method("ML")
    recent_emails = get_recent_emails()

    response = make_response()
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=phishing_report.pdf'

    c = canvas.Canvas(response.stream, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, 750, "Phishing Detection Report")

    c.setFont("Helvetica", 12)
    c.drawString(100, 720, f"Rule-based stats: {stats_rule}")
    c.drawString(100, 700, f"ML-based stats: {stats_ml}")

    y = 670
    c.drawString(100, y, "Recent Emails:")
    y -= 20
    for email in recent_emails:
        c.drawString(100, y, f"ID: {email[4]} | Sender: {email[0]} | Verdict: {email[1]} | Method: {email[2]}")
        y -= 20
        if y < 100:
            c.showPage()
            y = 750

    c.showPage()
    c.save()
    return response
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)

