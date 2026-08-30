# 📧 PhishSheild AI Detector

A full‑stack web application built with **Flask** that detects phishing emails using **rule‑based checks, machine learning models, and email header analysis**. It provides both a **web interface** and a **REST API** for flexible integration.

## **🚀 Features**

- **User Authentication**
  - Secure login with Gmail validation
  - OTP verification for added security
  - Session expiry and login attempt limits

- **Phishing Detection**
  - **Rule‑based analysis**: keyword checks, suspicious links, sender validation
  - **Machine learning analysis**: trained model + vectorizer for adaptive detection
  - **Risk scoring**: confidence levels and risk classification (High/Low)

- **Email Header Analysis**
   Parses and displays key headers (From, Return‑Path, Received, etc.).
   Implements SPF, DKIM, and DMARC validation:
   Flags spoofed senders (SPF fail).
   Verifies email integrity (DKIM signature check).
   Enforces domain policies (DMARC pass/fail).
   Tested with fail, pass, and mixed case email samples to validate detection accuracy.
  
- **Blacklist System**
  - Automatically blocks repeat offenders
  - Prevents duplicate analysis
  - Manage blacklist entries via dashboard

- **Dashboard & Reports**
  - View statistics for rule‑based and ML detections
  - Recent email analysis history
  - Export phishing detection reports as PDF

- **REST API**
  - `/api/analyze` endpoint for programmatic access
  - Accepts JSON input (`email_text`, `sender`, `links`, `attachments`)
  - Returns JSON verdicts (`verdict_rule`, `verdict_ml`, `confidence`, `risk_score`)

## **🖥️ User Interface**

- **Upload Page**
  - Two analysis options:
    - Paste email text → Content analysis
    - Upload `.eml` file → Header analysis
- **Results Pages**
  - `result.html`: verdicts, confidence, gauges, risk score
  - `results_headers.html`: header breakdown + suspicious findings
- **Dashboard**
  - Stats, recent emails, blacklist management
- **Reports**
  - Generate PDF summaries of detection activity
 **Lilly AI Q&A**
  - Ask phishing‑related questions and get rule‑based answers
  - 
## **⚙️ Tech Stack**
- **Backend**: Flask, SQLite, Joblib (ML model + vectorizer)  
- **Frontend**: HTML, CSS, Bootstrap, Chart.js  
- **Security**: OTP verification, session expiry, login attempt limits  
- **Reporting**: ReportLab for PDF generation

## Install Dependencies
pip install flask
pip install scikit-learn
pip install joblib
pip install reportlab
pip install pdfkit 
pip install email-validator
pip install dkimpy
# Install dependencies in windows cmd 

# Train the model
python train_model.py
Result should be -1.0 Accuracy the model is trained 

# Run project in windows CMD
python app.py

## Installation
Install Google Chrome or Edge (Chromium‑based browser).

Go to the Chrome Web Store and search for “Talend API Tester”.

Direct link: Talend API Tester Extension (chrome.google.com in Bing)

Click Add to Chrome → Add Extension.

Once installed, you’ll see the Talend API Tester icon in your browser toolbar.

## ⚙️ Using Talend API Tester with Your Project
Open the extension from your browser toolbar.

You’ll see a panel with:

Method dropdown (GET, POST, PUT, DELETE, etc.)

URL field

Tabs for Headers and Body

## Testing API Analyzer
Set Method → POST

Enter URL → http://127.0.0.1:5000/api/analyze

Go to Headers → Add:

Code
Content-Type: application/json
Go to Body → Select application/json and paste:

json
{
  "email_text": "Your account has been locked. Click here urgently.",
  "sender": "support@fakebank.com",
  "links": ["http://fakebank-login.com"],
  "attachments": []
}
Click Send.

Expected Response

{
  "verdict_rule": "Phishing",
  "verdict_ml": "Phishing",
  "confidence": 92.5,
  "risk_score": "High Risk"
}


## Default Admin Login :
Username: admin@gmail.com
Password: AdminPass123!


## Future Scope
Multi‑User Authentication  
Add role‑based access (e.g., admin, analyst, regular user) with different permissions.

Advanced OTP Delivery  
Integrate real email/SMS OTP delivery instead of demo display, using services like Twilio or SendGrid.

Improved Blacklist Management  
Allow bulk import/export of blacklisted senders and automated syncing with external threat feeds.

Enhanced Dashboard  
Add interactive charts (e.g., phishing trends, detection accuracy) with filters and drill‑down analytics.

Machine Learning Expansion  
Train on larger datasets, add deep learning models, and support continuous retraining with new phishing samples.

Email Header Analysis  
Expand header checks with SPF/DKIM/DMARC validation and anomaly detection.

API Integration  
Provide REST/GraphQL endpoints for external systems to submit emails and fetch analysis results.

Deployment & Scaling  
Containerize with Docker, deploy to cloud (AWS/Azure/GCP), and add load balancing for high traffic.

User Notifications  
Add in‑app alerts or email notifications when suspicious activity is detected.






