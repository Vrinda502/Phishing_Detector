import re

def check_phishing(email_text, email_links, sender, attachments):
    score = 0
    
    keywords = ["urgent", "verify", "password", "account suspended"]
    if any(word in email_text.lower() for word in keywords):
        score += 2
    
    for link in email_links:
        if not re.match(r"https?://[a-zA-Z0-9.-]+", link.strip()):
            score += 3
    
    if not sender.endswith("@trusted.com"):
        score += 2
    
    for att in attachments:
        if att.strip().endswith((".exe", ".scr", ".js")):
            score += 5
    
    if "<form" in email_text.lower():
        score += 3
    
    if "base64" in email_text.lower():
        score += 4
    
    return "Phishing" if score >= 7 else "Safe"
