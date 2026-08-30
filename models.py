import sqlite3

DB_NAME = "phishing.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Create table with all required columns
    c.execute('''CREATE TABLE IF NOT EXISTS emails
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender TEXT,
                  content TEXT,
                  verdict TEXT,
                  method TEXT)''')
    # Create blacklist table
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender TEXT,
                  content TEXT)''')
    conn.commit()
    conn.close()

def save_email(content, sender, verdict, method="Rule"):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO emails (sender, content, verdict, method) VALUES (?, ?, ?, ?)",
              (sender, content, verdict, method))
    conn.commit()
    conn.close()

def get_stats_by_method(method):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT verdict, COUNT(*) FROM emails WHERE method=? GROUP BY verdict", (method,))
    stats = dict(c.fetchall())
    conn.close()
    return stats

def get_recent_emails(limit=10):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Include ID so we can delete specific emails
    c.execute("SELECT sender, verdict, method, content, id FROM emails ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def delete_email(email_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM emails WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()

def email_exists(content, sender):
    """Check if an email with the same sender and content already exists."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM emails WHERE sender=? AND content=?", (sender, content))
    count = c.fetchone()[0]
    conn.close()
    return count > 0

# ------------------ BLACKLIST FUNCTIONS ------------------

def add_to_blacklist(sender, content):
    """Add a suspicious email to the blacklist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO blacklist (sender, content) VALUES (?, ?)", (sender, content))
    conn.commit()
    conn.close()

def is_blacklisted(sender, content):
    """Check if an email or sender is already blacklisted."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM blacklist WHERE sender=? OR content=?", (sender, content))
    result = c.fetchone()
    conn.close()
    return result is not None

def get_blacklist(limit=20):
    """Retrieve blacklisted entries."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, sender, content FROM blacklist ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def delete_blacklist_entry(entry_id):
    """Remove a specific entry from the blacklist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
