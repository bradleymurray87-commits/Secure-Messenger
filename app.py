from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, request, render_template
from cryptography.fernet import Fernet
import sqlite3

app = Flask(__name__)
app.secret_key = 'bR@dL3yS3cur3M3ssag3App2025!'
key = Fernet.generate_key()
cipher = Fernet(key)

# Initialize database
conn = sqlite3.connect('messages.db', check_same_thread=False)
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT, content TEXT)')
c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
conn.commit()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/send', methods=['POST'])
def send():
    sender = session['username']
    receiver = request.form['receiver']
    message = request.form['message']
    encrypted = cipher.encrypt(message.encode())
    c.execute('INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)', (sender, receiver, encrypted))
    conn.commit()
    return "✅ Message sent!"

@app.route('/receive', methods=['GET'])
def receive():
    receiver = session['username']
    c.execute('SELECT sender, content FROM messages WHERE receiver=?', (receiver,))
    rows = c.fetchall()
    decrypted_messages = [(row[0], cipher.decrypt(row[1]).decode()) for row in rows]
    return {'messages': decrypted_messages}
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        c.execute('SELECT password FROM users WHERE username=?', (username,))
        row = c.fetchone()
        if row and check_password_hash(row[0], password):
            session['username'] = username
            return redirect(url_for('index'))
        return "❌ Invalid credentials"
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        return "❌ Username already exists"

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)