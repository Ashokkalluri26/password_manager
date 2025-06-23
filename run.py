import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Hardcoded master password (for demo purposes)
MASTER_PASSWORD = 'admin123'

# Encryption key (should be stored securely in production)
if not os.path.exists('secret.key'):
    with open('secret.key', 'wb') as key_file:
        key_file.write(Fernet.generate_key())
with open('secret.key', 'rb') as key_file:
    key = key_file.read()
cipher_suite = Fernet(key)

# Database setup
DB_NAME = 'vault.db'
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        site TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password BLOB NOT NULL
                    )''')
        conn.commit()
init_db()

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        if request.form['password'] == MASTER_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Incorrect master password!', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/index')
def index():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('SELECT id, site, username, password FROM credentials')
        creds = [
            {
                'id': row[0],
                'site': row[1],
                'username': row[2],
                'password': cipher_suite.decrypt(row[3]).decode()
            } for row in c.fetchall()
        ]
    return render_template('index.html', creds=creds)

@app.route('/add', methods=['POST'])
def add():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    site = request.form['site']
    username = request.form['username']
    password = request.form['password']
    enc_password = cipher_suite.encrypt(password.encode())
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO credentials (site, username, password) VALUES (?, ?, ?)', (site, username, enc_password))
        conn.commit()
    return redirect(url_for('index'))

@app.route('/delete/<int:cred_id>')
def delete(cred_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM credentials WHERE id=?', (cred_id,))
        conn.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True) 