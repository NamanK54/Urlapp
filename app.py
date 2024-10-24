from flask import Flask, request, redirect, render_template, jsonify, session, g
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import random
import string
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.secret_key = 'naman_dev_secret_key_1234567890'
bcrypt = Bcrypt(app)
limiter = Limiter(app)

# Database setup
def init_db():
    conn = sqlite3.connect('urls.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS urls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  long_url TEXT NOT NULL,
                  short_url TEXT NOT NULL UNIQUE,
                  custom_url TEXT UNIQUE,
                  clicks INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL UNIQUE,
                  password TEXT NOT NULL,
                  api_key TEXT UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS clicks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url_id INTEGER,
                  clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  ip_address TEXT,
                  user_agent TEXT)''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('urls.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

def generate_short_url():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(6))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = f"User {username} is already registered."

        if error is None:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            api_key = str(uuid.uuid4())
            db.execute('INSERT INTO users (username, password, api_key) VALUES (?, ?, ?)',
                       (username, hashed_password, api_key))
            db.commit()
            return redirect('/login')

        flash(error)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not bcrypt.check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect('/')

        flash(error)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/shorten', methods=['POST'])
@limiter.limit("5 per minute")
def shorten_url():
    long_url = request.json['url']
    custom_url = request.json.get('custom_url')
    expiration_days = request.json.get('expiration_days')
    
    db = get_db()
    user_id = session.get('user_id')
    
    if custom_url:
        if db.execute('SELECT id FROM urls WHERE custom_url = ?', (custom_url,)).fetchone():
            return jsonify({'error': 'Custom URL already exists'}), 400
        short_url = custom_url
    else:
        short_url = generate_short_url()
    
    expires_at = None
    if expiration_days:
        expires_at = datetime.now() + timedelta(days=int(expiration_days))
    
    db.execute('INSERT INTO urls (user_id, long_url, short_url, custom_url, expires_at) VALUES (?, ?, ?, ?, ?)',
               (user_id, long_url, short_url, custom_url, expires_at))
    db.commit()
    
    return jsonify({'short_url': request.host_url + short_url})

@app.route('/<short_url>')
def redirect_url(short_url):
    db = get_db()
    url = db.execute('SELECT id, long_url, expires_at FROM urls WHERE short_url = ? OR custom_url = ?', (short_url, short_url)).fetchone()
    
    if url:
        if url['expires_at'] and datetime.now() > datetime.fromisoformat(url['expires_at']):
            return "URL has expired", 410
        
        db.execute('UPDATE urls SET clicks = clicks + 1 WHERE id = ?', (url['id'],))
        db.execute('INSERT INTO clicks (url_id, ip_address, user_agent) VALUES (?, ?, ?)',
                   (url['id'], request.remote_addr, request.user_agent.string))
        db.commit()
        return redirect(url['long_url'])
    else:
        return "URL not found", 404

@app.route('/stats/<short_url>')
def get_stats(short_url):
    db = get_db()
    url = db.execute('SELECT id, long_url, clicks, created_at, expires_at FROM urls WHERE short_url = ? OR custom_url = ?', (short_url, short_url)).fetchone()
    
    if url:
        clicks = db.execute('SELECT clicked_at, ip_address, user_agent FROM clicks WHERE url_id = ? ORDER BY clicked_at DESC LIMIT 10', (url['id'],)).fetchall()
        return jsonify({
            'long_url': url['long_url'],
            'total_clicks': url['clicks'],
            'created_at': url['created_at'],
            'expires_at': url['expires_at'],
            'recent_clicks': [dict(c) for c in clicks]
        })
    else:
        return "URL not found", 404

@app.route('/qr/<short_url>')
def generate_qr(short_url):
    url = request.host_url + short_url
    img = qrcode.make(url)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f'<img src="data:image/png;base64,{img_str}">'

@app.route('/api/shorten', methods=['POST'])
@limiter.limit("100 per day")
def api_shorten_url():
    api_