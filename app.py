# quaverse_server.py
"""
QUAVERSE Local LAN Chat Server (single-file)
- Real-time chat using Flask-SocketIO (eventlet)
- Admin (Egmenqua) can view plaintext passwords & manage co-admins
- Co-admins have admin-like powers but cannot affect Egmenqua
- IMPORTANT: passwords are stored plaintext by design per request (NOT SAFE FOR PRODUCTION)
"""

import os
import sqlite3
import secrets
from datetime import datetime
from flask import (Flask, render_template_string, request, redirect, url_for,
                   session, flash, jsonify, send_from_directory)
from flask_session import Session
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.path.join(BASE_DIR, "quaverse_lan.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(24)

# Flask-Session (filesystem) — allows many simultaneous sessions
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(BASE_DIR, 'flask_sessions')
app.config['SESSION_PERMANENT'] = False
Session(app)

# SocketIO (use eventlet if available)
# Install eventlet: pip install eventlet
socketio = SocketIO(app, manage_session=False)  # we manage Flask sessions separately

# ---------- Database helpers ----------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # users: store plaintext intentionally (per request)
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_plain TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        role TEXT DEFAULT 'viewer',  -- 'admin', 'coadmin', 'viewer'
        created_at TEXT
    )
    ''')
    # friends (directed: user_id added friend_id)
    c.execute('''
    CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        created_at TEXT
    )
    ''')
    # messages: 1:1 messages stored
    c.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT
    )
    ''')
    conn.commit()

    # Ensure main admin exists: Egmenqua / 782757474
    c.execute("SELECT id FROM users WHERE username = ?", ("Egmenqua",))
    if not c.fetchone():
        now = datetime.utcnow().isoformat()
        pw_plain = "782757474"
        pw_hash = generate_password_hash(pw_plain)
        c.execute('''
            INSERT INTO users (username, password_plain, password_hash, display_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ("Egmenqua", pw_plain, pw_hash, "Egmenqua", "admin", now))
        conn.commit()
    conn.close()

init_db()

# ---------- Utilities ----------
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (uid,))
    row = c.fetchone()
    conn.close()
    return row

def login_user(user_row):
    session.clear()
    session['user_id'] = user_row['id']
    session['username'] = user_row['username']
    session['role'] = user_row['role']

def require_login(fn):
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Önce giriş yapmalısın.", "warning")
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def chat_room_name(a, b):
    # deterministic room name for 1:1 chat
    a_, b_ = min(a,b), max(a,b)
    return f"chat_{a_}_{b_}"

# ---------- Routes ----------
@app.route('/uploads/<path:fn>')
def uploaded_file(fn):
    return send_from_directory(UPLOAD_DIR, fn)

@app.route('/')
def index():
    user = current_user()
    return render_template_string(LAYOUT + INDEX_HTML, user=user)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        display = request.form.get('display','').strip() or username
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli.", "danger")
            return redirect(url_for('register'))
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            flash("Kullanıcı adı alınmış.", "danger"); conn.close(); return redirect(url_for('register'))
        now = datetime.utcnow().isoformat()
        pw_hash = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password_plain, password_hash, display_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (username, password, pw_hash, display, 'viewer', now))
        conn.commit()
        # auto-login
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        u = c.fetchone()
        conn.close()
        login_user(u)
        flash("Hesap oluşturuldu ve giriş yapıldı.", "success")
        return redirect(url_for('dashboard'))
    return render_template_string(LAYOUT + REGISTER_HTML, user=current_user())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if not user:
            flash("Kullanıcı bulunamadı.", "danger"); return redirect(url_for('login'))
        if not check_password_hash(user['password_hash'], password):
            flash("Şifre hatalı.", "danger"); return redirect(url_for('login'))
        # login
        login_user(user)
        flash("Giriş başarılı.", "success")
        return redirect(url_for('dashboard'))
    return render_template_string(LAYOUT + LOGIN_HTML, user=current_user())

@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for('index'))

@app.route('/dashboard')
@require_login
def dashboard():
    user = current_user()
    conn = get_db(); c = conn.cursor()
    # fetch friends for display
    c.execute('''SELECT u.id,u.username,u.display_name FROM friends f JOIN users u ON f.friend_id=u.id WHERE f.user_id=?''',(user['id'],))
    friends = c.fetchall()
    c.execute("SELECT id,username,display_name,role FROM users WHERE id != ? ORDER BY username",(user['id'],))
    others = c.fetchall()
    conn.close()
    return render_template_string(LAYOUT + DASH_HTML, user=user, friends=friends, others=others)

@app.route('/add_friend', methods=['POST'])
@require_login
def add_friend():
    user = current_user()
    target = request.form.get('friend_username','').strip()
    if not target:
        flash("Kullanıcı adı gir.", "danger"); return redirect(url_for('dashboard'))
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (target,))
    row = c.fetchone()
    if not row: flash("Kullanıcı yok.", "danger"); conn.close(); return redirect(url_for('dashboard'))
    target_id = row['id']
    if target_id == user['id']: flash("Kendini ekleyemezsin.", "warning"); conn.close(); return redirect(url_for('dashboard'))
    c.execute("SELECT id FROM friends WHERE user_id=? AND friend_id=?", (user['id'], target_id))
    if c.fetchone(): flash("Zaten ekli.", "info"); conn.close(); return redirect(url_for('dashboard'))
    now = datetime.utcnow().isoformat()
    c.execute("INSERT INTO friends (user_id, friend_id, created_at) VALUES (?, ?, ?)", (user['id'], target_id, now))
    conn.commit(); conn.close()
    flash("Arkadaş eklendi.", "success")
    return redirect(url_for('dashboard'))

@app.route('/chat/<int:friend_id>')
@require_login
def chat(friend_id):
    user = current_user()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id,username,display_name FROM users WHERE id = ?", (friend_id,))
    friend = c.fetchone()
    if not friend: conn.close(); flash("Kullanıcı bulunamadı.", "danger"); return redirect(url_for('dashboard'))
    # check permission: either friend relation exists or user is admin
    allowed = False
    if user['role'] == 'admin' and user['username']=='Egmenqua':
        allowed = True
    else:
        c.execute("SELECT id FROM friends WHERE user_id=? AND friend_id=?", (user['id'], friend_id))
        if c.fetchone(): allowed = True
    # load last messages
    c.execute('''SELECT m.*, s.username as sender_username FROM messages m JOIN users s ON m.sender_id=s.id
                 WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
                 ORDER BY m.id ASC LIMIT 500''', (user['id'], friend_id, friend_id, user['id']))
    msgs = c.fetchall()
    conn.close()
    if not allowed:
        flash("Önce arkadaş ekle.", "warning"); return redirect(url_for('dashboard'))
    return render_template_string(LAYOUT + CHAT_HTML, user=user, friend=friend, messages=msgs)

# Admin-only page (Egmenqua) — can see plaintext passwords and promote/demote
@app.route('/admin_panel')
@require_login
def admin_panel():
    user = current_user()
    if not (user['role']=='admin' and user['username']=='Egmenqua'):
        flash("Sadece ana admin erişebilir.", "danger"); return redirect(url_for('dashboard'))
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, username, display_name, role, password_plain, created_at FROM users ORDER BY id")
    users = c.fetchall()
    conn.close()
    return render_template_string(LAYOUT + ADMIN_HTML, user=user, users=users)

@app.route('/promote/<int:uid>', methods=['POST'])
@require_login
def promote(uid):
    user = current_user()
    if not (user['role']=='admin' and user['username']=='Egmenqua'):
        flash("Yetkiniz yok.", "danger"); return redirect(url_for('dashboard'))
    conn = get_db(); c=conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (uid,))
    row = c.fetchone()
    if not row: flash("Kullanıcı yok.", "danger"); conn.close(); return redirect(url_for('admin_panel'))
    if row['username']=='Egmenqua': flash("Ana admin'e müdahale edilemez.", "warning"); conn.close(); return redirect(url_for('admin_panel'))
    c.execute("UPDATE users SET role='coadmin' WHERE id=?", (uid,))
    conn.commit(); conn.close()
    flash("Co-Admin yapıldı.", "success"); return redirect(url_for('admin_panel'))

@app.route('/demote/<int:uid>', methods=['POST'])
@require_login
def demote(uid):
    user = current_user()
    if not (user['role']=='admin' and user['username']=='Egmenqua'):
        flash("Yetkiniz yok.", "danger"); return redirect(url_for('dashboard'))
    conn = get_db(); c=conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (uid,))
    row = c.fetchone()
    if not row: flash("Kullanıcı yok.", "danger"); conn.close(); return redirect(url_for('admin_panel'))
    c.execute("UPDATE users SET role='viewer' WHERE id=?", (uid,))
    conn.commit(); conn.close()
    flash("Co-Admin kaldırıldı.", "success"); return redirect(url_for('admin_panel'))

@app.route('/delete_user/<int:uid>', methods=['POST'])
@require_login
def delete_user(uid):
    user = current_user()
    conn = get_db(); c=conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id=?", (uid,))
    target = c.fetchone()
    if not target: flash("Kullanıcı yok.", "danger"); conn.close(); return redirect(url_for('dashboard'))
    # protect Egmenqua
    if target['username']=='Egmenqua':
        flash("Egmenqua silinemez.", "warning"); conn.close(); return redirect(url_for('dashboard'))
    # permission: Egmenqua can delete anyone; coadmin can delete others but not Egmenqua; viewer cannot
    if user['username']=='Egmenqua' or user['role']=='coadmin':
        # delete messages & friends & user
        c.execute("DELETE FROM messages WHERE sender_id=? OR receiver_id=?", (uid, uid))
        c.execute("DELETE FROM friends WHERE user_id=? OR friend_id=?", (uid, uid))
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit(); conn.close()
        flash("Kullanıcı silindi.", "success")
        return redirect(url_for('admin_panel') if user['username']=='Egmenqua' else url_for('dashboard'))
    else:
        conn.close(); flash("Yetkiniz yok.", "danger"); return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET','POST'])
@require_login
def profile():
    user = current_user()
    if request.method=='POST':
        display = request.form.get('display','').strip() or user['username']
        newpw = request.form.get('new_password','').strip()
        conn = get_db(); c = conn.cursor()
        if newpw:
            c.execute("UPDATE users SET display_name=?, password_plain=?, password_hash=? WHERE id=?",
                      (display, newpw, generate_password_hash(newpw), user['id']))
        else:
            c.execute("UPDATE users SET display_name=? WHERE id=?", (display, user['id']))
        conn.commit(); conn.close()
        flash("Profil güncellendi.", "success"); return redirect(url_for('profile'))
    return render_template_string(LAYOUT + PROFILE_HTML, user=user)

# ---------- Socket.IO events ----------
@socketio.on('connect')
def on_connect():
    usr = current_user()
    if not usr:
        # Reject connection
        return False
    # connection accepted
    # join a personal room to allow server->user pushes
    join_room(f"user_{usr['id']}")
    # optional: emit welcome
    emit('status', {'msg': f"{usr['username']} bağlantı kurdu."}, room=f"user_{usr['id']}")

@socketio.on('join_chat')
def on_join_chat(data):
    # data: { friend_id: int }
    usr = current_user()
    if not usr: return
    friend_id = int(data.get('friend_id'))
    room = chat_room_name(usr['id'], friend_id)
    join_room(room)
    emit('joined', {'room': room}, room=room)

@socketio.on('leave_chat')
def on_leave_chat(data):
    usr = current_user()
    if not usr: return
    friend_id = int(data.get('friend_id'))
    room = chat_room_name(usr['id'], friend_id)
    leave_room(room)

@socketio.on('send_message')
def on_send_message(data):
    """
    data: { to_id: int, content: str }
    """
    usr = current_user()
    if not usr:
        emit('error', {'msg':'Giriş gerekli'}); return
    to_id = int(data.get('to_id', 0))
    content = (data.get('content') or '').strip()
    if not content:
        emit('error', {'msg':'Mesaj boş'}); return
    # permission: either Egmenqua (master) or friend relation exists or coadmin allowed
    conn = get_db(); c = conn.cursor()
    allowed = False
    if usr['username']=='Egmenqua':
        allowed = True
    else:
        # coadmin allowed too (per your spec) - coadmin has admin-like powers
        if usr['role']=='coadmin':
            allowed = True
        else:
            c.execute("SELECT id FROM friends WHERE user_id=? AND friend_id=?", (usr['id'], to_id))
            if c.fetchone():
                allowed = True
    if not allowed:
        conn.close(); emit('error', {'msg':'İzinsiz'}); return
    ts = datetime.utcnow().isoformat()
    c.execute("INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)",
              (usr['id'], to_id, content, ts))
    conn.commit()
    conn.close()
    room = chat_room_name(usr['id'], to_id)
    # broadcast to room
    socketio.emit('new_message', {
        'sender_id': usr['id'],
        'sender_username': usr['username'],
        'receiver_id': to_id,
        'content': content,
        'timestamp': ts
    }, room=room)

# ---------- Templates (layout + pages) ----------
# (concise HTML/CSS templates embedded for single-file convenience)
LAYOUT = """
<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QUAVERSE LAN Chat</title>
<style>
:root{--purple:#a855f7;--blue:#0ea5e9;}
*{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,Arial;background:linear-gradient(135deg,#000000,#070017);color:#fff}
.header{display:flex;justify-content:space-between;align-items:center;padding:14px;background:linear-gradient(90deg,var(--purple),var(--blue))}
.header h1{margin:0;font-size:1.05rem}
.nav{display:flex;gap:8px;align-items:center}
.btn{background:rgba(255,255,255,0.06);padding:8px 12px;border-radius:8px;color:#fff;text-decoration:none}
.container{max-width:1100px;margin:20px auto;padding:12px}
.card{background:rgba(255,255,255,0.02);padding:14px;border-radius:12px;margin-bottom:12px}
.small{color:rgba(255,255,255,0.75)}
input,textarea,select{width:100%;padding:10px;border-radius:8px;border:none;background:rgba(255,255,255,0.03);color:#fff}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
.footer{margin-top:18px;text-align:center;color:rgba(255,255,255,0.4)}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style>
</head><body>
  <div class="header">
    <h1>QUAVERSE Sistem Sohbet Arayüzü</h1>
    <div class="nav">
      {% if user %}
        <div class="small">Hoşgeldin, <strong>{{ user['display_name'] or user['username'] }}</strong> ({{ user['role'] }})</div>
        <a class="btn" href="{{ url_for('dashboard') }}">Panel</a>
        <a class="btn" href="{{ url_for('profile') }}">Profil</a>
        {% if user['role']=='admin' and user['username']=='Egmenqua' %}
          <a class="btn" href="{{ url_for('admin_panel') }}">Ana Admin</a>
        {% endif %}
        <a class="btn" href="{{ url_for('logout') }}">Çıkış</a>
      {% else %}
        <a class="btn" href="{{ url_for('login') }}">Giriş</a>
        <a class="btn" href="{{ url_for('register') }}">Kayıt</a>
      {% endif %}
    </div>
  </div>
  <div class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat,msg in messages %}
          <div class="card"><div class="small">{{ msg }}</div></div>
        {% endfor %}
      {% endif %}
    {% endwith %}
"""

INDEX_HTML = """
  <div class="card">
    <h2>QUAVERSE LAN Chat</h2>
    <p class="small">Yerel ağ üzerinde gerçek zamanlı sohbet. Sunucuyu çalıştıran kişi (sen) bağlantıyı başlatmalı.</p>
    {% if user %}
      <div style="margin-top:12px"><a class="btn" href="{{ url_for('dashboard') }}">Panele Git</a></div>
    {% else %}
      <div style="margin-top:12px"><a class="btn" href="{{ url_for('login') }}">Giriş Yap</a> <a class="btn" href="{{ url_for('register') }}">Kayıt Ol</a></div>
    {% endif %}
  </div>
  <div class="footer">QUAVERSE · LOCAL · 2025</div>
  </div></body></html>
"""

REGISTER_HTML = """
  <div class="card" style="max-width:600px;margin:auto">
    <h3>Kayıt</h3>
    <form method="POST">
      <label>Kullanıcı adı</label><input name="username" required>
      <label>Görünen isim (opsiyonel)</label><input name="display">
      <label>Şifre</label><input name="password" type="password" required>
      <div style="margin-top:8px"><button class="btn" type="submit">Kayıt Ol</button></div>
    </form>
  </div>
  </div></body></html>
"""

LOGIN_HTML = """
  <div class="card" style="max-width:600px;margin:auto">
    <h3>Giriş</h3>
    <form method="POST">
      <label>Kullanıcı adı</label><input name="username" required>
      <label>Şifre</label><input name="password" type="password" required>
      <div style="margin-top:8px"><button class="btn" type="submit">Giriş</button></div>
    </form>
  </div>
  </div></body></html>
"""

DASH_HTML = """
  <div class="card">
    <h3>Kontrol Paneli</h3>
    <p class="small">Hızlı erişim. Arkadaş ekle, sonra 1:1 sohbet başlat.</p>
    <div style="display:flex;gap:8px;margin-top:8px">
      <a class="btn" href="{{ url_for('profile') }}">Profil</a>
      {% if user['role']=='admin' and user['username']=='Egmenqua' %}<a class="btn" href="{{ url_for('admin_panel') }}">Ana Admin</a>{% endif %}
    </div>
  </div>

  <div class="card" style="display:grid;grid-template-columns:320px 1fr;gap:12px">
    <div>
      <h4>Arkadaşlar</h4>
      {% for f in friends %}
        <div style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);display:flex;justify-content:space-between;align-items:center">
          <div><strong>{{ f['display_name'] or f['username'] }}</strong><div class="small">@{{ f['username'] }}</div></div>
          <div><a class="btn" href="{{ url_for('chat', friend_id=f['id']) }}">Sohbet</a></div>
        </div>
      {% else %}
        <div class="small">Henüz arkadaş yok.</div>
      {% endfor %}
      <hr>
      <h4>Yeni Arkadaş Ekle</h4>
      <form method="POST" action="{{ url_for('add_friend') }}">
        <label>Kullanıcı adı</label><input name="friend_username" required>
        <div style="margin-top:8px"><button class="btn" type="submit">Ekle</button></div>
      </form>
    </div>
    <div>
      <h4>Tüm Kullanıcılar</h4>
      <div style="max-height:60vh;overflow:auto">
        {% for o in others %}
          <div style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);display:flex;justify-content:space-between;align-items:center">
            <div><strong>{{ o['display_name'] or o['username'] }}</strong><div class="small">@{{ o['username'] }} • {{ o['role'] }}</div></div>
            <div><a class="btn" href="{{ url_for('chat', friend_id=o['id']) }}">Sohbet</a></div>
          </div>
        {% endfor %}
      </div>
    </div>
  </div>
  <div class="footer">QUAVERSE · LOCAL · 2025</div>
  </div></body></html>
"""

CHAT_HTML = """
  <div class="card" style="display:grid;grid-template-columns:1fr 320px;gap:12px">
    <div>
      <div style="display:flex;gap:12px;align-items:center"><div style="width:48px;height:48px;border-radius:50%;background:linear-gradient(45deg,var(--purple),var(--blue));display:flex;align-items:center;justify-content:center">{{ friend['username'][0] }}</div>
      <div><strong>{{ friend['display_name'] or friend['username'] }}</strong><div class="small">@{{ friend['username'] }}</div></div></div>
      <hr>
      <div id="messages" style="height:60vh;overflow:auto;padding:8px;border-radius:8px;background:rgba(255,255,255,0.02)">
        {% for m in messages %}
          <div style="margin-bottom:8px;max-width:70%;padding:10px;border-radius:8px;background:{{ 'linear-gradient(90deg,var(--purple),var(--blue))' if m['sender_id']==user['id'] else 'rgba(255,255,255,0.03)' }};color:{{ '#000' if m['sender_id']==user['id'] else '#fff' }}">
            <div class="small">{{ m['sender_username'] }} • {{ m['timestamp'] }}</div>
            <div>{{ m['content'] }}</div>
          </div>
        {% endfor %}
      </div>
      <div style="display:flex;gap:8px;margin-top:10px">
        <input id="msgInput" placeholder="Mesaj yaz..." type="text">
        <button id="sendBtn" class="btn">Gönder</button>
      </div>
    </div>
    <div>
      <div class="card">
        <h4>Profil</h4>
        <div class="small"><strong>{{ user['display_name'] or user['username'] }}</strong></div>
        <div class="small">@{{ user['username'] }} • {{ user['role'] }}</div>
      </div>
      <div class="card" style="margin-top:12px">
        <h4>Hızlı İşlemler</h4>
        <a class="btn" href="{{ url_for('dashboard') }}">Geri</a>
        {% if user['role']=='admin' and user['username']=='Egmenqua' %}
          <a class="btn" href="{{ url_for('admin_panel') }}">Ana Admin</a>
        {% endif %}
      </div>
    </div>
  </div>

<script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script>
const socket = io();
const friendId = {{ friend['id'] }};
const meId = {{ user['id'] }};
const messagesEl = document.getElementById('messages');
const input = document.getElementById('msgInput');
const btn = document.getElementById('sendBtn');

socket.on('connect', ()=> {
  console.log('socket connected');
  socket.emit('join_chat', {friend_id: friendId});
});

socket.on('new_message', data => {
  // if message belongs to this chat, render
  const a = Number(data.sender_id), b = Number(data.receiver_id);
  if ((a===meId && b===friendId) || (a===friendId && b===meId)) {
    const div = document.createElement('div');
    const isMe = data.sender_id === meId;
    div.style.marginBottom='8px';
    div.style.maxWidth='70%';
    div.style.padding='10px';
    div.style.borderRadius='8px';
    div.style.background = isMe ? 'linear-gradient(90deg,var(--purple),var(--blue))' : 'rgba(255,255,255,0.03)';
    div.style.color = isMe ? '#000' : '#fff';
    div.innerHTML = `<div class="small">${data.sender_username} • ${data.timestamp}</div><div>${data.content}</div>`;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }
});

btn.addEventListener('click', async ()=>{
  const text = input.value.trim();
  if(!text) return;
  socket.emit('send_message', {to_id: friendId, content: text});
  input.value = '';
});

input.addEventListener('keydown', e => { if(e.key==='Enter'){ e.preventDefault(); btn.click(); } });
</script>
</body></html>
"""

ADMIN_HTML = """
  <div class="card">
    <h3>Ana Admin Panel (Egmenqua)</h3>
    <p class="small">Tüm kullanıcılar ve PLAINTEXT şifreler (UYARI: sadece lokal/test için).</p>
    <table class="table">
      <thead><tr><th>#</th><th>Kullanıcı</th><th>Görünen</th><th>Rol</th><th>Şifre (Plain)</th><th>Oluşturma</th><th>İşlem</th></tr></thead>
      <tbody>
        {% for u in users %}
          <tr>
            <td>{{ u['id'] }}</td>
            <td>{{ u['username'] }}</td>
            <td>{{ u['display_name'] }}</td>
            <td>{{ u['role'] }}</td>
            <td><strong>{{ u['password_plain'] }}</strong></td>
            <td class="small">{{ u['created_at'] }}</td>
            <td>
              {% if u['username'] != 'Egmenqua' %}
                <form style="display:inline" method="post" action="{{ url_for('delete_user', uid=u['id']) }}" onsubmit="return confirm('Silinsin mi?');"><button class="btn" type="submit">Sil</button></form>
                {% if u['role'] != 'coadmin' %}
                  <form style="display:inline" method="post" action="{{ url_for('promote', uid=u['id']) }}"><button class="btn" type="submit">Co-Admin Yap</button></form>
                {% else %}
                  <form style="display:inline" method="post" action="{{ url_for('demote', uid=u['id']) }}"><button class="btn" type="submit">Co-Admin Kaldır</button></form>
                {% endif %}
              {% else %}
                <span class="small">Ana Admin</span>
              {% endif %}
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  </div></body></html>
"""

PROFILE_HTML = """
  <div class="card">
    <h3>Profil</h3>
    <form method="POST">
      <label>Görünen isim</label><input name="display" value="{{ user['display_name'] or '' }}">
      <label>Yeni şifre (boş bırakılırsa değişmez)</label><input name="new_password" type="password">
      <div style="margin-top:8px"><button class="btn" type="submit">Güncelle</button></div>
    </form>
    <hr>
    {% if user['username'] != 'Egmenqua' %}
      <form method="post" action="{{ url_for('delete_user', uid=user['id']) }}" onsubmit="return confirm('Hesabı silmek istediğine emin misin?');">
        <button class="btn" style="background:rgba(255,0,0,0.08)">Hesabı Sil</button>
      </form>
    {% else %}
      <div class="small">Ana admin silinemez.</div>
    {% endif %}
  </div>
  </div></body></html>
"""

# ---------- Run ----------
if __name__ == '__main__':
    # print connection hint
    print("QUAVERSE LAN Chat server başlatılıyor...")
    print("Aynı WiFi ağındaki cihazlar bağlanmak için: http://<YOUR_DEVICE_IP>:5000")
    # Use eventlet if installed (recommended)
    try:
        import eventlet
        eventlet.monkey_patch()
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except Exception:
        # fallback
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, threaded=True)
