# quaverse_server.py
"""
QUAVERSE Sistem Sohbeti - Tam Sürüm
- Gerçek zamanlı mesajlaşma (DM + Grup)
- Sesli ve Görüntülü görüşme (WebRTC)
- Tek tuşla mikrofon/kamera aç-kapat
- SQLite veritabanı: quaverse_chat.db
- Şifreler plaintext + hash (lokal/test amaçlı)
- Ana Admin Paneli (kullanıcı yönetimi, co-admin atama, şifre görüntüleme)
"""

import os
import sqlite3
import secrets
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from flask_session import Session
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- CONFIG ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.path.join(BASE_DIR, "quaverse_chat.db")

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(24)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(BASE_DIR, 'flask_sessions')
app.config['SESSION_PERMANENT'] = False
Session(app)

socketio = SocketIO(app, manage_session=False)

# ---------------- DATABASE ----------------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_plain TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        role TEXT DEFAULT 'viewer',
        created_at TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        created_at TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER,
        room TEXT,
        content TEXT NOT NULL,
        timestamp TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        created_at TEXT
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member'
    )
    ''')

    # Ana admin oluştur
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

# ---------------- HELPERS ----------------
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

def require_admin(fn):
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user['username'] != 'Egmenqua' or user['role'] != 'admin':
            flash("Bu sayfaya erişim yetkin yok.", "danger")
            return redirect(url_for('dashboard'))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper

def chat_room_name(a, b):
    a_, b_ = min(a,b), max(a,b)
    return f"chat_{a_}_{b_}"

# ---------------- ROUTES ----------------
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
    c.execute('''SELECT u.id,u.username,u.display_name FROM friends f JOIN users u ON f.friend_id=u.id WHERE f.user_id=?''',(user['id'],))
    friends = c.fetchall()
    c.execute("SELECT id,username,display_name,role FROM users WHERE id != ? ORDER BY username",(user['id'],))
    others = c.fetchall()
    c.execute("SELECT g.id,g.name FROM groups g JOIN group_members gm ON g.id=gm.group_id WHERE gm.user_id=?",(user['id'],))
    groups = c.fetchall()
    conn.close()
    return render_template_string(LAYOUT + DASH_HTML, user=user, friends=friends, others=others, groups=groups)

# ---------------- ADMIN PANEL ----------------
@app.route('/admin_panel')
@require_admin
def admin_panel():
    user = current_user()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, username, display_name, role, password_plain, password_hash, created_at FROM users ORDER BY created_at ASC")
    users = c.fetchall()
    conn.close()
    return render_template_string(LAYOUT + ADMIN_PANEL_HTML, user=user, users=users)

@app.route('/admin_set_role', methods=['POST'])
@require_admin
def admin_set_role():
    target_id = request.form.get('user_id')
    new_role = request.form.get('new_role')
    conn = get_db(); c = conn.cursor()

    # Egmenqua'nın rolü değiştirilemez
    c.execute("SELECT username FROM users WHERE id=?", (target_id,))
    row = c.fetchone()
    if row and row['username'] == 'Egmenqua':
        flash("Egmenqua'nın rolü değiştirilemez.", "danger")
        conn.close()
        return redirect(url_for('admin_panel'))

    if new_role not in ('viewer', 'coadmin', 'admin'):
        flash("Geçersiz rol.", "danger")
        conn.close()
        return redirect(url_for('admin_panel'))

    c.execute("UPDATE users SET role=? WHERE id=?", (new_role, target_id))
    conn.commit()
    conn.close()
    flash("Rol güncellendi.", "success")
    return redirect(url_for('admin_panel'))

# ---------------- FRIENDS ----------------
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

# ---------------- GROUPS ----------------
@app.route('/create_group', methods=['POST'])
@require_login
def create_group():
    user = current_user()
    name = request.form.get('group_name','').strip()
    if not name:
        flash("Grup adı gerekli.", "danger"); return redirect(url_for('dashboard'))
    conn = get_db(); c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute("INSERT INTO groups (name, owner_id, created_at) VALUES (?, ?, ?)", (name, user['id'], now))
    group_id = c.lastrowid
    c.execute("INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)", (group_id, user['id'], 'owner'))
    conn.commit(); conn.close()
    flash("Grup oluşturuldu.", "success")
    return redirect(url_for('dashboard'))

@app.route('/group/<int:group_id>')
@require_login
def group_chat(group_id):
    user = current_user()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM groups WHERE id=?", (group_id,))
    group = c.fetchone()
    if not group:
        conn.close(); flash("Grup bulunamadı.", "danger"); return redirect(url_for('dashboard'))
    c.execute("SELECT id FROM group_members WHERE group_id=? AND user_id=?", (group_id, user['id']))
    if not c.fetchone():
        conn.close(); flash("Bu gruba erişimin yok.", "danger"); return redirect(url_for('dashboard'))
    c.execute("SELECT m.*, u.username as sender_username FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.room=? ORDER BY m.id ASC LIMIT 500",(f"group_{group_id}",))
    messages = c.fetchall()
    c.execute("SELECT u.id,u.username,u.display_name FROM group_members gm JOIN users u ON gm.user_id=u.id WHERE gm.group_id=?", (group_id,))
    members = c.fetchall()
    conn.close()
    return render_template_string(LAYOUT + GROUP_CHAT_HTML, user=user, group=group, messages=messages, members=members)

# ---------------- CHAT ----------------
@app.route('/chat/<int:friend_id>')
@require_login
def chat(friend_id):
    user = current_user()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id,username,display_name FROM users WHERE id = ?", (friend_id,))
    friend = c.fetchone()
    if not friend:
        conn.close(); flash("Kullanıcı bulunamadı.", "danger"); return redirect(url_for('dashboard'))
    allowed = False
    if user['role']=='admin' and user['username']=='Egmenqua':
        allowed = True
    else:
        c.execute("SELECT id FROM friends WHERE user_id=? AND friend_id=?", (user['id'], friend_id))
        if c.fetchone(): allowed = True
    c.execute('''SELECT m.*, s.username as sender_username FROM messages m JOIN users s ON m.sender_id=s.id
                 WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
                 ORDER BY m.id ASC LIMIT 500''', (user['id'], friend_id, friend_id, user['id']))
    msgs = c.fetchall()
    conn.close()
    if not allowed:
        flash("Önce arkadaş ekle.", "warning"); return redirect(url_for('dashboard'))
    return render_template_string(LAYOUT + CHAT_HTML, user=user, friend=friend, messages=msgs)

# ---------------- PROFILE ----------------
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

# ---------------- SOCKET.IO EVENTS ----------------
@socketio.on('connect')
def on_connect():
    usr = current_user()
    if not usr:
        return False
    join_room(f"user_{usr['id']}")

@socketio.on('join_chat')
def on_join_chat(data):
    usr = current_user()
    if not usr: return
    friend_id = int(data.get('friend_id'))
    room = chat_room_name(usr['id'], friend_id)
    join_room(room)

@socketio.on('join_group')
def on_join_group(data):
    usr = current_user()
    if not usr: return
    group_id = int(data.get('group_id'))
    room = f"group_{group_id}"
    join_room(room)

@socketio.on('send_message')
def on_send_message(data):
    usr = current_user()
    if not usr:
        emit('error', {'msg':'Giriş gerekli'}); return
    to_id = data.get('to_id')
    room = data.get('room')
    content = (data.get('content') or '').strip()
    if not content:
        emit('error', {'msg':'Mesaj boş'}); return
    conn = get_db(); c = conn.cursor()
    ts = datetime.utcnow().isoformat()
    if room:
        c.execute("INSERT INTO messages (sender_id, receiver_id, room, content, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (usr['id'], None, room, content, ts))
        conn.commit(); conn.close()
        socketio.emit('new_message', {
            'sender_id': usr['id'],
            'sender_username': usr['username'],
            'room': room,
            'content': content
        }, room=room)
    else:
        to_id = int(to_id)
        c.execute("INSERT INTO messages (sender_id, receiver_id, room, content, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (usr['id'], to_id, None, content, ts))
        conn.commit(); conn.close()
        room_name = chat_room_name(usr['id'], to_id)
        socketio.emit('new_message', {
            'sender_id': usr['id'],
            'sender_username': usr['username'],
            'receiver_id': to_id,
            'content': content
        }, room=room_name)

@socketio.on('webrtc_signal')
def on_webrtc_signal(data):
    target = data.get('target')
    signal = data.get('signal')
    if target:
        emit('webrtc_signal', {'from': session.get('user_id'), 'signal': signal}, room=f"user_{target}")

# ---------------- TEMPLATES ----------------

LAYOUT = """
<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QUAVERSE Sistem Sohbeti</title>
<style>
:root{--purple:#a855f7;--blue:#0ea5e9;}
*{box-sizing:border-box} body{margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,Arial;background:linear-gradient(135deg,#000000,#070017);color:#fff}
.header{display:flex;justify-content:space-between;align-items:center;padding:14px;background:linear-gradient(90deg,var(--purple),var(--blue))}
.header h1{margin:0;font-size:1.05rem}
.nav{display:flex;gap:8px;align-items:center}
.btn{background:rgba(255,255,255,0.06);padding:8px 12px;border-radius:8px;color:#fff;text-decoration:none;border:none;cursor:pointer}
.container{max-width:1200px;margin:20px auto;padding:12px}
.card{background:rgba(255,255,255,0.02);padding:14px;border-radius:12px;margin-bottom:12px}
.small{color:rgba(255,255,255,0.75)}
input,textarea,select{width:100%;padding:10px;border-radius:8px;border:none;background:rgba(255,255,255,0.03);color:#fff}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
.footer{margin-top:18px;text-align:center;color:rgba(255,255,255,0.4)}
.chat-box{height:60vh;overflow:auto;padding:8px;border-radius:8px;background:rgba(255,255,255,0.02)}
.msg{margin-bottom:8px;max-width:70%;padding:10px;border-radius:8px}
.msg.me{background:linear-gradient(90deg,var(--purple),var(--blue));color:#000}
.msg.other{background:rgba(255,255,255,0.03);color:#fff}
.video-box{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
video{width:200px;border-radius:12px;background:#000}
.control-bar{display:flex;gap:8px;margin-top:10px}
</style>
</head><body>
  <div class="header">
    <h1>QUAVERSE Sistem Sohbeti</h1>
    <div class="nav">
      {% if user %}
        <div class="small">Hoşgeldin, <strong>{{ user['display_name'] or user['username'] }}</strong> ({{ user['role'] }})</div>
        <a class="btn" href="{{ url_for('dashboard') }}">Panel</a>
        {% if user['username']=='Egmenqua' and user['role']=='admin' %}
          <a class="btn" href="{{ url_for('admin_panel') }}">Ana Admin Paneli</a>
        {% endif %}
        <a class="btn" href="{{ url_for('profile') }}">Profil</a>
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
    <h2>QUAVERSE Sistem Sohbeti</h2>
    {% if user %}
      <div style="margin-top:12px"><a class="btn" href="{{ url_for('dashboard') }}">Panele Git</a></div>
    {% else %}
      <div style="margin-top:12px"><a class="btn" href="{{ url_for('login') }}">Giriş Yap</a> <a class="btn" href="{{ url_for('register') }}">Kayıt Ol</a></div>
    {% endif %}
  </div>
  <div class="footer">QUAVERSE · 2026</div>
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
    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
      <a class="btn" href="{{ url_for('profile') }}">Profil</a>
      {% if user['username']=='Egmenqua' and user['role']=='admin' %}
        <a class="btn" href="{{ url_for('admin_panel') }}">Ana Admin Paneli</a>
      {% endif %}
    </div>
  </div>

  <div class="card" style="display:grid;grid-template-columns:300px 1fr 1fr;gap:12px">
    <div>
      <h4>Arkadaşlar</h4>
      {% for f in friends %}
        <div style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);display:flex;justify-content:space-between;align-items:center">
          <div><strong>{{ f['display_name'] or f['username'] }}</strong></div>
          <div><a class="btn" href="{{ url_for('chat', friend_id=f['id']) }}">Sohbet</a></div>
        </div>
      {% else %}
        <div class="small">Henüz arkadaş yok.</div>
      {% endfor %}
      <hr>
      <h4>Yeni Arkadaş Ekle</h4>
      <form method="POST" action="{{ url_for('add_friend') }}">
        <input name="friend_username" placeholder="Kullanıcı adı" required>
        <div style="margin-top:8px"><button class="btn" type="submit">Ekle</button></div>
      </form>
    </div>

    <div>
      <h4>Gruplar</h4>
      {% for g in groups %}
        <div style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);display:flex;justify-content:space-between;align-items:center">
          <div><strong>{{ g['name'] }}</strong></div>
          <div><a class="btn" href="{{ url_for('group_chat', group_id=g['id']) }}">Gir</a></div>
        </div>
      {% else %}
        <div class="small">Henüz grup yok.</div>
      {% endfor %}
      <hr>
      <h4>Yeni Grup Oluştur</h4>
      <form method="POST" action="{{ url_for('create_group') }}">
        <input name="group_name" placeholder="Grup adı" required>
        <div style="margin-top:8px"><button class="btn" type="submit">Oluştur</button></div>
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
  <div class="footer">QUAVERSE · 2026</div>
  </div></body></html>
"""

ADMIN_PANEL_HTML = """
  <div class="card">
    <h2>Ana Admin Paneli</h2>
    <p class="small">Bu panel yalnızca Egmenqua tarafından görülebilir. (Test amaçlı plaintext şifreler görünür.)</p>
  </div>

  <div class="card">
    <table class="table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Kullanıcı</th>
          <th>Görünen İsim</th>
          <th>Rol</th>
          <th>Şifre (Plain)</th>
          <th>Şifre (Hash)</th>
          <th>Oluşturulma</th>
          <th>Rol Değiştir</th>
        </tr>
      </thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u['id'] }}</td>
          <td>@{{ u['username'] }}</td>
          <td>{{ u['display_name'] or '-' }}</td>
          <td><strong>{{ u['role'] }}</strong></td>
          <td>{{ u['password_plain'] }}</td>
          <td style="font-size:0.75em;max-width:260px;word-break:break-all">{{ u['password_hash'] }}</td>
          <td>{{ u['created_at'] }}</td>
          <td>
            {% if u['username'] != 'Egmenqua' %}
            <form method="POST" action="{{ url_for('admin_set_role') }}">
              <input type="hidden" name="user_id" value="{{ u['id'] }}">
              <select name="new_role">
                <option value="viewer" {% if u['role']=='viewer' %}selected{% endif %}>viewer</option>
                <option value="coadmin" {% if u['role']=='coadmin' %}selected{% endif %}>coadmin</option>
                <option value="admin" {% if u['role']=='admin' %}selected{% endif %}>admin</option>
              </select>
              <button class="btn" type="submit">Uygula</button>
            </form>
            {% else %}
              <span class="small">Değiştirilemez</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="footer">QUAVERSE · Admin Yönetimi</div>
  </div></body></html>
"""

CHAT_HTML = """
  <div class="card" style="display:grid;grid-template-columns:1fr 320px;gap:12px">
    <div>
      <div style="display:flex;gap:12px;align-items:center">
        <div style="width:48px;height:48px;border-radius:50%;background:linear-gradient(45deg,var(--purple),var(--blue));display:flex;align-items:center;justify-content:center">{{ friend['username'][0] }}</div>
        <div><strong>{{ friend['display_name'] or friend['username'] }}</strong><div class="small">@{{ friend['username'] }}</div></div>
      </div>
      <hr>
      <div id="messages" class="chat-box">
        {% for m in messages %}
          <div class="msg {{ 'me' if m['sender_id']==user['id'] else 'other' }}">
            <div class="small">{{ m['sender_username'] }}</div>
            <div>{{ m['content'] }}</div>
          </div>
        {% endfor %}
      </div>
      <div class="control-bar">
        <input id="msgInput" placeholder="Mesaj yaz..." type="text">
        <button id="sendBtn" class="btn">Gönder</button>
      </div>

      <div class="control-bar">
        <button id="startCall" class="btn">📞 Ara</button>
        <button id="toggleMic" class="btn">🎤 Mikrofon</button>
        <button id="toggleCam" class="btn">📷 Kamera</button>
      </div>

      <div class="video-box">
        <video id="localVideo" autoplay muted></video>
        <video id="remoteVideo" autoplay></video>
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

let localStream = null;
let peer = null;
let micEnabled = true;
let camEnabled = true;

socket.on('connect', ()=> {
  socket.emit('join_chat', {friend_id: friendId});
});

socket.on('new_message', data => {
  const a = Number(data.sender_id), b = Number(data.receiver_id);
  if ((a===meId && b===friendId) || (a===friendId && b===meId)) {
    const div = document.createElement('div');
    div.className = 'msg ' + (data.sender_id===meId ? 'me':'other');
    div.innerHTML = `<div class="small">${data.sender_username}</div><div>${data.content}</div>`;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }
});

btn.addEventListener('click', ()=>{
  const text = input.value.trim();
  if(!text) return;
  socket.emit('send_message', {to_id: friendId, content: text});
  input.value = '';
});
input.addEventListener('keydown', e => { if(e.key==='Enter'){ e.preventDefault(); btn.click(); } });

async function startCall() {
  localStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
  document.getElementById('localVideo').srcObject = localStream;

  peer = new RTCPeerConnection();
  localStream.getTracks().forEach(track => peer.addTrack(track, localStream));

  peer.ontrack = e => {
    document.getElementById('remoteVideo').srcObject = e.streams[0];
  };

  peer.onicecandidate = e => {
    if(e.candidate){
      socket.emit('webrtc_signal', {target: friendId, signal: {candidate: e.candidate}});
    }
  };

  const offer = await peer.createOffer();
  await peer.setLocalDescription(offer);
  socket.emit('webrtc_signal', {target: friendId, signal: {sdp: peer.localDescription}});
}

socket.on('webrtc_signal', async data => {
  if(!peer){
    peer = new RTCPeerConnection();
    peer.ontrack = e => {
      document.getElementById('remoteVideo').srcObject = e.streams[0];
    };
    peer.onicecandidate = e => {
      if(e.candidate){
        socket.emit('webrtc_signal', {target: data.from, signal: {candidate: e.candidate}});
      }
    };
  }

  if(data.signal.sdp){
    await peer.setRemoteDescription(new RTCSessionDescription(data.signal.sdp));
    if(data.signal.sdp.type === 'offer'){
      localStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
      document.getElementById('localVideo').srcObject = localStream;
      localStream.getTracks().forEach(track => peer.addTrack(track, localStream));
      const answer = await peer.createAnswer();
      await peer.setLocalDescription(answer);
      socket.emit('webrtc_signal', {target: data.from, signal: {sdp: peer.localDescription}});
    }
  } else if(data.signal.candidate){
    await peer.addIceCandidate(new RTCIceCandidate(data.signal.candidate));
  }
});

document.getElementById('startCall').onclick = startCall;
document.getElementById('toggleMic').onclick = ()=>{
  if(!localStream) return;
  micEnabled = !micEnabled;
  localStream.getAudioTracks().forEach(t => t.enabled = micEnabled);
};
document.getElementById('toggleCam').onclick = ()=>{
  if(!localStream) return;
  camEnabled = !camEnabled;
  localStream.getVideoTracks().forEach(t => t.enabled = camEnabled);
};
</script>
</body></html>
"""

GROUP_CHAT_HTML = """
  <div class="card" style="display:grid;grid-template-columns:1fr 320px;gap:12px">
    <div>
      <h3>{{ group['name'] }}</h3>
      <hr>
      <div id="messages" class="chat-box">
        {% for m in messages %}
          <div class="msg {{ 'me' if m['sender_id']==user['id'] else 'other' }}">
            <div class="small">{{ m['sender_username'] }}</div>
            <div>{{ m['content'] }}</div>
          </div>
        {% endfor %}
      </div>
      <div class="control-bar">
        <input id="msgInput" placeholder="Mesaj yaz..." type="text">
        <button id="sendBtn" class="btn">Gönder</button>
      </div>

      <div class="control-bar">
        <button id="startCall" class="btn">📞 Grup Araması</button>
        <button id="toggleMic" class="btn">🎤 Mikrofon</button>
        <button id="toggleCam" class="btn">📷 Kamera</button>
      </div>

      <div class="video-box" id="videoGrid"></div>
    </div>
    <div>
      <div class="card">
        <h4>Üyeler</h4>
        {% for m in members %}
          <div class="small">{{ m['display_name'] or m['username'] }}</div>
        {% endfor %}
      </div>
      <div class="card" style="margin-top:12px">
        <a class="btn" href="{{ url_for('dashboard') }}">Geri</a>
      </div>
    </div>
  </div>

<script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script>
const socket = io();
const groupRoom = "group_{{ group['id'] }}";
const meId = {{ user['id'] }};
const messagesEl = document.getElementById('messages');
const input = document.getElementById('msgInput');
const btn = document.getElementById('sendBtn');

let localStream = null;
let peers = {};
let micEnabled = true;
let camEnabled = true;

socket.on('connect', ()=> {
  socket.emit('join_group', {group_id: {{ group['id'] }}});
});

socket.on('new_message', data => {
  if(data.room === groupRoom){
    const div = document.createElement('div');
    div.className = 'msg ' + (data.sender_id===meId ? 'me':'other');
    div.innerHTML = `<div class="small">${data.sender_username}</div><div>${data.content}</div>`;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }
});

btn.addEventListener('click', ()=>{
  const text = input.value.trim();
  if(!text) return;
  socket.emit('send_message', {room: groupRoom, content: text});
  input.value = '';
});
input.addEventListener('keydown', e => { if(e.key==='Enter'){ e.preventDefault(); btn.click(); } });

async function startCall(){
  localStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
  addVideo(meId, localStream, true);
  socket.emit('webrtc_signal', {target: null, signal: {join_group: groupRoom}});
}

socket.on('webrtc_signal', async data => {
  const from = data.from;
  if(data.signal.join_group){
    if(from === meId) return;
    await createPeer(from);
  } else if(data.signal.sdp){
    await peers[from].setRemoteDescription(new RTCSessionDescription(data.signal.sdp));
    if(data.signal.sdp.type === 'offer'){
      const answer = await peers[from].createAnswer();
      await peers[from].setLocalDescription(answer);
      socket.emit('webrtc_signal', {target: from, signal: {sdp: peers[from].localDescription}});
    }
  } else if(data.signal.candidate){
    await peers[from].addIceCandidate(new RTCIceCandidate(data.signal.candidate));
  }
});

async function createPeer(userId){
  const peer = new RTCPeerConnection();
  peers[userId] = peer;
  localStream.getTracks().forEach(track => peer.addTrack(track, localStream));
  peer.ontrack = e => addVideo(userId, e.streams[0], false);
  peer.onicecandidate = e => {
    if(e.candidate){
      socket.emit('webrtc_signal', {target: userId, signal: {candidate: e.candidate}});
    }
  };
  const offer = await peer.createOffer();
  await peer.setLocalDescription(offer);
  socket.emit('webrtc_signal', {target: userId, signal: {sdp: peer.localDescription}});
}

function addVideo(userId, stream, muted){
  let video = document.getElementById("video_"+userId);
  if(video) return;
  video = document.createElement('video');
  video.id = "video_"+userId;
  video.autoplay = true;
  video.muted = muted;
  video.srcObject = stream;
  document.getElementById('videoGrid').appendChild(video);
}

document.getElementById('startCall').onclick = startCall;
document.getElementById('toggleMic').onclick = ()=>{
  if(!localStream) return;
  micEnabled = !micEnabled;
  localStream.getAudioTracks().forEach(t => t.enabled = micEnabled);
};
document.getElementById('toggleCam').onclick = ()=>{
  if(!localStream) return;
  camEnabled = !camEnabled;
  localStream.getVideoTracks().forEach(t => t.enabled = camEnabled);
};
</script>
</body></html>
"""

PROFILE_HTML = """
  <div class="card">
    <h3>Profil</h3>
    <form method="POST">
      <label>Görünen isim</label><input name="display" value="{{ user['display_name'] or '' }}">
      <label>Yeni şifre (boş bırakılırsa değişmez)</label><input name="new_password" type="password">
      <div style="margin-top:8px"><button class="btn" type="submit">Güncelle</button></div>
    </form>
  </div>
  </div></body></html>
"""

# ---------------- RUN ----------------
if __name__ == '__main__':
    print("QUAVERSE Sistem Sohbeti başlatılıyor...")
    try:
        import eventlet
        eventlet.monkey_patch()
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except Exception:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, threaded=True)
