from flask import Flask, request, redirect, url_for, session, flash, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "quaverse_super_secret_key"

DB_NAME = "quaverse_chat.db"

# -------------------- VERİTABANI --------------------
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'User'
        )
        """)

        c.execute("""
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """)

        # Admin hesabı
        admin_pass = generate_password_hash("782757474")
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("Egmenqua", admin_pass, "Admin"))

        conn.commit()
        conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# -------------------- HTML ŞABLONLAR --------------------
login_template = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QUAVERSE Sohbet - Giriş</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body {
    background: linear-gradient(135deg, #000, #1f0036, #4b0082);
    color: white;
    font-family: 'Segoe UI', sans-serif;
}
.card {
    max-width: 420px;
    margin: 80px auto;
    background: rgba(255,255,255,0.1);
    border-radius: 15px;
    padding: 30px;
    box-shadow: 0 0 25px rgba(168,85,247,0.6);
}
h1 {
    text-align: center;
    font-weight: 900;
    margin-bottom: 25px;
    background: linear-gradient(45deg,#c084fc,#a855f7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
input {
    background: rgba(255,255,255,0.2);
    border: none;
    color: white;
}
input::placeholder { color: #ddd; }
.btn-custom {
    background: #a855f7;
    border: none;
    width: 100%;
    font-weight: bold;
}
.btn-custom:hover { background: #9333ea; }
a { color: #0bf; }
</style>
</head>
<body>
<div class="card">
<h1>QUAVERSE Sohbet</h1>
<form method="POST">
<input type="text" name="username" class="form-control mb-3" placeholder="Kullanıcı Adı" required>
<input type="password" name="password" class="form-control mb-3" placeholder="Şifre" required>
<button type="submit" class="btn btn-custom">Giriş Yap</button>
</form>
<p class="text-center mt-3"><a href="/register">Hesap Oluştur</a></p>

{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category, msg in messages %}
    <div class="alert alert-{{category}} mt-2">{{msg}}</div>
  {% endfor %}
{% endwith %}
</div>
</body>
</html>
"""

register_template = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QUAVERSE Sohbet - Kayıt</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body {
    background: linear-gradient(135deg, #000, #1f0036, #4b0082);
    color: white;
    font-family: 'Segoe UI', sans-serif;
}
.card {
    max-width: 420px;
    margin: 80px auto;
    background: rgba(255,255,255,0.1);
    border-radius: 15px;
    padding: 30px;
    box-shadow: 0 0 25px rgba(168,85,247,0.6);
}
h1 {
    text-align: center;
    font-weight: 900;
    margin-bottom: 25px;
    background: linear-gradient(45deg,#c084fc,#a855f7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
input {
    background: rgba(255,255,255,0.2);
    border: none;
    color: white;
}
input::placeholder { color: #ddd; }
.btn-custom {
    background: #a855f7;
    border: none;
    width: 100%;
    font-weight: bold;
}
.btn-custom:hover { background: #9333ea; }
a { color: #0bf; }
</style>
</head>
<body>
<div class="card">
<h1>Hesap Oluştur</h1>
<form method="POST">
<input type="text" name="username" class="form-control mb-3" placeholder="Kullanıcı Adı" required>
<input type="password" name="password" class="form-control mb-3" placeholder="Şifre" required>
<button type="submit" class="btn btn-custom">Kayıt Ol</button>
</form>
<p class="text-center mt-3"><a href="/">Giriş Yap</a></p>

{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category, msg in messages %}
    <div class="alert alert-{{category}} mt-2">{{msg}}</div>
  {% endfor %}
{% endwith %}
</div>
</body>
</html>
"""

dashboard_template = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QUAVERSE Sohbet</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body {
    background: linear-gradient(120deg, #1f0036, #4b0082);
    color: white;
    font-family: 'Segoe UI', sans-serif;
}
h1 {
    text-align: center;
    font-weight: 900;
    margin-bottom: 20px;
    background: linear-gradient(45deg,#c084fc,#a855f7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.container {
    max-width: 900px;
}
.chat-box {
    background: rgba(0,0,0,0.3);
    border-radius: 10px;
    padding: 15px;
    max-height: 400px;
    overflow-y: auto;
}
.message {
    margin-bottom: 10px;
    padding: 8px 12px;
    border-radius: 8px;
    background: rgba(255,255,255,0.15);
}
.sender {
    font-weight: bold;
    color: #a855f7;
}
textarea, input {
    background: rgba(255,255,255,0.2);
    border: none;
    color: white;
}
textarea::placeholder, input::placeholder { color: #ddd; }
.btn-custom {
    background: #a855f7;
    border: none;
    font-weight: bold;
}
.btn-custom:hover { background: #9333ea; }
a { color: #0bf; }
</style>
</head>
<body>
<div class="container mt-4">
<h1>QUAVERSE Sohbet Arayüzü</h1>
<p>Hoşgeldin <b>{{username}}</b> | Rol: {{role}} | <a href="{{url_for('logout')}}">Çıkış Yap</a></p>

{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category, msg in messages %}
    <div class="alert alert-{{category}} mt-2">{{msg}}</div>
  {% endfor %}
{% endwith %}

<div class="row">
<div class="col-md-8">
<h4>Mesajlar</h4>
<div class="chat-box mb-3">
{% for msg in messages %}
<div class="message">
<span class="sender">{{msg['sender']}}</span> → <b>{{msg['receiver']}}</b>
<small class="text-muted float-end">{{msg['timestamp']}}</small><br>
{{msg['message']}}
</div>
{% endfor %}
</div>

<form method="POST">
<div class="mb-2">
<input type="text" name="receiver" class="form-control" placeholder="Alıcı kullanıcı adı" required>
</div>
<div class="mb-2">
<textarea name="message" class="form-control" rows="3" placeholder="Mesajınızı yazın..." required></textarea>
</div>
<button type="submit" class="btn btn-custom">Gönder</button>
</form>
</div>

<div class="col-md-4">
<h4>Kullanıcılar</h4>
<ul class="list-group">
{% for user in users %}
<li class="list-group-item bg-dark text-white">
{{user['username']}}
{% if role == "Admin" %}
 - <small>{{user['role']}}</small>
{% endif %}
</li>
{% endfor %}
</ul>
</div>
</div>
</div>
</body>
</html>
"""

# -------------------- ROUTES --------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            flash("Kullanıcı adı veya şifre yanlış!", "danger")

    return render_template_string(login_template)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        if not username or not password:
            flash("Lütfen tüm alanları doldurun.", "warning")
            return redirect(url_for("register"))

        conn = get_db()
        exists = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("Bu kullanıcı adı zaten alınmış!", "warning")
        else:
            hashed = generate_password_hash(password)
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
            flash("Hesap oluşturuldu! Giriş yapabilirsiniz.", "success")
        conn.close()
        return redirect(url_for("login"))

    return render_template_string(register_template)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    role = session["role"]
    conn = get_db()

    if request.method == "POST":
        receiver = request.form.get("receiver").strip()
        message = request.form.get("message").strip()

        if receiver and message:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)",
                (username, receiver, message, timestamp)
            )
            conn.commit()
            flash("Mesaj gönderildi.", "success")

    # Kullanıcı listesi
    users = conn.execute("SELECT username, role FROM users").fetchall()

    # Mesajlar
    if role == "Admin":
        messages = conn.execute("SELECT * FROM messages ORDER BY id ASC").fetchall()
    else:
        messages = conn.execute(
            "SELECT * FROM messages WHERE sender = ? OR receiver = ? ORDER BY id ASC",
            (username, username)
        ).fetchall()

    conn.close()

    return render_template_string(dashboard_template,
                                  username=username,
                                  role=role,
                                  users=users,
                                  messages=messages)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------- ÇALIŞTIR --------------------
if __name__ == "__main__":
    print("QUAVERSE Sohbet Sunucusu başlatılıyor...")
    print("Tarayıcıdan aç: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)