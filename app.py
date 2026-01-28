from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime

app = Flask(__name__)
app.secret_key = "QUAVERSE_CORE_KEY"
socketio = SocketIO(app)

DB = "quaverse_chat.db"

# =========================
# DATABASE
# =========================
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_plain TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        role TEXT DEFAULT 'viewer',
        is_banned INTEGER DEFAULT 0,
        is_muted INTEGER DEFAULT 0,
        created_at TEXT
    )
    """)
    conn.commit()

    # Egmenqua bootstrap
    c.execute("SELECT * FROM users WHERE username='Egmenqua'")
    if not c.fetchone():
        pw = "egmenqua"
        c.execute("""
        INSERT INTO users 
        (username,password_plain,password_hash,display_name,role,created_at)
        VALUES (?,?,?,?,?,?)
        """, (
            "Egmenqua",
            pw,
            generate_password_hash(pw),
            "Egmenqua",
            "admin",
            str(datetime.datetime.now())
        ))
        conn.commit()
    conn.close()

init_db()

# =========================
# AUTH HELPERS
# =========================
def current_user():
    if "uid" not in session:
        return None
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (session["uid"],))
    u = c.fetchone()
    conn.close()
    return u

def require_admin(fn):
    def wrap(*a, **kw):
        u = current_user()
        if not u or u["role"] != "admin":
            flash("Yetki yok", "danger")
            return redirect(url_for("chat"))
        return fn(*a, **kw)
    wrap.__name__ = fn.__name__
    return wrap

# =========================
# ROUTES
# =========================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if not user:
            flash("Kullanıcı yok", "danger")
            return redirect(url_for("login"))

        if user["is_banned"]:
            flash("Bu hesap banlandı.", "danger")
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("Şifre hatalı", "danger")
            return redirect(url_for("login"))

        session["uid"] = user["id"]
        return redirect(url_for("chat"))

    return render_template_string(LOGIN_HTML)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/chat")
def chat():
    if not current_user():
        return redirect(url_for("login"))
    return render_template_string(CHAT_HTML, user=current_user())

# =========================
# ADMIN PANEL
# =========================
@app.route("/admin")
@require_admin
def admin_panel():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return render_template_string(ADMIN_PANEL_HTML, users=users)

@app.route("/admin_toggle_ban", methods=["POST"])
@require_admin
def admin_toggle_ban():
    uid = request.form["user_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET is_banned = 1 - is_banned WHERE id=? AND username!='Egmenqua'", (uid,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

@app.route("/admin_toggle_mute", methods=["POST"])
@require_admin
def admin_toggle_mute():
    uid = request.form["user_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET is_muted = 1 - is_muted WHERE id=? AND username!='Egmenqua'", (uid,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

@app.route("/admin_delete_user", methods=["POST"])
@require_admin
def admin_delete_user():
    uid = request.form["user_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=? AND username!='Egmenqua'", (uid,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

# =========================
# SOCKET
# =========================
@socketio.on("send_message")
def handle_message(data):
    usr = current_user()
    if not usr:
        return
    if usr["is_muted"]:
        emit("error", {"msg": "Mutelisin"})
        return
    emit("receive_message", {
        "user": usr["display_name"],
        "msg": data["msg"]
    }, broadcast=True)

# =========================
# HTML TEMPLATES
# =========================

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>QUAVERSE</title>
<style>
body { background:#0b0b14; color:#fff; font-family:Arial; }
.card { width:300px; margin:100px auto; padding:20px; background:#15152a; }
input,button { width:100%; margin:5px 0; padding:8px; }
</style>
</head>
<body>
<div class="card">
<h2>QUAVERSE</h2>
<form method="POST">
<input name="username" placeholder="Username">
<input name="password" type="password" placeholder="Password">
<button>Login</button>
</form>
</div>
</body>
</html>
"""

CHAT_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>QUAVERSE CHAT</title>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<style>
body { background:#0b0b14; color:#fff; font-family:Arial; }
#chat { height:300px; overflow:auto; border:1px solid #333; padding:5px; }
</style>
</head>
<body>

<h3>Hoşgeldin {{user['display_name']}}</h3>
<div id="chat"></div>
<input id="msg"><button onclick="send()">Gönder</button>

<script>
const socket = io();

const rtcConfig = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" }
  ]
};

let peer = new RTCPeerConnection(rtcConfig);

function send(){
  socket.emit("send_message", {msg: msg.value});
  msg.value="";
}

socket.on("receive_message", d=>{
  chat.innerHTML += "<div><b>"+d.user+"</b>: "+d.msg+"</div>";
});
</script>

</body>
</html>
"""

ADMIN_PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>ADMIN</title>
<style>
body { background:#0b0b14; color:#fff; font-family:Arial; }
table { width:100%; }
td,th { padding:5px; border-bottom:1px solid #333; }
button { padding:5px; }
</style>
</head>
<body>

<h2>ADMIN PANEL</h2>
<table>
<tr>
<th>User</th><th>Role</th><th>Ban</th><th>Mute</th><th>Sil</th>
</tr>
{% for u in users %}
<tr>
<td>{{u['username']}}</td>
<td>{{u['role']}}</td>
<td>
<form method="POST" action="/admin_toggle_ban">
<input type="hidden" name="user_id" value="{{u['id']}}">
<button>{{'Unban' if u['is_banned'] else 'Ban'}}</button>
</form>
</td>
<td>
<form method="POST" action="/admin_toggle_mute">
<input type="hidden" name="user_id" value="{{u['id']}}">
<button>{{'Unmute' if u['is_muted'] else 'Mute'}}</button>
</form>
</td>
<td>
<form method="POST" action="/admin_delete_user">
<input type="hidden" name="user_id" value="{{u['id']}}">
<button>Sil</button>
</form>
</td>
</tr>
{% endfor %}
</table>

</body>
</html>
"""

# =========================
# RUN
# =========================
if __name__ == "__main__":
    socketio.run(app, debug=True)
