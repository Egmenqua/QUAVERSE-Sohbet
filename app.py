# quaverse_server_webrtc.py
import os, sqlite3, secrets
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_session import Session
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.path.join(BASE_DIR, "quaverse_chat.db")

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(BASE_DIR, 'flask_sessions')
app.config['SESSION_PERMANENT'] = False
Session(app)
socketio = SocketIO(app, manage_session=False)

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_plain TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        role TEXT DEFAULT 'viewer',
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER,
        room TEXT,
        content TEXT NOT NULL,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member'
    )''')
    c.execute("SELECT id FROM users WHERE username = ?", ("Egmenqua",))
    if not c.fetchone():
        now = datetime.utcnow().isoformat()
        pw_plain = "782757474"
        pw_hash = generate_password_hash(pw_plain)
        c.execute('''INSERT INTO users (username,password_plain,password_hash,display_name,role,created_at)
                     VALUES (?,?,?,?,?,?)''', ("Egmenqua", pw_plain, pw_hash, "Egmenqua", "admin", now))
        conn.commit()
    conn.close()
init_db()

def current_user():
    uid = session.get('user_id')
    if not uid: return None
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (uid,))
    row = c.fetchone(); conn.close()
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

def chat_room_name(a,b):
    return f"chat_{min(a,b)}_{max(a,b)}"

@app.route('/')
def index():
    user = current_user()
    return render_template_string(INDEX_HTML, user=user)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        display = request.form.get('display','').strip() or username
        if not username or not password:
            flash("Kullanıcı adı ve şifre gerekli.","danger")
            return redirect(url_for('register'))
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            flash("Kullanıcı adı alınmış.","danger"); conn.close(); return redirect(url_for('register'))
        now = datetime.utcnow().isoformat()
        pw_hash = generate_password_hash(password)
        c.execute("INSERT INTO users (username,password_plain,password_hash,display_name,role,created_at) VALUES (?,?,?,?,?,?)",
                  (username,password,pw_hash,display,'viewer',now))
        conn.commit(); c.execute("SELECT * FROM users WHERE username=?",(username,))
        u = c.fetchone(); conn.close()
        login_user(u); flash("Hesap oluşturuldu ve giriş yapıldı.","success")
        return redirect(url_for('dashboard'))
    return render_template_string(REGISTER_HTML, user=current_user())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone(); conn.close()
        if not user: flash("Kullanıcı bulunamadı.","danger"); return redirect(url_for('login'))
        if not check_password_hash(user['password_hash'], password):
            flash("Şifre hatalı.","danger"); return redirect(url_for('login'))
        login_user(user); flash("Giriş başarılı.","success"); return redirect(url_for('dashboard'))
    return render_template_string(LOGIN_HTML, user=current_user())

@app.route('/logout')
def logout():
    session.clear(); flash("Çıkış yapıldı.","info"); return redirect(url_for('index'))

@app.route('/dashboard')
@require_login
def dashboard():
    user = current_user()
    conn = get_db(); c = conn.cursor()
    c.execute('SELECT u.id,u.username,u.display_name FROM friends f JOIN users u ON f.friend_id=u.id WHERE f.user_id=?',(user['id'],))
    friends = c.fetchall()
    c.execute("SELECT id,username,display_name,role FROM users WHERE id!=? ORDER BY username",(user['id'],))
    others = c.fetchall()
    c.execute("SELECT g.id,g.name FROM groups g JOIN group_members gm ON g.id=gm.group_id WHERE gm.user_id=?",(user['id'],))
    groups = c.fetchall(); conn.close()
    return render_template_string(DASH_HTML, user=user, friends=friends, others=others, groups=groups)

@app.route('/chat/<int:friend_id>')
@require_login
def chat(friend_id):
    user = current_user(); conn = get_db(); c = conn.cursor()
    c.execute("SELECT id,username,display_name FROM users WHERE id = ?", (friend_id,))
    friend = c.fetchone()
    if not friend: conn.close(); flash("Kullanıcı bulunamadı.","danger"); return redirect(url_for('dashboard'))
    c.execute('SELECT m.*, s.username as sender_username FROM messages m JOIN users s ON m.sender_id=s.id WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?) ORDER BY m.id ASC LIMIT 500',
              (user['id'], friend_id, friend_id, user['id']))
    msgs = c.fetchall(); conn.close()
    return render_template_string(CHAT_HTML, user=user, friend=friend, messages=msgs)

# ---------------- SOCKET.IO ----------------
@socketio.on('connect')
def on_connect():
    usr = current_user(); 
    if not usr: return False
    join_room(f"user_{usr['id']}")

@socketio.on('join_chat')
def on_join_chat(data):
    usr = current_user(); friend_id=int(data.get('friend_id')); join_room(chat_room_name(usr['id'],friend_id))

@socketio.on('send_message')
def on_send_message(data):
    usr=current_user(); 
    if not usr: return
    to_id = int(data.get('to_id')); content=(data.get('content') or '').strip()
    if not content: emit('error',{'msg':'Mesaj boş'}); return
    conn=get_db(); c=conn.cursor(); ts=datetime.utcnow().isoformat()
    c.execute("INSERT INTO messages (sender_id, receiver_id, room, content, timestamp) VALUES (?,?,?,?,?)",(usr['id'],to_id,None,content,ts))
    conn.commit(); conn.close()
    room_name=chat_room_name(usr['id'],to_id)
    socketio.emit('new_message',{'sender_id':usr['id'],'sender_username':usr['username'],'receiver_id':to_id,'content':content},room=room_name)

@socketio.on('webrtc_signal')
def on_webrtc_signal(data):
    target = data.get('target'); signal = data.get('signal')
    if target: emit('webrtc_signal',{'from':session.get('user_id'),'signal':signal},room=f"user_{target}")

# ---------------- HTML / JS ----------------
INDEX_HTML = """
<h2>QUAVERSE Sistem Sohbeti</h2>
{% if user %}<a href="{{ url_for('dashboard') }}">Panele Git</a>{% else %}<a href="{{ url_for('login') }}">Giriş</a>{% endif %}
"""
REGISTER_HTML = """
<form method="POST"><input name="username" required><input name="display"><input name="password" type="password" required><button type="submit">Kayıt</button></form>
"""
LOGIN_HTML = """
<form method="POST"><input name="username" required><input name="password" type="password" required><button type="submit">Giriş</button></form>
"""
DASH_HTML = """
<h3>Kontrol Paneli</h3>
{% for f in friends %}<div>{{ f['display_name'] or f['username'] }} <a href="{{ url_for('chat',friend_id=f['id']) }}">Sohbet</a></div>{% endfor %}
"""
CHAT_HTML = """
<h3>{{ friend['display_name'] or friend['username'] }}</h3>
<div id="messages">{% for m in messages %}<div class="{{ 'me' if m['sender_id']==user['id'] else 'other' }}">{{ m['sender_username'] }}: {{ m['content'] }}</div>{% endfor %}</div>
<input id="msgInput"><button id="sendBtn">Gönder</button>
<button id="startCall">📞 Ara</button>
<button id="toggleMic">🎤</button>
<button id="toggleCam">📷</button>
<script src="//cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script>
const socket=io(),friendId={{ friend['id'] }},meId={{ user['id'] }},messagesEl=document.getElementById('messages'),input=document.getElementById('msgInput'),btn=document.getElementById('sendBtn');
let localStream=null,peer=null,micEnabled=true,camEnabled=true;
socket.on('connect',()=>{socket.emit('join_chat',{friend_id:friendId})});
socket.on('new_message',data=>{const div=document.createElement('div');div.className=data.sender_id===meId?'me':'other';div.innerHTML=data.sender_username+": "+data.content;messagesEl.appendChild(div);messagesEl.scrollTop=messagesEl.scrollHeight});
btn.onclick=()=>{const t=input.value.trim();if(!t)return;socket.emit('send_message',{to_id:friendId,content:t});input.value='';};
input.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();btn.click();}});
async function startCall(){localStream=await navigator.mediaDevices.getUserMedia({video:true,audio:true});peer=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});localStream.getTracks().forEach(t=>peer.addTrack(t,localStream));peer.ontrack=e=>{let v=document.getElementById('remoteVideo');if(!v){v=document.createElement('video');v.id='remoteVideo';v.autoplay=true;document.body.appendChild(v);}v.srcObject=e.streams[0];};peer.onicecandidate=e=>{if(e.candidate){socket.emit('webrtc_signal',{target:friendId,signal:{candidate:e.candidate}});}};const offer=await peer.createOffer();await peer.setLocalDescription(offer);socket.emit('webrtc_signal',{target:friendId,signal:{sdp:peer.localDescription}});}
socket.on('webrtc_signal',async data=>{if(!peer){peer=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});peer.ontrack=e=>{let v=document.getElementById('remoteVideo');if(!v){v=document.createElement('video');v.id='remoteVideo';v.autoplay=true;document.body.appendChild(v);}v.srcObject=e.streams[0];};peer.onicecandidate=e=>{if(e.candidate){socket.emit('webrtc_signal',{target:data.from,signal:{candidate:e.candidate}});}};} if(data.signal.sdp){await peer.setRemoteDescription(new RTCSessionDescription(data.signal.sdp));if(data.signal.sdp.type==='offer'){localStream=await navigator.mediaDevices.getUserMedia({video:true,audio:true});localStream.getTracks().forEach(t=>peer.addTrack(t,localStream));const answer=await peer.createAnswer();await peer.setLocalDescription(answer);socket.emit('webrtc_signal',{target:data.from,signal:{sdp:peer.localDescription}});}}else if(data.signal.candidate){await peer.addIceCandidate(new RTCIceCandidate(data.signal.candidate));}});
document.getElementById('startCall').onclick=startCall;
document.getElementById('toggleMic').onclick=()=>{if(!localStream)return;micEnabled=!micEnabled;localStream.getAudioTracks().forEach(t=>t.enabled=micEnabled);};
document.getElementById('toggleCam').onclick=()=>{if(!localStream)return;camEnabled=!camEnabled;localStream.getVideoTracks().forEach(t=>t.enabled=camEnabled);};
</script>
<video id="localVideo" autoplay muted></video>
"""

if __name__=="__main__":
    socketio.run(app,host='0.0.0.0',port=5000,debug=True)
