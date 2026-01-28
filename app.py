from flask import Flask, request, redirect, session, url_for, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'quaverse-gizli-anahtar'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quaverse.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# =========================
# VERİTABANI MODELLERİ
# =========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kullanici_adi = db.Column(db.String(80), unique=True, nullable=False)
    sifre_hash = db.Column(db.String(200), nullable=False)
    rol = db.Column(db.String(20), default="izleyici")

    # 🔴 EKLENENLER (SADECE EK)
    is_muted = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)

    olusturulma_tarihi = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Mesaj(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    oda = db.Column(db.String(100))
    kullanici_adi = db.Column(db.String(80))
    icerik = db.Column(db.Text)
    zaman = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# =========================
# YARDIMCI FONKSİYONLAR
# =========================

def aktif_kullanici():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# =========================
# GİRİŞ / KAYIT
# =========================

@app.route('/')
def anasayfa():
    if 'user_id' in session:
        return redirect(url_for('panel'))
    return render_template_string(ANASAYFA_HTML)

@app.route('/kayit', methods=['GET', 'POST'])
def kayit():
    if request.method == 'POST':
        kullanici_adi = request.form['kullanici_adi']
        sifre = request.form['sifre']

        if User.query.filter_by(kullanici_adi=kullanici_adi).first():
            return "Bu kullanıcı adı zaten alınmış."

        yeni_kullanici = User(
            kullanici_adi=kullanici_adi,
            sifre_hash=generate_password_hash(sifre),
            rol="izleyici"
        )
        db.session.add(yeni_kullanici)
        db.session.commit()
        return redirect(url_for('giris'))

    return render_template_string(KAYIT_HTML)

@app.route('/giris', methods=['GET', 'POST'])
def giris():
    if request.method == 'POST':
        kullanici_adi = request.form['kullanici_adi']
        sifre = request.form['sifre']

        kullanici = User.query.filter_by(kullanici_adi=kullanici_adi).first()

        if not kullanici or not check_password_hash(kullanici.sifre_hash, sifre):
            return "Kullanıcı adı veya şifre hatalı."

        # 🔴 BAN KONTROLÜ (EK)
        if kullanici.is_banned:
            return "Bu hesap yönetici tarafından yasaklanmıştır."

        session['user_id'] = kullanici.id
        return redirect(url_for('panel'))

    return render_template_string(GIRIS_HTML)

@app.route('/cikis')
def cikis():
    session.clear()
    return redirect(url_for('anasayfa'))

# =========================
# KULLANICI PANELİ
# =========================

@app.route('/panel')
def panel():
    if 'user_id' not in session:
        return redirect(url_for('giris'))
    kullanici = aktif_kullanici()
    return render_template_string(PANEL_HTML, kullanici=kullanici)

# =========================
# HTML ŞABLONLARI (TÜRKÇE)
# =========================

ANASAYFA_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>QUAVERSE</title>
</head>
<body>
    <h1>QUAVERSE'e Hoş Geldin</h1>
    <a href="/giris">Giriş Yap</a> |
    <a href="/kayit">Kayıt Ol</a>
</body>
</html>
"""

GIRIS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Giriş Yap</title>
</head>
<body>
    <h2>Giriş Yap</h2>
    <form method="post">
        <input name="kullanici_adi" placeholder="Kullanıcı Adı"><br>
        <input type="password" name="sifre" placeholder="Şifre"><br>
        <button>Giriş</button>
    </form>
</body>
</html>
"""

KAYIT_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Kayıt Ol</title>
</head>
<body>
    <h2>Kayıt Ol</h2>
    <form method="post">
        <input name="kullanici_adi" placeholder="Kullanıcı Adı"><br>
        <input type="password" name="sifre" placeholder="Şifre"><br>
        <button>Kayıt Ol</button>
    </form>
</body>
</html>
"""

PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Kullanıcı Paneli</title>
</head>
<body>
    <h2>Hoş geldin {{ kullanici.kullanici_adi }}</h2>
    <p>Rolün: {{ kullanici.rol }}</p>

    <a href="/chat/genel">Genel Sohbet</a><br><br>
    <a href="/cikis">Çıkış Yap</a>
</body>
</html>
"""
# =========================
# SOCKET.IO OLAYLARI
# =========================

@socketio.on('odaya_katil')
def odaya_katil(data):
    oda = data.get('oda')
    join_room(oda)
    emit('durum', {
        'mesaj': f"{data.get('kullanici_adi')} odaya katıldı."
    }, room=oda)

@socketio.on('odadan_cik')
def odadan_cik(data):
    oda = data.get('oda')
    leave_room(oda)
    emit('durum', {
        'mesaj': f"{data.get('kullanici_adi')} odadan çıktı."
    }, room=oda)

@socketio.on('mesaj_gonder')
def mesaj_gonder(data):
    kullanici = aktif_kullanici()
    if not kullanici:
        return

    # 🔴 MUTE KONTROLÜ
    if kullanici.is_muted:
        emit('hata', {
            'mesaj': 'Yönetici tarafından susturuldun.'
        })
        return

    oda = data.get('oda')
    icerik = data.get('icerik')

    yeni_mesaj = Mesaj(
        oda=oda,
        kullanici_adi=kullanici.kullanici_adi,
        icerik=icerik
    )
    db.session.add(yeni_mesaj)
    db.session.commit()

    emit('mesaj_al', {
        'kullanici_adi': kullanici.kullanici_adi,
        'icerik': icerik,
        'zaman': yeni_mesaj.zaman.strftime("%H:%M")
    }, room=oda)

# =========================
# SOHBET ROUTE
# =========================

@app.route('/chat/<oda>')
def sohbet(oda):
    if 'user_id' not in session:
        return redirect(url_for('giris'))

    mesajlar = Mesaj.query.filter_by(oda=oda).all()
    kullanici = aktif_kullanici()
    return render_template_string(
        SOHBET_HTML,
        oda=oda,
        mesajlar=mesajlar,
        kullanici=kullanici
    )

# =========================
# WEBRTC + STUN (JS)
# =========================

WEBRTC_JS = """
<script>
let yerelAkis;
let baglanti;

const rtcAyarlar = {
    iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
        { urls: "stun:global.stun.twilio.com:3478" }
    ]
};

async function medyaBaslat() {
    yerelAkis = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    document.getElementById("yerelVideo").srcObject = yerelAkis;
}

async function aramaBaslat() {
    baglanti = new RTCPeerConnection(rtcAyarlar);

    yerelAkis.getTracks().forEach(track => {
        baglanti.addTrack(track, yerelAkis);
    });

    baglanti.ontrack = event => {
        document.getElementById("uzakVideo").srcObject = event.streams[0];
    };
}

function aramaBitir() {
    if (baglanti) {
        baglanti.close();
        baglanti = null;
    }
}
</script>
"""

# =========================
# SOHBET HTML (TÜRKÇE UI)
# =========================

SOHBET_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>QUAVERSE Sohbet</title>
    <style>
        body {
            background:#0e0e1a;
            color:#ffffff;
            font-family:Arial;
        }
        .sohbet-kutu {
            height:300px;
            overflow-y:auto;
            border:1px solid #333;
            padding:10px;
        }
        .kontroller {
            margin-top:10px;
        }
        video {
            width:200px;
            border:1px solid #555;
            margin-right:5px;
        }
    </style>
</head>
<body>

<h2>Oda: {{ oda }}</h2>

<div class="sohbet-kutu" id="sohbetKutu">
{% for m in mesajlar %}
    <p><b>{{ m.kullanici_adi }}:</b> {{ m.icerik }}</p>
{% endfor %}
</div>

<div class="kontroller">
    <input id="mesajInput" placeholder="Mesaj yaz...">
    <button onclick="mesajGonder()">Gönder</button>
</div>

<hr>

<h3>Görüntülü Görüşme</h3>
<video id="yerelVideo" autoplay muted></video>
<video id="uzakVideo" autoplay></video><br><br>

<button onclick="medyaBaslat()">Kamerayı Aç</button>
<button onclick="aramaBaslat()">Aramayı Başlat</button>
<button onclick="aramaBitir()">Aramayı Bitir</button>

<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<script>
const socket = io();

socket.emit('odaya_katil', {
    oda: "{{ oda }}",
    kullanici_adi: "{{ kullanici.kullanici_adi }}"
});

function mesajGonder() {
    const mesaj = document.getElementById("mesajInput").value;
    socket.emit('mesaj_gonder', {
        oda: "{{ oda }}",
        icerik: mesaj
    });
    document.getElementById("mesajInput").value = "";
}

socket.on('mesaj_al', data => {
    const kutu = document.getElementById("sohbetKutu");
    kutu.innerHTML += `<p><b>${data.kullanici_adi}:</b> ${data.icerik}</p>`;
    kutu.scrollTop = kutu.scrollHeight;
});

socket.on('hata', data => {
    alert(data.mesaj);
});
</script>

{{ webrtc|safe }}

</body>
</html>
"""
# =========================
# ADMIN YETKİ KONTROLÜ
# =========================

def admin_mi():
    kullanici = aktif_kullanici()
    return kullanici and kullanici.rol == "admin"

# =========================
# ADMIN PANEL ROUTE
# =========================

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('giris'))

    if not admin_mi():
        return "Bu sayfaya erişim yetkin yok."

    kullanicilar = User.query.all()
    return render_template_string(
        ADMIN_HTML,
        kullanicilar=kullanicilar
    )

# =========================
# ADMIN AKSİYONLARI
# =========================

@app.route('/admin/mute/<int:kullanici_id>')
def admin_mute(kullanici_id):
    if not admin_mi():
        return "Yetkisiz işlem."

    u = User.query.get(kullanici_id)
    u.is_muted = True
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/unmute/<int:kullanici_id>')
def admin_unmute(kullanici_id):
    if not admin_mi():
        return "Yetkisiz işlem."

    u = User.query.get(kullanici_id)
    u.is_muted = False
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/ban/<int:kullanici_id>')
def admin_ban(kullanici_id):
    if not admin_mi():
        return "Yetkisiz işlem."

    u = User.query.get(kullanici_id)
    u.is_banned = True
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/unban/<int:kullanici_id>')
def admin_unban(kullanici_id):
    if not admin_mi():
        return "Yetkisiz işlem."

    u = User.query.get(kullanici_id)
    u.is_banned = False
    db.session.commit()
    return redirect(url_for('admin_panel'))

# =========================
# ADMIN PANEL HTML (TÜRKÇE UI)
# =========================

ADMIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>QUAVERSE Admin Paneli</title>
    <style>
        body {
            background:#0e0e1a;
            color:#fff;
            font-family:Arial;
        }
        table {
            width:100%;
            border-collapse:collapse;
        }
        th, td {
            border:1px solid #333;
            padding:8px;
            text-align:center;
        }
        th {
            background:#1a1a2e;
        }
        a {
            color:#4da6ff;
            text-decoration:none;
            margin:0 5px;
        }
        .yasakli {
            color:red;
        }
        .susturulmus {
            color:orange;
        }
    </style>
</head>
<body>

<h2>🔐 QUAVERSE Ana Admin Paneli</h2>

<table>
<tr>
    <th>ID</th>
    <th>Kullanıcı Adı</th>
    <th>Rol</th>
    <th>Durum</th>
    <th>İşlemler</th>
</tr>

{% for u in kullanicilar %}
<tr>
    <td>{{ u.id }}</td>
    <td>{{ u.kullanici_adi }}</td>
    <td>{{ u.rol }}</td>
    <td>
        {% if u.is_banned %}
            <span class="yasakli">Yasaklı</span>
        {% elif u.is_muted %}
            <span class="susturulmus">Susturulmuş</span>
        {% else %}
            Aktif
        {% endif %}
    </td>
    <td>
        {% if not u.is_muted %}
            <a href="/admin/mute/{{ u.id }}">Sustur</a>
        {% else %}
            <a href="/admin/unmute/{{ u.id }}">Susturmayı Kaldır</a>
        {% endif %}

        {% if not u.is_banned %}
            <a href="/admin/ban/{{ u.id }}">Yasakla</a>
        {% else %}
            <a href="/admin/unban/{{ u.id }}">Yasağı Kaldır</a>
        {% endif %}
    </td>
</tr>
{% endfor %}
</table>

<br>
<a href="/panel">⬅ Kullanıcı Paneline Dön</a>

</body>
</html>
"""
