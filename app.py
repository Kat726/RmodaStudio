from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.datastructures import Headers
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore
from functools import wraps
import requests
from requests.structures import CaseInsensitiveDict

cred = credentials.Certificate('firebase.json')
firebase_admin.initialize_app(cred)

db = firestore.client()

app = Flask(__name__)
app.secret_key = "apl1k4s1kuY"

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' in session:
            return f(*args, **kwargs)
        else:
            flash('Anda harus login', 'danger')
            return redirect(url_for('login'))
    return wrapper

def send_wa(m, p):
    api = "2df45e9c2a80a3d92cfce80e96b305ca2368a75b"
    url = "https://starsender.online/api/sendText"
    
    data = {
        "tujuan": p,
        "message": m
    }

    headers = CaseInsensitiveDict()
    headers['apikey'] = api
    
    res = request.post(url, json=data, header=headers)
    return res.text

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    #menetukan method
    if request.method == "POST":
    #ambil data dari form
        data = {
        "email": request.form["email"],
        "password": request.form["password"]
        }
        #lakukan pengecekan
        users = db.collection("users").where("email", "==", data["email"]).stream()
        user  = {}
    
        for us in users:
            user = us.to_dict()
    
        if user:
            if check_password_hash(user["password"], data["password"]):
                session["user"] = user
                flash('Selamat anda berhasil login', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Maaf password anda salah', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Email belum terdaftar', 'danger')
            return redirect(url_for('login'))

    if 'user' in session:
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Anda belum login', 'danger')
        return redirect(url_for('login'))
    return render_template("login.html")
   
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/mahasiswa')
def mahasiswa():
    # panggil data di database
    # lakukan pengulangan terhadap data
    # simpan data yang sudah di ulang di dalam sebuah array
    maba = db.collection("mahasiswa").stream()
    mb = []

    for mhs in maba:
        m = mhs.to_dict()
        m["id"] = mhs.id
        mb.append(m)    
    
    return render_template('mahasiswa.html', data=mb)
    # return jsonify(mb)

@app.route('/mahasiswa/tambah', methods=["GET", "POST"])
def tambah_mhs():
    if request.method == 'POST':
        data = {
            "nama": request.form["nama"],
            "email": request.form["email"],
            "nim": request.form["nim"],
            "jurusan": request.form["jurusan"]
        }
        # ini adalah fungsi firebase untuk menambahkan data
        db.collection("mahasiswa").document().set(data)
        send_wa(f"Halo *{data['nama_lengkap']}* Selamat Siang kakak", data["no_hp"])
        flash('Berhasil Tambah Mahasiswa', 'success')
        return redirect(url_for('mahasiswa'))
    return render_template('add_mhs.html')

@app.route('/mahasiswa/hapus/<uid>')
def hapus_mhs(uid):
    db.collection('mahasiswa').document(uid).delete()
    flash('berhasil hapus data', 'danger')
    return redirect(url_for('mahasiswa'))

@app.route('/mahasiswa/lihat/<uid>')
def lihat_mhs(uid):
    # memanggil datanya di database
    user = db.collection('mahasiswa').document(uid).get().to_dict()
    # db.collection('mahasiswa').document(uid).delete()
    return render_template('lihat_mhs.html', user=user)

@app.route('/mahasiswa/ubah/<uid>', methods=["GET", "POST"])
def ubah_mhs(uid):
    # menentukan method
    if request.method == "POST":
        data = {
            "nama": request.form["nama"],
            "email": request.form["email"],
            "nim": request.form["nim"],
            "jurusan": request.form["jurusan"]
        }

        db.collection('mahasiswa').document(uid).set(data, merge=True)
        flash('Berhasil ubah data', 'success')
        return redirect(url_for('mahasiswa'))
    # menerima data baru
    # set di database

    # mengambil data
    user = db.collection('mahasiswa').document(uid).get().to_dict()
    user['id'] = uid
    # render template
    return render_template('ubah_mhs.html', user=user)

@app.route('/register',methods=["GET", "POST"])
def register():
    # cek dulu methodnya
    if request.method == "POST":
    # if post
        # ambil data dari form
        data = {
            "nama_lengkap": request.form["nama_lengkap"],
            "email": request.form["email"],
            "no_hp": request.form["no_hp"]
        }
        users = db.collection('users').where('email', '==', data['email']).stream()
        user = {}    
        for us in users:
            user = us.to_dict()
        if user:
            flash('email sudah terdaftar', 'danger')
            return redirect(url_for('register'))

        data['password'] = generate_password_hash(request.form['password'], 'sha256')
        # kita masukkan datanya ke database
        db.collection('users').document().set(data)
        flash('Berhasil Register', 'success')
        # redirect ke halaman login
        return redirect(url_for('login'))

    # menampilkan halaman register
    return render_template('register.html')


if __name__ == "__main__":
    app.run(debug=True)