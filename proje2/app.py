from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import jwt
import os

# Ortam değişkenlerini yükle
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 30))
REDIRECT_URL = os.getenv("DASHBOARD_REDIRECT")

app = Flask(__name__)
CORS(app)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# JWT token oluştur
def generate_token(username):
    payload = {
        "user": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Kayıt
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "Kullanıcı adı ve şifre gerekli"}), 400

    user_check = session.execute(
        text("SELECT * FROM users WHERE username = :username"),
        {"username": username}
    ).fetchone()

    if user_check:
        return jsonify({"success": False, "message": "Bu kullanıcı adı zaten var"}), 409

    hashed_pw = generate_password_hash(password)
    session.execute(
        text("INSERT INTO users (username, password_hash) VALUES (:username, :pw)"),
        {"username": username, "pw": hashed_pw}
    )
    session.commit()

    return jsonify({"success": True, "message": "Kayıt başarılı"}), 201

# Giriş
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    result = session.execute(
        text("SELECT * FROM users WHERE username = :username"),
        {"username": username}
    ).fetchone()

    if result and check_password_hash(result.password_hash, password):
        token = generate_token(username)

        # Sniffer'ı biz zaten Kali'de elle başlattığımız için bu satıra gerek yok:
        # subprocess.Popen(['python', 'sniffer.py'])

        return jsonify({
            "success": True,
            "token": token,
            "redirect_url": REDIRECT_URL
        }), 200

    return jsonify({"success": False, "message": "Kullanıcı adı veya şifre hatalı"}), 401

# Token doğrulama
@app.route("/api/verify", methods=["GET"])
def verify():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"valid": False, "message": "Token eksik"}), 401

    try:
        token = auth_header.split(" ")[1]
        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"valid": True}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "message": "Token süresi doldu"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "message": "Geçersiz token"}), 401

# Uygulama başlat
if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")
