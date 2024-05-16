from flask import Flask, request, redirect, url_for, render_template, make_response
import hashlib
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# Конфигурация (логин и хешированный пароль)
ADMIN_LOGIN = 'admin'
ADMIN_PASSWORD_HASH = hashlib.sha256('your_password'.encode()).hexdigest()

# Создание подключения к базе данных
def get_db_connection():
    conn = sqlite3.connect('passwords.db')
    conn.row_factory = sqlite3.Row
    return conn 

# Функции шифрования и дешифрования
def encrypt_password(password, key):
    key = hashlib.sha256(key).digest()  # Хешируем ключ для получения длины 32 байта
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(password.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return f'{iv}:{ct}'

def decrypt_password(enc_password, key):
    key = hashlib.sha256(key).digest()  # Хешируем ключ для получения длины 32 байта
    try:
        iv, ct = enc_password.split(':')
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        return None

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if username != ADMIN_LOGIN:
        return render_template('error.html')

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash != ADMIN_PASSWORD_HASH:
        return render_template('error.html')

    resp = make_response(redirect(url_for('protected')))
    resp.set_cookie('auth', password_hash)
    resp.set_cookie('key', base64.b64encode(password.encode()).decode('utf-8'))
    return resp

@app.route('/protected', methods=['GET', 'POST'])
def protected():
    auth_cookie = request.cookies.get('auth')

    if auth_cookie != ADMIN_PASSWORD_HASH:
        return redirect(url_for('home'))

    error = None
    key = base64.b64decode(request.cookies.get('key'))

    if request.method == 'POST':
        site = request.form.get('site')
        login = request.form.get('login')
        password = request.form.get('password')

        if not site or not login or not password:
            error = "All fields are required."
        else:
            encrypted_password = encrypt_password(password, key)
            conn = get_db_connection()
            conn.execute('INSERT INTO passwords (site, login, password) VALUES (?, ?, ?)',
                         (site, login, encrypted_password))
            conn.commit()
            conn.close()

    passwords = get_passwords(key)
    return render_template('protected.html', passwords=passwords, error=error)

@app.route('/delete_password', methods=['POST'])
def delete_password():
    auth_cookie = request.cookies.get('auth')

    if auth_cookie != ADMIN_PASSWORD_HASH:
        return redirect(url_for('home'))

    password_id = request.form.get('id')
    conn = get_db_connection()
    conn.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('protected'))

def get_passwords(key):
    conn = get_db_connection()
    encrypted_passwords = conn.execute('SELECT id, site, login, password FROM passwords').fetchall()
    conn.close()

    passwords = []
    for row in encrypted_passwords:
        decrypted_password = decrypt_password(row['password'], key)
        if decrypted_password is not None:
            passwords.append({'id': row['id'], 'site': row['site'], 'login': row['login'], 'password': decrypted_password})

    return passwords

if __name__ == '__main__':
    app.run(debug=True)
