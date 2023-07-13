from flask import Flask, request, jsonify
from passlib.hash import sha256_crypt
import sqlite3
import secrets
import re

app = Flask(__name__)
DATABASE = 'database.db'

def message(message: str, status_code: int):
    return jsonify({'message': message}), status_code

def error(message: str, status_code: int):
    return jsonify({'error': message}), status_code

def verify_password(password):
    letter_regex = r'[a-zA-Z]'
    number_regex = r'\d'

    letter_count = len(re.findall(letter_regex, password))
    number_count = len(re.findall(number_regex, password))

    return letter_count >= 5 and number_count >= 2

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.route('/register', methods=['POST'])
def register():
    # Get the username and password from the request
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return error('Username and password are required.', 400)
    if not verify_password(password):
        return error(f'Password must contain 5 letters and 2 numbers. {verify_password(password)}', 400)
    
    # Check if the username already exists
    db = get_db()
    existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if existing_user:
        return error('Username already exists.', 400)

    # Generate a random salt and hash the password with the salt
    salt = secrets.token_hex(16)
    hashed_password = sha256_crypt.hash(password + salt)

    # Insert the user into the database
    db.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (username, hashed_password, salt))
    db.commit()
    return message('User registered successfully.', 200)


@app.route('/login', methods=['POST'])
def login():
    # Get the username and password from the request
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return error('Username and password are required.', 400)

    # Check if the user exists
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        return error('Invalid username or password.', 400)

    # Check if the password is correct
    hashed_password = sha256_crypt.hash(password + user['salt'])
    if not sha256_crypt.verify(password + user['salt'], user['password']):
        return error('Invalid username or password.', 400)
    return message('User logged in successfully.', 200)


@app.route('/change_password', methods=['POST'])
def change_password():
    # Get the username, old password, and new password from the request
    username = request.json.get('username')
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')
    if not username or not old_password or not new_password:
        return error('Username, old password, and new password are required.', 400)
    if not verify_password(new_password):
        return error('New password must contain 5 letters and 2 numbers.', 400)

    # Check if the user exists and if the old password is correct
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        return error('Invalid username or password.', 400)
    if not sha256_crypt.verify(old_password + user['salt'], user['password']):
        return error('Invalid username or password.', 400)

    # Generate a new random salt and hash the new password with the salt
    salt = secrets.token_hex(16)
    hashed_password = sha256_crypt.hash(new_password + salt)
    db.execute('UPDATE users SET password = ?, salt = ? WHERE username = ?', (hashed_password, salt, username))
    db.commit()
    return message('Password changed successfully.', 200)


if __name__ == '__main__':
    app.run(debug=True)
