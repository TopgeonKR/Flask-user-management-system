from flask import Flask, jsonify, request, render_template_string
import sqlite3
import hashlib
import os


app = Flask(__name__)

# 랜덤 Salt 생성
def generate_salt():
    return os.urandom(16).hex()

# 비밀번호 해싱 함수
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 데이터베이스 초기화
def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, 
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# HTML 폼 (사용자 입력 페이지)
HTML_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register, Login, Reset Password, and Manage Users</title>
</head>
<body>
    <h1>Register</h1>
    <form action="/register" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Register</button>
    </form>
    
    <h1>Login</h1>
    <form action="/login" method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>

    <h1>Reset Password</h1>
    <form action="/reset-password" method="GET">
        <button type="submit">Go to Reset Password Page</button>
    </form>

    <h1>Delete User</h1>
    <form action="/delete-user" method="GET">
        <button type="submit">Go to Delete User Page</button>
    </form>

    <h1>View User List</h1>
    <form action="/list-users" method="GET">
        <button type="submit">Go to User List</button>
    </form>
</body>
</html>
"""


# HTML 폼 템플릿 (비밀번호 재설정 페이지)
RESET_PASSWORD_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
</head>
<body>
    <h1>Reset Password</h1>
    <form action="/reset-password" method="POST">
        Username: <input type="text" name="username" required><br>
        New Password: <input type="password" name="password" required><br>
        <button type="submit">Reset Password</button>
    </form>
</body>
</html>
"""

# 비밀번호 재설정 페이지 렌더링
@app.route('/reset-password', methods=['GET'])
def reset_password_form():
    return render_template_string(RESET_PASSWORD_FORM)

# HTML 폼 템플릿 (사용자 삭제 페이지)
DELETE_USER_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delete User</title>
</head>
<body>
    <h1>Delete User</h1>
    <form action="/delete-user" method="POST">
        Username: <input type="text" name="username" required><br>
        <button type="submit">Delete User</button>
    </form>
</body>
</html>
"""

# 사용자 삭제 페이지 렌더링
@app.route('/delete-user', methods=['GET'])
def delete_user_form():
    return render_template_string(DELETE_USER_FORM)


# 사용자 목록 HTML 템플릿
USER_LIST_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User List</title>
</head>
<body>
    <h1>Registered Users</h1>
    <table border="1">
        <tr>
            <th>Username</th>
            <th>Password Hash</th>
        </tr>
        {% for user in users %}
        <tr>
            <td>{{ user['username'] }}</td>
            <td>{{ user['password_hash'] }}</td>
        </tr>
        {% endfor %}
    </table>
    <br>
    <a href="/">Go Back to Home</a>
</body>
</html>
"""

# 사용자 목록 조회 API
@app.route('/list-users', methods=['GET'])
def list_users():
    # 데이터베이스에서 사용자 목록 가져오기
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT username, password_hash FROM users")
    users = [{"username": row[0], "password_hash": row[1]} for row in c.fetchall()]
    conn.close()

    # HTML 페이지 렌더링
    return render_template_string(USER_LIST_PAGE, users=users)


# 홈 화면에서 HTML 폼 제공
@app.route('/')
def home():
    return render_template_string(HTML_FORM)

# 사용자 등록 API
@app.route('/register', methods=['POST'])
def register():
    # HTML 폼에서 데이터를 받기
    if request.content_type == 'application/x-www-form-urlencoded':
        username = request.form.get('username')
        password = request.form.get('password')
        is_html_request = True
    # JSON 데이터로 받기
    elif request.content_type == 'application/json':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        is_html_request = False
    else:
        return jsonify({"message": "Unsupported Media Type"}), 415

    # Salt 생성
    salt = generate_salt()
    # Salt를 사용해 비밀번호 해싱
    password_hash = hash_password(password + salt)

    try:
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        # Salt와 해싱된 비밀번호를 저장
        c.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, password_hash, salt))
        conn.commit()
        conn.close()
        # HTML 요청일 경우 성공 페이지 렌더링
        if is_html_request:
            return "<h1>User registered successfully!</h1>"
        # JSON 요청일 경우 JSON 응답 반환
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        if is_html_request:
            return "<h1>Username already exists!</h1>", 400
        return jsonify({"message": "Username already exists!"}), 400

#로그인 API
@app.route('/login', methods=['POST'])
def login():
    # HTML 폼에서 데이터를 받기
    if request.content_type == 'application/x-www-form-urlencoded':
        username = request.form.get('username')
        password = request.form.get('password')
        is_html_request = True
    # JSON 데이터로 받기
    elif request.content_type == 'application/json':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        is_html_request = False
    else:
        return jsonify({"message": "Unsupported Media Type"}), 415

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    # Salt와 저장된 해시 값 가져오기
    c.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if row:
        stored_hash, salt = row
        # 입력된 비밀번호에 Salt를 적용해 해싱
        input_hash = hash_password(password + salt)
        if input_hash == stored_hash:
            if is_html_request:
                return f"<h1>Login successful! Welcome, {username}.</h1>"
            return jsonify({"message": "Login successful!"}), 200

    if is_html_request:
        return "<h1>Invalid username or password</h1>", 401
    return jsonify({"message": "Invalid username or password"}), 401

# Reset-Password API
@app.route('/reset-password', methods=['POST'])
def reset_password():
    # HTML 폼에서 데이터 받기
    username = request.form.get('username')
    new_password = request.form.get('password')

    # 새 Salt 생성 및 비밀번호 해싱
    salt = generate_salt()
    password_hash = hash_password(new_password + salt)

    # 데이터베이스 업데이트
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (password_hash, salt, username))
    conn.commit()
    updated_rows = c.rowcount
    conn.close()

    # 결과 반환
    if updated_rows == 0:  # 사용자 이름이 없을 경우
        return "<h1>User not found</h1>", 404

    return "<h1>Password reset successfully!</h1>", 200

#Delete-user API
@app.route('/delete-user', methods=['POST'])
def delete_user():
    # HTML 폼에서 데이터를 받기
    username = request.form.get('username')

    # 데이터베이스에서 사용자 삭제
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    deleted_rows = c.rowcount  # 삭제된 행 수 확인
    conn.close()

    # 결과 반환
    if deleted_rows == 0:  # 사용자 이름이 없을 경우
        return "<h1>User not found</h1>", 404

    return "<h1>User deleted successfully!</h1>", 200


if __name__ == '__main__':
    app.run(debug=True)
