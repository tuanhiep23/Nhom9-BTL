from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import base64
import os
import logging
import re
from datetime import datetime

# Import các hàm mã hóa và khóa từ module mới
from MultipleFiles.cipher_utils import (
    caesar_cipher_decrypt,
    vigenere_cipher_decrypt,
    rsa_decrypt,
    aes_decrypt,
    rsa_encrypt,
    aes_encrypt,
    rsa_public_key,
    rsa_private_key,
    generate_and_save_keys
)

app = Flask(__name__)
CORS(app, origins=["http://localhost:5000"])
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    print("WARNING: SECRET_KEY environment variable not set. Using a temporary key for development.")
    app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lấy khóa AES từ biến môi trường
AES_KEY = base64.b64decode(os.getenv('AES_KEY', base64.b64encode(os.urandom(16)).decode()))
if len(AES_KEY) != 16:
    raise ValueError("AES_KEY phải là chuỗi base64 đại diện cho khóa 16 byte!")

# Database Model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    score = db.Column(db.Integer, default=0)
    current_level = db.Column(db.Integer, default=1)
    attempts = db.relationship('UserAttempt', backref='user', lazy=True)

class UserAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    attempts_left = db.Column(db.Integer, default=5)
    last_attempt = db.Column(db.DateTime, nullable=True)

# Create database tables
with app.app_context():
    db.create_all()

LEVELS = [
    {
        "level": 1,
        "algorithm": "caesar",
        "ciphertext": "KhoiF, Zruog!",
        "correct_output": "Hello, World!",
        "hint": "Số bước dịch là số ngọn nến trong hang động (thử số nhỏ).",
        "story": "Bạn tìm thấy một mẩu giấy cổ trong hang động, ghi thông điệp bí ẩn dẫn đến kho báu.",
        "solution_param": 3
    },
    {
        "level": 2,
        "algorithm": "vigenere",
        "ciphertext": "Rijvs, Uyvzr!",
        "correct_output": "Hello, World!",
        "hint": "Từ khóa là tên của vị thần bảo vệ ngôi đền (3 chữ cái).",
        "story": "Thông điệp dẫn bạn đến ngôi đền cổ, nơi ẩn chứa câu đố phức tạp hơn.",
        "solution_param": "KEY"
    },
    {
        "level": 3,
        "algorithm": "rsa",
        "ciphertext": base64.b64encode(rsa_encrypt(rsa_public_key, "Find the key!")).decode(),
        "correct_output": "Find the key!",
        "hint": "Khóa riêng được khắc trên tường ngôi đền, cần định dạng đúng. (Gợi ý: Khóa RSA là một chuỗi dài, bắt đầu bằng '-----BEGIN RSA PRIVATE KEY-----')",
        "story": "Trong ngôi đền, bạn tìm thấy một chiếc hộp khóa bằng mật mã số học.",
        "solution_param": rsa_private_key.decode()
    },
    {
        "level": 4,
        "algorithm": "aes",
        "ciphertext": base64.b64encode(aes_encrypt(AES_KEY, "You found the treasure!")).decode(),
        "correct_output": "You found the treasure!",
        "hint": "Khóa AES là mật khẩu cuối cùng, ẩn trong câu đố của chiếc hộp. (Gợi ý: Khóa AES là một chuỗi base64 ngắn gọn)",
        "story": "Chiếc hộp mở ra, tiết lộ vị trí kho báu, nhưng cần giải mã lần cuối!",
        "solution_param": base64.b64encode(AES_KEY).decode()
    }
]

@app.route('/register', methods=['POST'])
def register():
    """Đăng ký người dùng mới."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not username or not password or not confirm_password:
        return jsonify({"error": "Tên người dùng, mật khẩu và xác nhận mật khẩu không được để trống!"}), 400
    if password != confirm_password:
        return jsonify({"error": "Mật khẩu không khớp!"}), 400
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
        return jsonify({"error": "Tên người dùng phải dài 3-20 ký tự, chỉ chứa chữ cái, số, dấu gạch dưới hoặc dấu gạch ngang!"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mật khẩu phải có ít nhất 6 ký tự!"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Tên người dùng đã tồn tại!"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"User registered: {username}")
    return jsonify({"message": "Đăng ký thành công!"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Đăng nhập người dùng."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Tên người dùng hoặc mật khẩu không đúng!"}), 401

    session['user_id'] = user.id
    session['username'] = user.username
    logger.info(f"User logged in: {username}")
    return jsonify({
        "message": "Đăng nhập thành công!",
        "username": user.username,
        "score": user.score,
        "current_level": user.current_level
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    """Đăng xuất người dùng."""
    username = session.get('username', 'Guest')
    session.pop('user_id', None)
    session.pop('username', None)
    logger.info(f"User logged out: {username}")
    return jsonify({"message": "Đăng xuất thành công!"}), 200

@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    """Lấy thông tin người dùng."""
    if 'user_id' not in session:
        return jsonify({"error": "Chưa đăng nhập!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB but in session.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404
    return jsonify({
        "username": user.username,
        "score": user.score,
        "current_level": user.current_level
    }), 200

@app.route('/reset', methods=['POST'])
def reset_game():
    """Đặt lại trò chơi cho người dùng."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB during reset.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404
    user.score = 0
    user.current_level = 1
    UserAttempt.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    logger.info(f"Game reset for user: {user.username}")
    return jsonify({"message": "Trò chơi đã được đặt lại!", "score": 0, "current_level": 1}), 200

@app.route('/level/<int:level>', methods=['GET'])
def get_level(level):
    """Lấy thông tin cấp độ, kiểm tra quyền truy cập."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB when getting level.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404

    if level > user.current_level:
        return jsonify({"error": "Bạn chưa mở khóa cấp độ này!"}), 403
    if level < 1 or level > len(LEVELS):
        return jsonify({"error": "Cấp độ không hợp lệ!"}), 400

    level_data = LEVELS[level-1]
    attempt = UserAttempt.query.filter_by(user_id=user.id, level=level).first()
    attempts_left = 5 if not attempt else attempt.attempts_left
    return jsonify({
        "level": level_data["level"],
        "algorithm": level_data["algorithm"],
        "ciphertext": level_data["ciphertext"],
        "hint": level_data["hint"],
        "story": level_data["story"],
        "points": user.score,
        "current_user_level": user.current_level,
        "attempts_left": attempts_left
    })

@app.route('/decode/<int:level>', methods=['POST'])
def decode(level):
    """Xử lý giải mã thông điệp và cập nhật điểm số."""
    if 'user_id' not in session:
        return jsonify({"error": "Vui lòng đăng nhập để chơi!"}), 401
    if level < 1 or level > len(LEVELS):
        return jsonify({"error": "Cấp độ không hợp lệ!"}), 400

    data = request.json
    submitted_ciphertext = data.get('ciphertext')
    submitted_param = data.get('param')

    level_data = LEVELS[level-1]
    user = User.query.get(session['user_id'])
    if not user:
        logger.error(f"User ID {session['user_id']} not found in DB during decode.")
        session.clear()
        return jsonify({"error": "Người dùng không tồn tại hoặc phiên không hợp lệ!"}), 404

    if level > user.current_level:
        return jsonify({"error": "Bạn chưa mở khóa cấp độ này!"}), 403

    if submitted_ciphertext != level_data["ciphertext"]:
        return jsonify({"success": False, "message": "Thông điệp mã hóa không khớp với cấp độ hiện tại!"}), 400

    attempt = UserAttempt.query.filter_by(user_id=user.id, level=level).first()
    if not attempt:
        attempt = UserAttempt(user_id=user.id, level=level, attempts_left=5)
        db.session.add(attempt)
    if attempt.attempts_left <= 0:
        return jsonify({"success": False, "message": "Bạn đã hết số lần thử cho cấp độ này! Vui lòng đặt lại trò chơi."}), 403
    attempt.attempts_left -= 1
    attempt.last_attempt = datetime.utcnow()
    db.session.commit()

    try:
        decrypted_result = ""
        solution_param = level_data["solution_param"]

        if level_data["algorithm"] == "caesar":
            if not submitted_param or not submitted_param.isdigit() or not (1 <= int(submitted_param) <= 25):
                return jsonify({"success": False, "message": "Độ dịch chuyển phải là số nguyên từ 1 đến 25!", "attempts_left": attempt.attempts_left}), 400
            decrypted_result = caesar_cipher_decrypt(submitted_ciphertext, int(submitted_param))
        elif level_data["algorithm"] == "vigenere":
            if not submitted_param or not re.match(r'^[a-zA-Z]+$', submitted_param):
                return jsonify({"success": False, "message": "Từ khóa chỉ được chứa chữ cái!", "attempts_left": attempt.attempts_left}), 400
            decrypted_result = vigenere_cipher_decrypt(submitted_ciphertext, submitted_param)
        elif level_data["algorithm"] == "rsa":
            if not submitted_param or not submitted_param.strip().startswith('-----BEGIN RSA PRIVATE KEY-----'):
                return jsonify({"success": False, "message": "Khóa RSA không hợp lệ. Phải bắt đầu bằng '-----BEGIN RSA PRIVATE KEY-----'!", "attempts_left": attempt.attempts_left}), 400
            try:
                encrypted_message_bytes = base64.b64decode(submitted_ciphertext)
                decrypted_result = rsa_decrypt(submitted_param.encode(), encrypted_message_bytes)
            except Exception as e:
                logger.error(f"RSA decryption error for user {user.username} at level {level}: {e}")
                return jsonify({"success": False, "message": f"Khóa RSA không hợp lệ: {str(e)}", "attempts_left": attempt.attempts_left}), 400
        elif level_data["algorithm"] == "aes":
            if not submitted_param:
                return jsonify({"success": False, "message": "Khóa AES không được để trống!", "attempts_left": attempt.attempts_left}), 400
            try:
                aes_key_bytes_from_param = base64.b64decode(submitted_param)
                if len(aes_key_bytes_from_param) != 16:
                    return jsonify({"success": False, "message": "Khóa AES phải là 16 byte sau khi giải mã base64!", "attempts_left": attempt.attempts_left}), 400
                iv_and_ciphertext_bytes = base64.b64decode(submitted_ciphertext)
                decrypted_result = aes_decrypt(aes_key_bytes_from_param, iv_and_ciphertext_bytes)
            except Exception as e:
                logger.error(f"AES decryption error for user {user.username} at level {level}: {e}")
                return jsonify({"success": False, "message": f"Khóa AES không hợp lệ: {str(e)}", "attempts_left": attempt.attempts_left}), 400
        else:
            return jsonify({"success": False, "message": "Thuật toán không hỗ trợ!", "attempts_left": attempt.attempts_left}), 400

        if decrypted_result == level_data["correct_output"]:
            points_earned = 100 * level
            user.score += points_earned
            if level == user.current_level:
                user.current_level = level + 1 if level < len(LEVELS) else level
            attempt.attempts_left = 5  # Reset attempts on success
            db.session.commit()
            logger.info(f"User {user.username} successfully decoded level {level}. Score: {user.score}")
            return jsonify({
                "success": True,
                "message": f"Thông điệp đã được giải mã thành công! Kết quả: {decrypted_result}",
                "points_earned": points_earned,
                "total_points": user.score,
                "next_level": user.current_level if user.current_level > level else None,
                "attempts_left": attempt.attempts_left
            })
        else:
            logger.info(f"User {user.username} failed to decode level {level}. Incorrect output.")
            return jsonify({
                "success": False,
                "message": f"Giải mã không chính xác. Còn {attempt.attempts_left} lần thử!",
                "attempts_left": attempt.attempts_left
            })
    except Exception as e:
        logger.error(f"Unhandled decryption error for user {user.username} at level {level}: {e}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi hệ thống: {str(e)}", "attempts_left": attempt.attempts_left}), 500

@app.route('/')
def index():
    """Render giao diện chính."""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)