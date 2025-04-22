from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import jwt
import datetime

app = Flask(__name__)
CORS(app)  # Allows requests from frontend
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'supersecretkey123'  # Replace with env var for production

# In-memory user store
users = {}

@app.route('/')
def home():
    return "Gestura Auth Backend Running 🚀"

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'error': 'Missing fields'}), 400

    if email in users:
        return jsonify({'error': 'Email already exists'}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    users[email] = {'name': name, 'email': email, 'password': hashed_pw}
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users.get(email)
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {'name': user['name'], 'email': user['email']}
    })

@app.route('/api/verify', methods=['POST'])
def verify_token():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': 'Token missing'}), 400

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = payload['email']
        user = users.get(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'valid': True, 'user': {'name': user['name'], 'email': user['email']}})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(debug=True)
