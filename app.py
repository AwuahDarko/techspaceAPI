from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from flask_marshmallow import Marshmallow
import os
from flask_bcrypt import Bcrypt
import jwt
from functools import wraps

# Init app
app = Flask(__name__)
bcrypt = Bcrypt(app)

# app.config.from_object(os.environ['APP_SETTINGS'])
pg_user = "darko"
pg_pwd = "12345"
pg_port = "5432"
app.config['SECRET_KEY'] = '&&!^@(##)**09864345123'
app.config["SQLALCHEMY_DATABASE_URI"] = \
    "postgresql://{username}:{password}@localhost:{port}/techspace".format(username=pg_user, password=pg_pwd,
                                                                           port=pg_port)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from models import Users
from models import Interests


# ==================== UTILS ================================================
def verify_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return make_response('Forbidden', 403)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            create_user = Users.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid'}), 401
        return f(create_user, *args, *kwargs)

    return decorated


# =================================ROUTES===============================================
# ====================== WELCOME ========================================
@app.route('/api', methods=['GET'])
def send_welcome_message():
    return jsonify({'msg': 'Welcome, API Created By Darko Awuah Jackson'})


# ===================== SIGN UP ==================================
@app.route('/api/sign-up', methods=['POST'])
def create_new_user():
    try:
        data = request.get_json()
        if not data:
            raise Exception("Bad request format, JSON required")
    except Exception as e:
        return make_response(str(e), 400)
    else:
        existing_user = Users.query.filter_by(email=data['email']).first()
        if not existing_user:
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('UTF-8')
            new_user = Users(email=data['email'], password=hashed_password, public_id=str(uuid.uuid4()))
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'New User created'})
        else:
            return make_response('Email is already registered', 400)


# ========================= LOGIN ==================================
@app.route('/api/login', methods=['POST'])
def login():
    try:
        auth = request.get_json()
        if not auth:
            raise Exception("Bad request format, JSON required")
    except Exception as e:
        return make_response(str(e), 400)
    else:
        if not auth or not auth['email'] or not auth['password']:
            return make_response('could not verify user', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        user = Users.query.filter_by(email=auth['email']).first()

        if not user:
            return make_response('Email is not registered', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if bcrypt.check_password_hash(user.password, auth['password']):
            token = jwt.encode({'public_id': user.public_id}, app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})

        return make_response('Password not right', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


# ===================== ADD INTEREST ============================================
@app.route('/api/interest', methods=['POST'])
@verify_token
def add_interest(current_user):
    if current_user.admin == 'No':
        return jsonify({'message': 'You are not authorized to do this'}), 401
    try:
        data = request.get_json()
        if not data:
            raise Exception("Bad request format, JSON required")
    except Exception as e:
        return make_response(str(e), 400)
    else:
        existing_interest = Interests.query.filter_by(interest_name=data['interest']).first()

        if not existing_interest:
            new_interest = Interests(name=data['interest'])
            db.session.add(new_interest)
            db.session.commit()
            return jsonify({'message': 'New Interest created'}), 200

        return jsonify({'message': 'This Interest already exist'}), 400


# =========================== INTEREST ===================================
@app.route('/api/interest', methods=['GET'])
# @verify_token
def get_all_interests():
    interests = Interests.query.all()
    output = []

    for interest in interests:
        interest_data = {'id': interest.interest_id, 'name': interest.interest_name}
        output.append(interest_data)

    return jsonify(output)


@app.route('/api/interest', methods=['DELETE'])
@verify_token
def delete_interest(current_user):
    if current_user.admin == 'No':
        return jsonify({'message': 'You are not authorized to do this'}), 401

    interest_id = request.args.get('interest_id')
    if not interest_id:
        return jsonify({'message': 'specify which interest'}), 400

    interest = Interests.query.filter_by(interest_id=interest_id).first()

    if not interest:
        return jsonify({"message": 'Interest exist not'})

    db.session.delete(interest)
    db.session.commit()

    return jsonify({'message': 'Interest deleted'})


@app.route('/api/interest', methods=['PATCH'])
@verify_token
def update_interest(current_user):
    if current_user.admin == 'No':
        return jsonify({'message': 'You are not authorized to do this'}), 401

    try:
        data = request.get_json()
        if not data or not data['interest_id'] or not data['interest_name']:
            raise Exception("Bad request format, JSON required")
    except Exception as e:
        return make_response(str(e), 400)
    else:
        interest = Interests.query.filter_by(interest_id=data['interest_id']).first()

        if interest is None:
            return jsonify({'message': 'Interest exist not'}), 400

        interest.interest_name = data['interest_name']
        db.session.commit()

        return jsonify({'message': 'Interest updated'})


@app.route('/api/interest-single', methods=['GET'])
def get_one_interest():
    interest_id = request.args.get('interest_id')

    if not interest_id:
        return jsonify({'message': 'specify which interest'}), 400

    interest = Interests.query.filter_by(interest_id=interest_id).first()
    if interest is None:
        return jsonify({'message': 'Interest exit not'}), 400
    interest_data = {'id': interest.interest_id, 'name': interest.interest_name}

    return jsonify(interest_data)


# Run Server
if __name__ == '__main__':
    app.run(debug=True)
