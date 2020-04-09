from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from flask_marshmallow import Marshmallow
import os
from flask_bcrypt import Bcrypt
import jwt

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


# pw_hash = bcrypt.generate_password_hash('hunter2')
# bcrypt.check_password_hash(pw_hash, 'hunter2') # returns True

# =================================ROUTES===============================================
@app.route('/sign-up', methods=['POST'])
def create_new_user():
    data = request.get_json()

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('UTF-8')
    new_user = Users(email=data['email'], password=hashed_password, public_id=str(uuid.uuid4()))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New User created'})


@app.route('/', methods=['GET'])
def send_welcome_message():
    return jsonify({'msg': 'Welcome, API Created By Darko Awuah Jackson'})


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()

    if not auth or not auth['email'] or not auth['password']:
        make_response('could not verify user', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = Users.query.filter_by(email=auth['email']).first()

    if not user:
        return make_response('Email is not registered', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if bcrypt.check_password_hash(user.password, auth['password']):
        token = jwt.encode({'public_id': user.public_id}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
        # return jsonify({'meg': "Done"})

    return make_response('Password not right', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


# Run Server
if __name__ == '__main__':
    app.run(debug=True)
