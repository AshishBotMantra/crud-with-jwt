import jwt
from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime,timedelta, timezone
from functools import wraps
from models import db,User
from schema import UserSchema,user_schema,users_schema,ma

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
db.init_app(app)
ma.init_app(app)


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'x-acces-token' in request.headers:
            token = request.headers['x-acces-token']
        if not token:
            return jsonify({"message":"token in missing"}), 401
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms='HS256')
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message":"token is invalid"}), 401

        return f(current_user,*args,**kwargs)
    return decorated


@app.before_first_request
def create():
    db.create_all()

@app.route('/user',methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({"message":"cannot perform that function"})
    get_users = User.query.all()
    result = users_schema.dump(get_users)
    return jsonify(result)

@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({"message":"cannot perform that function"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":"no user found"})
    return user_schema.jsonify(user)

@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message":"cannot perform that function"})
    data = request.json['password']
    name = request.json['name']
    hashed_password = generate_password_hash(data, method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=name,password=hashed_password,admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message":"new user created"})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message":"cannot perform that function"})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "no user found"})

    user.admin = True
    db.session.commit()
    return jsonify({"message":"user has been promoted"})

@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({"message":"cannot perform that function"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":"user has been deleted"})

@app.route('/login')

def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify',403,{'www-authenticate' : 'Basic-realm="Login required'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify', 403, {'www-authenticate': 'Basic-realm="Login required'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp':datetime.now(timezone.utc) + timedelta(minutes=10)},
                           app.config['SECRET_KEY'])
        return jsonify({"token": token})
    return make_response('could not verify', 403, {'www-authenticate': 'Basic-realm="Login required'})


if __name__ == '__main__':
    app.run(debug=True)