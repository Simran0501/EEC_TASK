from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
from functools import wraps
from jwt.exceptions import InvalidTokenError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vyking123'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db=SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), nullable = False)
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    public_id = db.Column(db.Integer, unique=True) 


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_content = db.Column(db.String(80))
    status = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'Message' : 'No token is there!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            curr_user = Users.query.filter_by(public_id = data['public_id']).first()
        except InvalidTokenError as e :
            return jsonify({'Message' : 'Invalid Token', 'err' : e.args[0]}), 401

        return f(curr_user, *args, **kwargs)
    return decorated


@app.route('/user', methods = ['GET'])
@token_required
def get_all_users(curr_user):

    if not curr_user.admin:
        return jsonify({'Message' : 'You are not allowed to perform that function!'})

    users = Users.query.all()
    result = []
    for user in users:
        user_info = {}
        user_info['name'] = user.name
        user_info['password'] = user.password
        user_info['admin'] = user.admin
        user_info['public_id'] = user.public_id
        result.append(user_info)
    
    return jsonify({'users' : result})

@app.route('/user/<public_id>', methods = ['GET'])
@token_required
def get_one_user(curr_user, public_id):
    user = Users.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'Message' : 'No record matched!'})
    user_info = {}
    user_info['name'] = user.name
    user_info['password'] = user.password
    user_info['admin'] = user.admin
    user_info['public_id'] = user.public_id
    
    return jsonify({'User' : user_info})
    

@app.route('/user', methods = ['POST'])
@token_required
def create_user(curr_user):
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method = 'sha256')
    new_user = Users(name = data['name'], password = hashed_password, admin = False, public_id=str(uuid.uuid4()))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message' : 'User Created successfully!'})

@app.route('/user/<public_id>', methods = ['PUT'])
@token_required
def make_admin(curr_user,public_id): 
    user = Users.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'Message' : 'No record matched!'})

    user.admin = True
    db.session.commit()
    return jsonify({'Message' : 'User has become admin now!'})

@app.route('/user/<public_id>', methods = ['DELETE'])
@token_required
def delete_user(curr_user,public_id):
    user = Users.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'Message' : 'No record matched!'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'Message' : 'User deleted successfully!'})

@app.route('/signin')
def signin():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Fail to verify!', 401, {'WWW-Authenticate' : 'Basic requirement = "Login required'})
    
    user = Users.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Fail to verify!', 401, {'WWW-Authenticate' : 'Basic Area = "Login required'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id , 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token})

    return make_response('Fail to verify!', 401, {'WWW-Authenticate' : 'Basic Area = "Login required'})

@app.route('/task', methods = ['GET'])
@token_required
def get_all_tasks(curr_user):
    tasks = Tasks.query.filter_by(user_id=curr_user.id).all()
    result = []
    for task in tasks:
        task_data = {}
        task_data['id'] = task.id
        task_data['task_content'] = task.task_content
        task_data['status'] = task.status
        result.append(task_data)
    return jsonify({'Tasks' : result})

@app.route('/task/<task_id>', methods = ['GET'])
@token_required
def get_one_task(curr_user, task_id):
    task = Tasks.query.filter_by(id=task_id, user_id = curr_user.id).first()
    if not task:
        return jsonify({'Message' : 'No task found'})
    task_data = {}
    task_data['id'] = task.id
    task_data['task_content'] = task.task_content
    task_data['status'] = task.status
    return jsonify({'Task' : task_data})

@app.route('/task', methods = ['POST'])
@token_required
def create_task(curr_user):
    data = request.get_json()
    new_task = Tasks(task_content = data['task_content'], status = False, user_id = curr_user.id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'Message' : 'New task has been added!'})

@app.route('/task/<task_id>', methods = ['PUT'])
@token_required
def update_status(curr_user, task_id):
    task = Tasks.query.filter_by(id=task_id, user_id = curr_user.id).first()
    if not task:
        return jsonify({'Message' : 'No task found'})
    
    task.status=True
    db.session.commit()
    return jsonify({'Message' : 'Tasks is done!'})

@app.route('/task/<task_id>', methods = ['DELETE'])
@token_required
def delete_task(curr_user, task_id):
    task = Tasks.query.filter_by(id=task_id, user_id = curr_user.id).first()
    if not task:
        return jsonify({'Message' : 'No task found'})
    
    db.session.delete(task)
    db.session.commit()
    return jsonify({'Message' : 'Task has been deleted'})

if __name__=='__main__':
    app.run(debug=True)
