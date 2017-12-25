from flask import Flask, request,  jsonify, render_template,\
    session, url_for, redirect, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
from flask_admin import Admin, BaseView, expose
import uuid
from uuid import getnode as get_mac
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
import time
from datetime import datetime, timedelta
import datetime
import traceback
import flask_login
import flask
import json
import jwt
import os
from db import Mdb
from werkzeug.utils import secure_filename
from wtforms.fields import SelectField
# from utils import log

app = Flask(__name__)
bcrypt = Bcrypt(app)
mdb = Mdb()


##############################################################################
#                                                                            #
#                                                                            #
#                                    SESSION                                 #
#                                                                            #
#                                                                            #
##############################################################################
@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=15)
    flask.session.modified = True
    flask.g.user = flask_login.current_user
    # print'session in working'


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


##############################################################################
#                                                                            #
#         _id of mongodb record was not getting JSON encoded, so             #
#                          using this custom one                             #
#                                                                            #
#                                                                            #
##############################################################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#               LOGIN MANAGER                #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})

        return f(*args, **kwargs)

    return decorated


##############################################
#                                            #
#               WHO AM I ROUTE               #
#                                            #
##############################################
@app.route('/api/whoami')
def whoami():
    ret = {}
    try:
        sumSessionCounter()
        ret['User'] = (" hii i am %s !!" % session['name'])
        email = session['email']
        ret['Session'] = email
        ret['User_Id'] = mdb.get_user_id_by_session(email)
    except Exception as exp:
        ret['error'] = 1
        ret['user'] = 'user is not login'
    return JSONEncoder().encode(ret)


@app.route('/')
def index():
    return render_template('index.html')


#############################################
#                                           #
#                  ADD USER                 #
#                                           #
#############################################
@app.route("/api/register", methods=['POST'])
def add_user():
    ret = {'msg': 'User Is Added Successfully'}
    try:
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        answer = request.form['answer']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        check = mdb.check_email(email)
        if check:
            return 'This Email Already Used'

        else:
            mdb.add_user(name, email, pw_hash, answer)

            return json.dumps(ret)
            # return 'Add user!'
    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/api/login', methods=['POST'])
def login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print 'password in server, get from db class', pw_hash
            passw = bcrypt.check_password_hash(pw_hash, password)

            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=15)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                # flask_login.login_user(user, remember=False)
                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
                templateData = {'title': 'singin page'}
            else:
                return 'Something is wrong!'

        else:
            # Login Failed!
            return 'Login Failed'

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    # return jsonify(ret)
    return json.dumps(ret)


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################
@app.route('/api/logout')
def clearsession():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = session['email']
        session.clear()
        ret['msg'] = 'Login successful'
        ret['err'] = 0
    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
    return json.dumps(ret)


#############################################
#                                           #
#              REGET PASSWORD               #
#                                           #
#############################################
@app.route("/api/reset_password", methods=['POST'])
def reset_password():
    try:
        ret = {}
        ret = {"error": 0}
        email = request.form['email']
        name = request.form['name']
        answer = request.form['answer']
        password = request.form['password']

        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        if mdb.user_exists(email):
            name = mdb.get_security_name(email)
            print 'database name', name

            if name == name:
                ans = mdb.get_security_answer(email)

                if answer == ans:
                    mdb.set_password(email, pw_hash)
                    return 'Done!'
                else:
                    return 'failed'

            else:
                return'failed1'
        else:
            return'failed2'
        ret['msg'] = 'Search Successfully!'
        ret['err'] = 0
    except Exception as exp:
        print 'reset_password():: Got exception: %s' % exp
        print(traceback.format_exc())


#############################################
#                                           #
#              SET PET INFORMATION          #
#                                           #
#############################################
@app.route("/api/set_pet_info", methods=['POST'])
def set_pet_info():
    ret = {'msg': 'Pet Is Added Successfully'}
    try:
        email = request.form['email']
        name = request.form['name']
        breed = request.form['breed']
        age = request.form['age']
        gender = request.form['gender']

        mdb.add_pet(name, email, breed, age, gender)

        return json.dumps(ret)
        # return 'Add user!'
    except Exception as exp:
        print('set_pet_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return 'some thing is wrong!'


#################################################
#                                               #
#              GET PET INFORMATION              #
#                                               #
#################################################
@app.route("/api/get_pet_info", methods=['GET'])
def get_pet_info():
    try:
        sumSessionCounter()
        email = session['email']
        result = mdb.my_pet_info(email)

    except Exception as exp:
        print('get_pet_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return "%s" % mdb.my_pet_info(email)

#################################################
#                                               #
#                 Main Server                   #
#                                               #
#################################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True, threaded=True)
