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
        # ret['User_Id'] = mdb.get_user_id_by_session(email)
        ret['error'] = 0

    except Exception as exp:
        print('whoami() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret['error'] = 1
        ret['msg'] = '%s' % exp
    return jsonify(ret)


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
    ret = {}
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
            ret['msg'] = 'This Email Already Used!'
            ret['error'] = 1
            return jsonify(ret)
        else:
            mdb.add_user(name, email, pw_hash, answer)
            ret['msg'] = 'User Is Added Successfully!'
            ret['error'] = 0
            return json.dumps(ret)

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret['msg'] = 'Something is wrong!'
        ret['error'] = 1

#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/api/login', methods=['POST'])
def login():
    ret = {}
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

            else:
                ret['msg'] = 'Password is not match!'
                ret['error'] = 1
                return jsonify(ret)

        else:
            ret['msg'] = 'email is not exist!'
            ret['error'] = 1
            return jsonify(ret)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    return jsonify(ret)


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################
@app.route('/api/logout')
def clearsession():
    ret = {}
    try:
        sumSessionCounter()
        email = session['email']
        session.clear()
        ret['msg'] = 'Logout successful'
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
        email = request.form['email']
        name = request.form['name']
        answer = request.form['answer']
        password = request.form['password']

        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        if mdb.user_exists(email):
            nm = mdb.get_security_name(email)

            if name == nm:
                ans = mdb.get_security_answer(email)

                if answer == ans:
                    mdb.set_password(email, pw_hash)
                    # ret["msg"] = "Done !"
                    ret['msg'] = 'Reset Password Successfully!'
                    # return 'Done!'
                else:
                    ret["msg"] = 'your answer is not match!'
                    ret['err'] = 1

            else:
                ret["msg"] = 'your name is wrong!'
                ret['err'] = 1
        else:
            ret["msg"] = 'Email id is incorrect!'
            ret['err'] = 1

    except Exception as exp:
        print 'reset_password():: Got exception: %s' % exp
        print(traceback.format_exc())
        ret["error"] = 1
        ret["msg"] = '%s' % exp
    return jsonify(ret)


#############################################
#                                           #
#              SET PET INFORMATION          #
#                                           #
#############################################
@app.route("/api/set_pet_info", methods=['POST'])
def set_pet_info():
    ret = {}
    try:
        sumSessionCounter()
        email = request.form['email']
        name = request.form['name']
        breed = request.form['breed']
        age = request.form['age']
        gender = request.form['gender']
        email_session = session['email']

        if email == email_session:
            mdb.add_pet(name, email, breed, age, gender)
            ret["msg"] = 'Add pet successfully!'
            ret['err'] = 0
            return json.dumps(ret)

        else:
            ret["msg"] = 'your email is wrong!'
            ret['err'] = 1
            return json.dumps(ret)

    except Exception as exp:
        print('set_pet_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["msg"] = 'User is not login!'
        ret['err'] = 1
        return json.dumps(ret)


#################################################
#                                               #
#              GET PET INFORMATION              #
#                                               #
#################################################
@app.route("/api/get_pet_info", methods=['GET'])
def get_pet_info():
    ret = {}
    try:
        sumSessionCounter()
        email = session['email']
        result = mdb.my_pet_info(email)
        ret["msg"] = "%s" % mdb.my_pet_info(email)
        ret['err'] = 0
        return json.dumps(ret)

    except Exception as exp:
        print('get_pet_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["msg"] = 'User is not login!'
        ret['err'] = 1
        return json.dumps(ret)


#################################################
#                                               #
#                 Main Server                   #
#                                               #
#################################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True, threaded=True)
