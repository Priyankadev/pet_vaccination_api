from flask import Flask, request,  jsonify, render_template
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
from datetime import datetime
import datetime
import traceback
import json
import jwt
import os
from db import Mdb

app = Flask(__name__)
bcrypt = Bcrypt(app)
mdb = Mdb()


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'


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

        return f(data, *args, **kwargs)

    return decorated


##############################################
#                                            #
#               WHO AM I ROUTE               #
#                                            #
##############################################
@app.route('/api/whoami')
@token_required
def whoami(token):
    ret = {}
    try:
        ret['User'] = token["user"]
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
        else:
            mdb.add_user(name, email, pw_hash, answer)
            ret['msg'] = 'User Is Added Successfully!'
            ret['error'] = 0

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret['msg'] = 'Something is wrong!'
        ret['error'] = 1
    return json.dumps(ret)


#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/api/login', methods=['POST'])
def login():
    ret = {}
    try:
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print('password in server, get from db class', pw_hash)
            passw = bcrypt.check_password_hash(pw_hash, password)

            if passw == True:
                name = mdb.get_name(email)

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                # flask_login.login_user(user, remember=False)
                ret['msg'] = 'Login successful'
                ret['success'] = True
                ret['token'] = token.decode('UTF-8')

            else:
                ret['msg'] = 'Password is not match!'
                ret['success'] = False

        else:
            ret['msg'] = 'email is not exist!'
            ret['error'] = 1

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['success'] = False
        print(traceback.format_exc())
    return jsonify(ret)


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################

@app.route('/api/logout')
@token_required
def clearsession(token):
    ret = {}
    try:
        email = token['user']
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
@token_required
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
        print ('reset_password():: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["error"] = 1
        ret["msg"] = '%s' % exp
    return jsonify(ret)


#############################################
#                                           #
#              SET PET INFORMATION          #
#                                           #
#############################################

@token_required
@app.route("/api/set_pet_info", methods=['POST'])
@token_required
def set_pet_info(token):
    ret = {}
    try:
        email = request.form['email']
        pet_name = request.form['name']
        breed = request.form['breed']
        age = request.form['age']
        gender = request.form['gender']
        user_email = token['user']

        if email == user_email:
            mdb.add_pet(pet_name, email, breed, age, gender)
            ret["msg"] = 'Add pet successfully!'
            ret['success'] = True

        else:
            ret["msg"] = 'your email is wrong!'
            ret['success'] = False

    except Exception as exp:
        print('set_pet_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["msg"] = 'User is not login!'
        ret['success'] = False
    return json.dumps(ret)


#############################################
#                                           #
#              SET PET INFORMATION          #
#                                           #
#############################################
@app.route("/api/set_vaccination", methods=['POST'])
@token_required
def set_vaccination(token):
    ret = {}
    try:

        email = token["user"]
        pet_name = request.form['name']
        date = request.form['date']
        notes = request.form['notes']
        if mdb.pet_name(pet_name, email):
            mdb.add_vaccination(pet_name, email, date, notes)
            ret["msg"] = 'Add pet vaccination successfully!'
            ret['success'] = True
        else:
            ret["msg"] = 'Name is incorrect!'
            ret['success'] = False
    except Exception as exp:
        print('set_vaccination() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["msg"] = 'User is not login!'
        ret['success'] = False
    return json.dumps(ret)


#################################################
#                                               #
#              GET PET INFORMATION              #
#                                               #
#################################################
@app.route("/api/get_vaccination", methods=['GET'])
@token_required
def get_vaccination(token):
    ret = {}
    try:
        email = token["user"]
        result = mdb.my_pet_vaccination(email)
        ret["msg"] = "%s" % mdb.my_pet_vaccination(email)
        ret['success'] = True
    except Exception as exp:
        print('get_vaccination() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["msg"] = '%s' % exp
        ret['success'] = False
    return json.dumps(ret)


#################################################
#                                               #
#              GET PET INFORMATION              #
#                                               #
#################################################
@app.route("/api/get_pet_info", methods=['GET'])
@token_required
def get_pet_info(token):
    ret = {}
    try:
        email = token["user"]
        ret["msg"] = "%s" % mdb.my_pet_info(email)
        ret['success'] = True
    except Exception as exp:
        print('get_pet_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret["msg"] = '%s' % exp
        ret['success'] = False
    return json.dumps(ret)


#################################################
#                                               #
#                 Main Server                   #
#                                               #
#################################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
