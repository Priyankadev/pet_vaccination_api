from pymongo import MongoClient
from config import *
import traceback
import json
import datetime
from bson import ObjectId


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


class Mdb:
    def __init__(self):
        conn_str = "mongodb://%s:%s@%s:%d/%s" \
                   % (DB_USER, DB_PASS, DB_HOST, DB_PORT, AUTH_DB_NAME)
        client = MongoClient(conn_str)
        self.db = client[DB_NAME]


#################################################
#                                               #
#                    ADD_USER                   #
#                                               #
#################################################
    def check_email(self, email):
        return self.db.user.find({'email': email}).count() > 0

    def add_user(self, name, email, pw_hash, answer):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'name': name,
                'email': email,
                'password': pw_hash,
                'answer': answer,
                'creation_date': ts
            }
            self.db.user.insert(rec)
        except Exception as exp:
            print("add_user() :: Got exception: %s", exp)
            print(traceback.format_exc())

#############################################
#                                           #
#           CHECK USER IN DATABASE          #
#                                           #
#############################################
    def user_exists(self, email):
        return self.db.user.find({'email': email}).count() > 0

#############################################
#                                           #
#               GET NEW PASSWORD            #
#                                           #
#############################################
    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print 'password in db class', password
        return password

#############################################
#                                           #
#        GET NAME ACCORDING TO EMAIL        #
#                                           #
#############################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
        return name

#############################################
#                                           #
#         GET USER ID BY SESSION            #
#                                           #
#############################################
    def get_user_id_by_session(self, email):
        result = self.db.user.find({'email': email})
        id = ''
        if result:
            for data in result:
                id = data['_id']
        return id


##############################################
#                                            #
#       GET SECURITY QUESTION BY EMAIL       #
#                                            #
##############################################
    def get_security_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        if result:
            for data in result:
                name = data['name']
                print 'password in db class', name
        return name

    def get_security_answer(self, email):
        result = self.db.user.find({'email': email})
        answer = ''
        if result:
            for data in result:
                answer = data['answer']
                print 'password in db class', answer
        return answer

    def set_password(self, email, pw_hash):
        self.db.user.update(
            {'email': email},
            {'$set': {'password': pw_hash}},
            upsert=True, multi=True)

    def add_pet(self, name, email, breed, age, gender):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'name': name,
                'email': email,
                'breed': breed,
                'age': age,
                'gender': gender,
                'creation_date': ts
            }
            self.db.pet.insert(rec)
        except Exception as exp:
            print("add_pet() :: Got exception: %s", exp)
            print(traceback.format_exc())

    def my_pet_info(self, email):
        result = self.db.pet.find({'email': email})
        ret = []
        for data in result:
            ret.append(data)
        return ret

if __name__ == "__main__":
    mdb = Mdb()
