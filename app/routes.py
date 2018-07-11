import hashlib
import time
from datetime import datetime
from app import argon2
from app import appAHQ
import flask
from dataModels.models import User, Data, Coach, AthleteInfo
import csv
import os
from flask import Flask, request, url_for, send_from_directory, json, make_response, render_template
from mongoengine import ValidationError, NotUniqueError
from werkzeug.utils import secure_filename
from dataModels import models
from app import appAHQ
from dataModels.models import User
from dataModels.unityFileOp import insertFile, getFile, listName, listFiles, delFile

ALLOWED_EXTENSIONS = set(['csv'])
appAHQ.config['UPLOAD_FOLDER'] = 'MongoDB/data'
appAHQ.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

#detect wether the format(suffix) of a file to upload is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

# unlink all relationships between two users.
def unlink(user, target_email):
# This function is to delete the nexus between the two users
    coach_user=models.get_coach().find({"email":user})
    coach_target=models.get_coach().find({"email":target_email})
    ath_user=models.get_athleteInfo().find({"athlete":user})
    ath_target=models.get_athleteInfo().find({"athlete":target_email})

    if coach_user and coach_user.count()!=0 and  target_email in coach_user[0]["athletes"]:
        athleteList = coach_user[0]["athletes"]
        athleteList = [x for x in athleteList if x!=target_email]
        try:
            models.get_coach().update({"email": user}, {"$set": {"athletes": athleteList}})
        except Exception as e:
            return 0
    if coach_target and coach_target.count()!=0 and user in coach_target[0]["athletes"]:
        athleteList = coach_target[0]["athletes"]
        athleteList = [x for x in athleteList if x != user]
        try:
            models.get_coach().update({"email": target_email}, {"$set": {"athletes": athleteList}})
        except Exception as e:
            return 0
    if ath_user and ath_user.count()!=0 and target_email in ath_user[0]["coaches"]:
        coachList = ath_user[0]["coaches"]
        coachList = [x for x in coachList if x != target_email]
        try:
            models.get_athleteInfo().update({"athlete": user}, {"$set": {"coaches": coachList}})
        except Exception as e:
            return 0
    if ath_target and ath_target.count()!=0 and user in ath_target[0]["coaches"]:
        coachList = ath_target[0]["coaches"]
        coachList = [x for x in coachList if x != user]
        try:
            models.get_athleteInfo().update({"athlete": target_email}, {"$set": {"coaches": coachList}})
        except Exception as e:
            return 0
    return 1

# session authentication: to detect wether this session is legal and valid.
def auth_sessionID(sessionID):
    try:
        list = sessionID.split("-")
        email = list[0]
        md5 = list[1]
        user = models.get_user().find({"email": email})
        email = user[0]['email']
        password = user[0]['password']
        time_expire = user[0]['expireTime']
        if datetime.utcnow() > time_expire:
            return False
        L = hashlib.md5(('%s-%s-%s' % (email, password, str(time_expire))).encode("utf-8")).hexdigest()
        if L == md5:
            return True
        else:
            return False
    except Exception:
        return False

# change user info from database into printable string
def userToString(dict):
    str = ''
    str += '[Email:' + dict['email'] + ', Password:' + dict['password']
    try:
        str += ', role:' + dict['role']
    except KeyError:
        str += ', role:' + 'Not Set'

    try:
        str += ', RFID:' + dict['rfidTag'] + ']'
    except KeyError:
        str += ', RFID:' + 'Not Set]'

    return str



@appAHQ.route('/')
# Return the main page(html5) of Athletehq.
def home():
    return render_template('home.html')


@appAHQ.route('/login_page')
# Return the coach's login page(html5) of Athletehq.
def login_page():
    return render_template('login.html')


@appAHQ.route('/coach/main_page',methods=['GET'])
# Return the main management page(html5) for a coach.
def web_get_main_page():
    return render_template('index.html')


@appAHQ.route('/coach/management',methods=['PUT','GET'])
# PUT    : Coach update his/her athletes' info/goals/focus.@require('sessionID','email', fieldsToUpdate)
# GET    : Fetch all linked athletes' info/goals/focus.@require('sessionID')
def web_main():
    if request.method=='GET':
        try:
            sessionID = request.headers.get('sessionID')
            if sessionID == None:
                return flask.jsonify(result='error', msg='SessionID field is required.')
        except BaseException:
            try:
                content = flask.request.get_json(force=True, silent=False, cache=True)
                sessionID = content.get("sessionID")
                if sessionID == None:
                    return flask.jsonify(result='error', msg='SessionID field is required.')
            except BaseException:
                return flask.jsonify(result='error', msg=eval("{'request': \"Wrong json format\"}"))
        if (auth_sessionID(sessionID)):
            coach = sessionID.split("-")[0]
            try:
                coaches = models.get_coach().find({"email": coach})
                print(not coaches)
                print(coaches.count() == 0)
                if not coaches or coaches.count() == 0:
                    new_coach = Coach(
                        email=coach,
                        athletes=[]
                    )
                    try:
                        new_coach.save()
                    except ValidationError as e:
                        return flask.jsonify(result='error', msg=e.to_dict())
                    else:
                        data=models.get_athlete_data_package(coach)
                        return flask.jsonify(data=data,result='succeed')
                else:
                    data=models.get_athlete_data_package(coach)
                    return flask.jsonify(data=data,result='succeed')
            except Exception as e:
                return flask.jsonify(result='error')
        else:
            return flask.jsonify(result='error', msg='Session expired, please relogin.')
    if request.method=='PUT':
        try:
            data= flask.request
        except BaseException:
            return flask.jsonify(result='error', msg='Wrong request format.')
        try:
            sessionID=data.values['sessionID']
            email = data.values['email']
        except BaseException:
            return flask.jsonify(result='error', msg='SessionID and email fields are required.')
        if (not auth_sessionID(sessionID)):
            return flask.jsonify(result='error', msg='Session expired, please relogin.')
        try:
            athletes=models.get_coach().find({"email":sessionID.split("-")[0]})[0]['athletes']
            if email not in athletes:
                return flask.jsonify(result='error', msg='You are not the coach of the athlete.')
        except Exception:
            return flask.jsonify(result='error', msg='Try it later.')

        try:
            tag=False
            dob=data.values['DOB']
            abdomen=data.values['abdomen']
            chest=data.values['chest']
            fatRate=data.values['fatRate']
            hip=data.values['hip']
            height=data.values['height']
            midAxi=data.values['midAxi']
            subscap=data.values['subscap']
            thigh=data.values['thigh']
            tricep=data.values['tricep']
            weight=data.values['weight']
            tag=True
            models.get_athleteInfo().update(
                {"athlete":email},
                {"$set": {
                'DOB':dob,
                'height':height,
                'weight':weight,
                'bodyFat':fatRate,
                'chest':chest,
                'abdomen':abdomen,
                'thigh':thigh,
                'tricep':tricep,
                'subscap':subscap,
                'midAxi':midAxi,
                'hip':hip
            }})
            return flask.jsonify(result='succeed')
        except Exception:
            if tag:
                return flask.jsonify(result='error',msg='Database not responding, try it later.')
        try:
            tag=False
            mainObs=data.values['mainObs'].strip("\r").strip("\n").split("\r\n")
            subObs=data.values['subObs'].strip("\r").strip("\n").split("\r\n")
            tag=True
            models.get_athleteInfo().update(
                {"athlete":email},
                {"$set": {
                'majorGoal':mainObs,
                'subGial':subObs
            }})
            return flask.jsonify(result='succeed')
        except Exception:
            if tag:
                return flask.jsonify(result='error',msg='Database not responding, try it later.')
        try:
            tag=False
            mobility=data.values['mobilitys'].strip("\r").strip("\n").split("\r\n")
            nutrition=data.values['nutritions'].strip("\r").strip("\n").split("\r\n")
            recovery=data.values['recoverys'].strip("\r").strip("\n").split("\r\n")
            tech=data.values['techs'].strip("\r").strip("\n").split("\r\n")
            tag=True
            models.get_athleteInfo().update(
                {"athlete":email},
                {"$set": {
                'recovery':recovery,
                'nutrition':nutrition,
                'technique':tech,
                'mobility':mobility
            }})
            return flask.jsonify(result='succeed')
        except Exception:
            if tag:
                return flask.jsonify(result='error', msg='Database not responding, try it later.')
        return flask.jsonify(result='error', msg='Some fields are missing.')

    return flask.jsonify(result='error', msg='Method not allowed.')


@appAHQ.route('/user', methods=['POST','GET','PUT','DELETE'])
# POST   : To register a new user.@require('email','password')
# GET    : To query all registered users.@require()
# UPDATE : To update one user's password or/and role or/and rfidTag.@require('email','password','newPassword','newRole','newRFID')
# DELETE : To delete a registered user and its all data(including unity files, info, relationship with other users).@require('email', 'password')
def user_operation():
# To register a new user.
    if request.method == 'POST':
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)
        except BaseException:
            return flask.jsonify(result='error', msg=eval("{'request': \"Wrong json format\"}"))
        if content.get("password")==None:
            password=None
        else:
            if len(content.get("password"))<8:
                password=content.get("password")
            else:
                # password=hashlib.md5((content.get("password")+'athletehq').encode("utf-8")).hexdigest()
                password=argon2.generate_password_hash((content.get("password")).encode("utf-8"))
        new_user = User(password=password,
                        email=content.get("email"),
                        rfidTag=content.get("RFID"),
                        role=content.get("role"),
                        expireTime=datetime.utcnow()
                        )
        new_info = AthleteInfo(
                            athlete=content.get("email"),
                            genTime=datetime.utcnow()
                            )
        try:
            new_user.save()
            new_info.save()
        except ValidationError as e:
            return flask.jsonify(result='error', msg=e.to_dict())
        except NotUniqueError as e2:
            return flask.jsonify(result='error', msg=eval("{'email': \"Account already exists\"}"))
        return flask.jsonify(result='succeed')

# To query all registered users. -->Only for testing.
    if request.method == 'GET':
        users = User.query_users()
        str = ''
        response = {}
        counter = 0
        for user in users:
            counter += 1
            response[counter] = userToString(user)
        return flask.jsonify(allUsers=response)

# User update his/her account information, including change password, role, and rfidTag
    if request.method == 'PUT':
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)

        except BaseException:
            return flask.jsonify(result='error', msg=eval("{'request': \"Wrong json format\"}"))
        try:
            email = content.get("email")
            password = content.get("password")
        except Exception :
            return flask.jsonify(result='error',msg='Request should contain email and password.')
        else:
            user = models.get_user().find({"email": email})
            if user and user.count() !=0 and argon2.check_password_hash(user[0]["password"], password):
                newrfidTag=content.get("newRFID")
                if newrfidTag==None:
                    newrfidTag = user[0]["rfidTag"]
                newPassword=content.get("newPassword")
                if newPassword==None:
                    newPassword=user[0]["password"]
                else:
                    if len(newPassword)<8:
                        return flask.jsonify(result='error',msg="Password length must be longer than 8 characters.")
                    else:
                        newPassword = argon2.generate_password_hash(
                            (content.get("newPassword")).encode("utf-8"))
                newRole=content.get("newRole")
                if newRole ==None:
                    newRole= ""
                if newRole not in ["","Not Set","Coach","Athlete"]:
                    return flask.jsonify(result="error",msg="new role must be one of 'Coach', 'Athlete','Not Set'")
                if (newRole=='Athlete'or'Not Set') and user[0]["role"]=='Coach':
                    return flask.jsonify(result='error', msg='Currently, a Coach is not allowed to change his/her role to an Athlete.')
                if newRole =='':
                    newRole = "Not Set"
                try:
                    print(newRole)
                    models.get_user().update(
                        {"email":email},
                        {"$set":
                            {
                                "password":newPassword,
                                "role":newRole,
                                "rfidTag":newrfidTag
                            }
                        }
                    )
                    print(newPassword)
                    return flask.jsonify(result='succeed')
                except Exception as e:
                    return flask.jsonify(result='error',msg=e.__str__())
            else:
                return flask.jsonify(result="error", msg="Check your email and password.")

# User delete his/her account, all information and linked relationships will be deleted.
    if request.method == 'DELETE':
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)

        except BaseException:
            return flask.jsonify(result='error', msg=eval("{'request': \"Wrong json format\"}"))
        try:
            email = content.get("email")
            password = content.get("password")
        except Exception :
            return flask.jsonify(result='error',msg='Request should contain email and password.')
        else:
            users = models.get_user().find({"email": email})
            if users and users.count() !=0 and argon2.check_password_hash(users[0]["password"], password):
                user=users[0]
                hisCouches= models.get_athleteInfo().find({"athlete":email})[0]["coaches"]
                for coach in hisCouches:
                    result=unlink(email, coach)
                    if result==1: continue
                    else:
                        return flask.jsonify(result='error', msg='Failed, try it later.')
                coaches=models.get_coach().find({"email":email})
                for coach in coaches:
                    hisAthletes= coach['athletes']
                    for athlete in hisAthletes:
                        result=unlink(email, athlete)
                        if result==1: continue
                        else:
                            return flask.jsonify(result='error',msg='Failed, try it later.')
                try:
                    models.get_athleteInfo().remove({"athlete":email})
                    models.get_coach().remove({"email":email})
                    models.get_user().remove({"email":email})
                except Exception as e:
                    return flask.jsonify(result='error',msg='Failed, try it later.')
                else:
                    return flask.jsonify(result='succeed')
            else:
                return flask.jsonify(result="error", msg="Check your email and password.")

    return flask.jsonify(result='error', msg='Method not allowed.')


@appAHQ.route('/session', methods=['POST','DELETE'])
#  POST   : Create a session with a client and generate a unique sessionID. The Client should use a valid email and password to create a session, and should save the sessionID locally.@require('email','password')
#  DELETE : User log out and delete a session, the sessionID will immeadiately be invalid. @require('sessionID')
def session_operation():
# To login and create a session. The server will return the client a sessionID, client should keep this sessionID to do further requests.
    if request.method == 'POST':
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)
            email = content.get("email")
            if email==None:
                return flask.jsonify(result='error', msg='Email field is required.')
            try:
                password = content.get("password").encode("utf-8")
            except Exception :
                return flask.jsonify(result='error',msg='Password field is required.')
        except BaseException:
            try:
                email = flask.request.values['email']
                password = flask.request.values['password'].encode("utf-8")
            except BaseException:
                return flask.jsonify(result='error', msg="Wrong json format.")
        try:
            user = models.get_user().find({"email": email})
            # print("list")
            if not user or user.count() == 0:
                return flask.jsonify(result='error', msg="Check your email and password.")
            if not argon2.check_password_hash(user[0]["password"], password) :
                return flask.jsonify(result='error', msg="Check your email and password.")
            else:
                doc = user[0]
                email = doc['email']
                password = doc['password']
                time_expire = doc['expireTime']
                max_time_live = 14 * 24 * 3600
                time_now_stamp = time.time()
                time_now = datetime.fromtimestamp(time_now_stamp)
                if time_now > time_expire:  ##session expired
                    print("expired")
                    time_expire = datetime.fromtimestamp(time_now_stamp + max_time_live)
                    models.get_user().update({"email": email}, {"$set": {"expireTime": time_expire}})
                    user = models.get_user().find({"email": email, "password": password})
                    time_expire = user[0]['expireTime']
                    L = [email, hashlib.md5(('%s-%s-%s' % (email, password, str(time_expire))).encode("utf-8")).hexdigest()]
                    print("Using:%s-%s-%s" % (email, password, str(time_expire)))
                    print("MD5:%s" % (L[1]))
                    return flask.jsonify(result='succeed', sessionID='-'.join(L))
                else:  ##session not expired
                    # print("not expired")
                    L = [email, hashlib.md5(('%s-%s-%s' % (email, password, str(time_expire))).encode("utf-8")).hexdigest()]
                    print("Using:%s-%s-%s" % (email, password, str(time_expire)))
                    print("MD5:%s" % (L[1]))
                    return flask.jsonify(result='succeed', sessionID='-'.join(L))
        except BaseException as e:
            return flask.jsonify(result='error', msg=e.__str__())

# To logout and invalidate this session. Notice: the change of a user's password will immediately terminate that user's current session.
    if request.method == 'DELETE':
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)
            sessionID = content.get("sessionID")
            if sessionID==None:
                return flask.jsonify(result='error',msg='SessionID field is required.')
            print(sessionID)
        except BaseException:
            try:
                sessionID = flask.request.values['sessionID']
                if sessionID == None:
                    return flask.jsonify(result='error', msg='SessionID field is required.')
            except BaseException:
                return flask.jsonify(result='error', msg="Wrong json format.")
        try:
            if auth_sessionID(sessionID):
                list = sessionID.split("-")
                email = list[0]
                time_now_stamp = time.time()
                time_now = datetime.fromtimestamp(time_now_stamp)
                models.get_user().update({"email": email}, {"$set": {"expireTime": time_now}})
                return flask.jsonify(result='succeed')
            else:
                return flask.jsonify(result='Invalid session.')
        except BaseException as e:
            return flask.jsonify(result='error', msg=e.__str__())

    return flask.jsonify(result='error',msg='Method not allowed.')


@appAHQ.route('/coach/login', methods=['POST'])
# Not used any more, not comform to the principle of REST api.
# @require('email','password')
def coach_login():
    content = None
    try:
        content = flask.request.get_json(force=True, silent=False, cache=True)
        password = hashlib.md5((content.get("password") + 'athletehq').encode("utf-8")).hexdigest()

        email = content.get("email")
    except BaseException:
        try:
            email = flask.request.values['email']
            password = hashlib.md5((flask.request.values['password'] + 'athletehq').encode("utf-8")).hexdigest()
            print("11111")
            print(password)
        except BaseException:
            return flask.jsonify(result='error', msg=eval("{'request': \"Wrong json format\"}"))
    try:
        user = models.get_user().find({"email": email, "password": password})
        auth = models.get_user().find({"email": email, "password": password, "role": "Coach"})
        # print("list")
        if not user or user.count() == 0:
            return flask.jsonify(result='error', msg="Check your email and password.")
        if not auth or auth.count() ==0:
            return flask.jsonify(result='error', msg='You are not registered as COACH.')
        else:
            doc = user[0]
            email = doc['email']
            password = doc['password']
            time_expire = doc['expireTime']
            max_time_live = 14 * 24 * 3600
            time_now_stamp = time.time()
            time_now = datetime.fromtimestamp(time_now_stamp)
            if time_now > time_expire:  ##session expired
                print("expired")
                time_expire = datetime.fromtimestamp(time_now_stamp + max_time_live)
                models.get_user().update({"email": email}, {"$set": {"expireTime": time_expire}})
                user = models.get_user().find({"email": email, "password": password})
                time_expire = user[0]['expireTime']
                L = [email, hashlib.md5(('%s-%s-%s' % (email, password, str(time_expire))).encode("utf-8")).hexdigest()]
                # print("Using:%s-%s-%s" % (email, password, str(time_expire)))
                # print("MD5:%s" % (L[1]))
                return flask.jsonify(result='succeed', sessionID='-'.join(L))

            else:  ##session not expired
                print("not expired")
                L = [email, hashlib.md5(('%s-%s-%s' % (email, password, str(time_expire))).encode("utf-8")).hexdigest()]
                # print( auth_sessionID('-'.join(L)))
                print("Using:%s-%s-%s" % (email, password, str(time_expire)))
                print("MD5:%s" % (L[1]))
                return flask.jsonify(result='succeed', sessionID='-'.join(L))
    except BaseException as e:
        return flask.jsonify(result='error', msg=e.to_dict())

@appAHQ.route('/user/nexus', methods=['POST','DELETE','GET'])
# POST   : Create a nexus between an athlete and a coach. @require('sessionID', 'link')
# DELETE : Delete any relationship between two users. @require('sessionID', 'unlink')
# GET    : Look up one's linked users (his/her athletes or/and coaches). @require('sessionID')
def user_link():
# To create a nexus between an athlete and a coach. @require('sessionID', 'link'):
    if request.method == 'POST':
        print("in if")
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)
            sessionID=content.get("sessionID")
            if sessionID==None:
                return flask.jsonify(result='error', msg="SessionID field is required.")
            email=content.get("link")
            if email==None:
                return flask.jsonify(result='error', msg="Link field is required.")
        except BaseException:
            return flask.jsonify(result='error', msg=eval("{'request': \"Wrong json format\"}"))
        if (auth_sessionID(sessionID)):
            user = sessionID.split("-")[0]
            user_raise=models.get_user().find({"email":user})
            user_to_link=models.get_user().find({"email":email})
            if not user_to_link or user_to_link.count()==0:
                return flask.jsonify(result='error', msg='User {} does not exist.'.format(email))
            if user_raise[0]["role"]=="Coach" and user_to_link[0]["role"] !="Coach":
                try:
                    coaches=models.get_coach().find({"email":user})
                    print(not coaches )
                    print(coaches.count() == 0)
                    if not coaches or coaches.count()==0:
                        new_coach=Coach(
                                        email=user,
                                        athletes=[email]
                                    )
                        try:
                            new_coach.save()
                            coachList=models.get_athleteInfo().find({"athlete":email})[0]["coaches"]
                            if user not in coachList:
                                coachList.append(user)
                                models.get_athleteInfo().update({"athlete":email},{"$set":{"coaches":coachList}})
                        except ValidationError as e:
                            return flask.jsonify(result='error', msg=e.to_dict())
                        else: return flask.jsonify(result='succeed')
                    else:
                        athletes=coaches[0]['athletes']
                        coachList=models.get_athleteInfo().find({"athlete":email})[0]["coaches"]
                        print(coachList)
                        if coachList ==None:
                            coachList=[user]
                            print(coachList)
                        if email not in athletes:
                            athletes.append(email)
                        if user not in coachList:
                            coachList.append(user)
                        print(athletes)
                        models.get_coach().update({"email":user},{"$set": {"athletes":athletes }})
                        models.get_athleteInfo().update({"athlete":email},{"$set":{"coaches":coachList}})
                        return flask.jsonify(result="succeed")
                except BaseException as e2:
                    return flask.jsonify(result="error", msg="Type error")

            if user_raise[0]["role"]!="Coach" and user_to_link[0]["role"] =="Coach":
                try:
                    coaches = models.get_coach().find({"email": email})
                    if not coaches or coaches.count() == 0:
                        new_coach = Coach(
                            email=email,
                            athletes=[user]
                        )
                        try:
                            new_coach.save()
                            coachList = models.get_athleteInfo().find({"athlete": user})[0]["coaches"]

                            if coachList == None:
                                coachList = [email]
                            else:
                                coachList.append(email)

                            models.get_athleteInfo().update({"athlete":user},{"$set":{"coaches":coachList}})
                        except ValidationError as e:
                            return flask.jsonify(result='error', msg=e.to_dict())
                        else:
                            return flask.jsonify(result='succeed')
                    else:
                        athletes = coaches[0]['athletes']
                        if user not in athletes:

                            athletes.append(user)
                            models.get_coach().update({"email": email}, {"$set": {"athletes": athletes}})
                            coachList = models.get_athleteInfo().find({"athlete": user})[0]["coaches"]

                            if coachList ==None:
                                coachList=[email]
                            else:
                                coachList.append(email)

                            models.get_athleteInfo().update({"athlete": user}, {"$set": {"coaches": coachList}})
                            return flask.jsonify(result="succeed")
                        else:
                            return flask.jsonify(result='succeed')
                except BaseException as e2:
                    return flask.jsonify(result="error", msg="Type error")

            return flask.jsonify(result='error',msg='Linking rule: the linked two users should contain one and only one Coach.')
        else:
            return flask.jsonify(result='error', msg='Session expired, please relogin.')

# To look up one's linked users (his/her athletes or/and coaches). @require('sessionID')
    if request.method == 'GET':
        content = None
        try:
            sessionID = request.headers.get('sessionID')
            if sessionID ==None:
                return flask.jsonify(result='error', msg="SessionID field is required.")
        except BaseException:
            return flask.jsonify(result='error', msg="Wrong request format.")
        if (auth_sessionID(sessionID)):
            user = sessionID.split("-")[0]
            try:
                if models.get_user().find({"email":user})[0]["role"]=="Coach":
                    coach=models.get_coach().find({"email":user})
                    athleteList=[]
                    if (coach != None) & (coach.count() !=0):
                        athleteList=coach[0]["athletes"]
                    return flask.jsonify(result="succeed",linked_athletes=athleteList)
                else:
                    coachList=models.get_athleteInfo().find({"athlete":user})[0]["coaches"]
                    return flask.jsonify(result="succeed",linked_coaches=coachList)
            except Exception as e :
                return flask.jsonify(result="error", msg=e.__str__())
        return flask.jsonify(result='error', msg='Session expired, please relogin.')

# To delete all relationship between two users. @require('sessionID', 'unlink')
    if request.method == 'DELETE':
        print("in if")
        content = None
        try:
            content = flask.request.get_json(force=True, silent=False, cache=True)
            sessionID=content.get("sessionID")
            target_email=content.get("unlink")
            if sessionID==None:
                return flask.jsonify(result='error', msg="SessionID field is required.")
            if target_email==None:
                return flask.jsonify(result='error', msg="Unlink field is required.")
        except BaseException:
            return flask.jsonify(result='error', msg="Wrong request format.")
        if (auth_sessionID(sessionID)):
            user = sessionID.split("-")[0]
            res=unlink(user, target_email)
            if res ==1:
                return flask.jsonify(result='succeed')
            else:
                return flask.jsonify(request='error',msg='Exception rised in database.')
        else: return flask.jsonify(result='error', msg='Session expired, please relogin.')

    return flask.jsonify(result='error', msg='Method not allowed.')


@appAHQ.route('/uploads/<filename>')
# not used.
def uploaded_file(filename):
    return send_from_directory(appAHQ.config['UPLOAD_FOLDER'],
                               filename)


@appAHQ.route('/user/unityFiles', methods=['GET', 'POST','DELETE'])
# POST   : Upload a user's csv file . @require('sessionID', path/to/file)
# GET    : Download a user's csv file. @require('sessionID', 'index')
# DELETE : Delete a user's csv file. @require('sessionID', 'index')
def unityFile_operation():
    if request.method == 'POST':
        file = request.files['file']
        sessionID = request.form['sessionID']
        if (auth_sessionID(sessionID)):
            user = sessionID.split("-")[0]
            # if user in database
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    # file.save(os.path.join(appAHQ.config['UPLOAD_FOLDER'], filename))
                    insertFile(user, file)
                    file_url = url_for('uploaded_file', filename=filename)
                except BaseException as e:
                    print(e)
                return flask.jsonify(result='succeed')
            else: return flask.jsonify(result='error', msg='File format is not allowed.')
        else:
            return flask.jsonify(result='error', msg='Session expired, please relogin.')
    if request.method == 'GET':
        try:
            sessionID = request.headers.get('sessionID')
            index = request.headers.get('index')
            if sessionID == '' or None:
                return flask.jsonify(result='error', msg="Can't resolve sessionID in Headers.")
        except :
            return flask.jsonify(result='error', msg="Can't resolve sessionID in Headers.")
        if auth_sessionID(sessionID):
            user = sessionID.split("-")[0]
            try:
                index= int(index)
            except BaseException :
                data = getFile(user, -1)
            else:
                data = getFile(user, index)

            if isinstance(data, bool):
                return flask.jsonify(result='error', msg='File requested is not in the list.')
            else:
                response = make_response(data)
                response.headers['Content-Type'] = 'text/javascript'
                return response
        else:
            return flask.jsonify(result='error', msg='Session expired or not found, please relogin.')
    if request.method == 'DELETE':
        try:
            sessionID = request.form['sessionID']
            index = request.form['index']
            if sessionID == '' or None:
                return flask.jsonify(result='error', msg="SessionID field is required. It should be a form-data in request body.")
            if index == '' or None:
                return flask.jsonify(result='error', msg="Index field is required. It should be a form-data in request body.")
        except :
            return flask.jsonify(result='error', msg="Can't resolve the request. Maybe field 'sessionID' or 'index' is /are missing.")
        if auth_sessionID(sessionID):
            user = sessionID.split("-")[0]
            try:
                index= int(index)
            except BaseException :
                return flask.jsonify(result='error', msg='Index should be a number.')
            else:
                delFile(user, index)
                return flask.jsonify(result='succeed')
        else:
            return flask.jsonify(result='error', msg='Session expired or not found, please relogin.')
    return flask.jsonify(result='error', msg='Method is not allowed.')


@appAHQ.route('/user/unityFiles/list', methods=['GET'])
# Client look up for the list of the unity files he/she posted to the server.
# The server will return (if succeed) -> 'list' will contain the datetime of each files uploaded by this user, sorted by time, use the index number of the list to download a file.
# 				{
#     				"list": [
#         					"Tue, 01 May 2018 07:46:36 GMT",
#         					"Tue, 01 May 2018 07:55:59 GMT"
#     				],
#     				"result": "succeed"
# 				}
#@require('sessionID')
def query_file():
    if request.method == 'GET':
        try:
            sessionID = request.headers.get('sessionID')
            if sessionID == '' or None:
                return flask.jsonify(result='error', msg="Can't resolve sessionID in Headers.")
        except :
            return flask.jsonify(result='error', msg="Can't resolve sessionID in Headers.")
        if auth_sessionID(sessionID):
            user = sessionID.split("-")[0]
            data = listFiles(user)
            print(data)
            if isinstance(data, bool):
                return flask.jsonify(result='error', msg='File requested is not in the list.')
            else:
                # response = make_response(data)
                # response.headers['Content-Type'] = 'text/javascript'
                # return response
                return flask.jsonify(result='succeed', list=data)
        else:
            return flask.jsonify(result='error', msg='Session expired or not found, please relogin.')
    return flask.jsonify(result='error', msg="The method for this request should be GET.")


@appAHQ.route('/database/init', methods=['POST','GET'])
# for testing: delete all data in database
def db_init():
    try:
        models.get_user().drop()
        models.get_athleteInfo().drop()
        models.get_coach().drop()
        models.get_unityFile_chunks().drop()
        models.get_unityFile_files().drop()
        return flask.jsonify(result='succeed')
    except Exception :
        return flask.jsonify(result='error',msg='Fail to drop records, try it later.')

@appAHQ.route('/api',methods=['GET'])
# redirect to Server ReadMe on google doc.
def api_rep():
    return flask.redirect('https://docs.google.com/document/d/1asK1bBoYSrgqPpCFO0ju6M-wvnhKEaP9io8UNG5l8vQ/edit?usp=sharing')