import hashlib

import pymongo
from app import db
from mongoengine import *
import datetime

# 返回一个 collection
from dataModels import models
from dataModels.models import get_coach
from dataModels.unityFileOp import delFile


def get_coll():

    client = pymongo.MongoClient('127.0.0.1', 27017)
    db = client.test
    user = db.user
    return user


username="frank444@gmail.com"
index=0

delFile(username, index)



def unlink(user, target_email):

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
    #
    # if coach is None or coach.count()==0: #user has no coach profile
    #     athlete=models.get_athleteInfo().find({"athlete":user})
    #     if athlete is None or athlete.count()==0: #user has no athlete_info profile
    #         return 0
    #     else: #user has an athlete_info profile
    #         coachList=athlete[0]["coaches"]
    #         if target_email in coachList:
    #             coachList=[x for x in coachList if x != target_email]
    #
    #
    #
    # else:


# print(user)