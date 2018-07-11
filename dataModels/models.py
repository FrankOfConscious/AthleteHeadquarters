import pymongo
from app import db
from mongoengine import *
import datetime

# 返回一个 collection

client = pymongo.MongoClient('127.0.0.1', 27017)
db_query = client.test
def get_user():

    # client = pymongo.MongoClient('127.0.0.1', 27017)
    # db = client.test
    user = db_query.user
    return user

def get_coach():
    # client = pymongo.MongoClient('127.0.0.1', 27017)
    # db = client.test
    coach = db_query.coach
    return coach

def get_athleteInfo():
    # client = pymongo.MongoClient('127.0.0.1', 27017)
    # db = client.test
    info = db_query.athlete_info
    return info

def get_unityFile_files():
    files=db_query.unityFile.files
    return files

def get_unityFile_chunks():
    chunks=db_query.unityFile.chunks
    return chunks

def get_athlete_data_package(email):
    coaches = get_coach().find({"email": email})
    athletes = coaches[0]['athletes']
    athlete_list = []
    for ath in athletes:
        ath_info = get_athleteInfo().find({"athlete": ath})[0]
        data = {
            "email": ath_info['athlete'],
            "bio": {
                "DOB": ath_info['DOB'],
                "height": ath_info['height'],
                "weight": ath_info['weight'],
                "fatRate": ath_info['bodyFat'],
                "chest": ath_info['chest'],
                "abdomen": ath_info['abdomen'],
                "thigh": ath_info['thigh'],
                "tricep": ath_info['tricep'],
                "subscap": ath_info['subscap'],
                "hip": ath_info['hip'],
                "midAxi": ath_info['midAxi']
            },
            "mainObs": ath_info['majorGoal'],
            "subObs": ath_info['subGoal'],
            "techs": ath_info['technique'],
            "mobilitys": ath_info['mobility'],
            "nutritions": ath_info['nutrition'],
            "recoverys": ath_info['recovery']
        }
        athlete_list.append(data)
    return athlete_list


class Coach(db.DynamicDocument):
    email=db.EmailField(required=True, unique=True)
    athletes=db.ListField(default=[])

class AthleteInfo(db.DynamicDocument):
    athlete=EmailField(required=True,unique=True)
    coaches=ListField(default=[])
    genTime=DateTimeField()
    DOB=db.StringField(default='')
    height=FloatField(default=0)
    weight=FloatField(default=0)
    bodyFat=FloatField(default=0)
    chest=FloatField(default=0)
    abdomen=FloatField(default=0)
    thigh=FloatField(default=0)
    tricep=FloatField(default=0)
    subscap=FloatField(default=0)
    hip=FloatField(default=0)
    midAxi=FloatField(default=0)
    recovery=ListField(default=[])
    nutrition=ListField(default=[])
    technique=ListField(default=[])
    mobility=ListField(default=[])
    majorGoal=ListField(default=[])
    subGoal=ListField(default=[])



class User(db.DynamicDocument):

    password= db.StringField(min_length=8, max_length=80, required=True)
    email =db.EmailField(required=True , unique=True)
    rfidTag =db.StringField(default='')
    role = db.StringField(choices=('Athlete','Coach','Not Set'), default='Not Set' )
    expireTime = db.DateTimeField()

    def __str__(self):
        return "[role: {} -- email: {} -- password: {} -- tag:{}] ".format(self.role,self.email, self.password, self.rfidTag)

    @staticmethod
    def query_users():
        users = get_user().find()
        return users

class Data(db.DynamicDocument):
    # meta = {
    #     'collection': '
    #     'ordering': ['-create_at'],
    #     'strict': False,
    # }
    password= db.StringField(min_length=6, max_length=80, required=True)
    email =db.EmailField(required=True , unique=True)
    rfidTag =db.StringField()
    role = db.StringField(choices=('Athlete','Coach'))

    #
    # def __init__(self, password, email):
    #     self.password = password
    #     self.email = email

    def __str__(self):
        return "[role: {} -- email: {} -- password: {} -- tag:{}] ".format(self.role,self.email, self.password, self.rfidTag)

