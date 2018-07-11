import csv

from bson.objectid import ObjectId
from flask import json, url_for
from gridfs import *
from pymongo import MongoClient

from app import db

def insertFile(username, file):
    client = MongoClient('localhost', 27017)
    db = client.test
    fs = GridFS(db, collection='unityFile')

    # with open (file,'rb') as myimage:
    #     data=myimage.read()
    id = fs.put(file,filename=username)
    print (id)
def getFile(username, index):
    try:
        print(index)
        client = MongoClient('localhost', 27017)
        db = client.test
        fs = GridFS(db,collection='unityFile')
        file = fs.get_version(username, index)# 0 : most ancient file
        data = file.read()
    except :
        data=False
        return data
    else:
        return data
    # str='static/{}.csv'.format(username)
    # out = open(str,'wb')
    # out.write(data)
    # out.close()
    # link=url_for('.static',_external=True, filename=username+'.csv')
    # return link

def delFile(username, index):
    client = MongoClient('localhost', 27017)
    db = client.test
    fs = GridFS(db,collection='unityFile')
    file=fs.get_version(username, index)
    id=file._id
    fs.delete(ObjectId(id))

def listName(username):
    client = MongoClient('localhost', 27017)
    db = client.test
    fs = GridFS(db, collection='unityFile')
    # fileList = db.find({"filename": username})
    # fs = GridFS(db,collection= 'unityFile.files')
    return fs.list()

def listFiles(username):
    client = MongoClient('localhost', 27017)
    db = client.test
    list = db.unityFile.files.find({"filename":username})
    timelist=[]
    for file in list:
        timelist.append(file['uploadDate'])
    timelist.sort()
    return timelist
# listName()