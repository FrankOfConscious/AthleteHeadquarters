from flask import Flask
from flask_argon2 import Argon2
from flask_mongoengine import MongoEngine

appAHQ = Flask(__name__ ,template_folder='templates')
argon2 =Argon2(appAHQ)

# test 是链接的数据库
appAHQ.config['MONGODB_SETTINGS'] = {'db': 'test'}
# app.config['MONGODB_DB'] = 'test'
# app.config['MONGODB_HOST'] = '127.0.0.1'
# app.config['MONGODB_PORT'] = 27017
# app.config['MONGODB_USERNAME'] = 'admin'
# app.config['MONGODB_PASSWORD'] = '12345'

# 实例化
db = MongoEngine(appAHQ)

from app import routes


