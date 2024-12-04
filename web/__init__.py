from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from dotenv import load_dotenv
from flask_socketio import SocketIO

load_dotenv('env.txt')
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')  # 세션 관리에 필요한 키
hash_salt = os.getenv('HASH_SALT')

# 프로필 이미지 저장 경로 설정
PROFILE_IMG_FOLDER = os.getenv('PROFILE_IMG_FOLDER')
POST_IMG_FOLDER = os.getenv('POST_IMG_FOLDER')

# 경로가 없으면 폴더를 생성
if not os.path.exists(PROFILE_IMG_FOLDER):
    os.makedirs(PROFILE_IMG_FOLDER)

if not os.path.exists(POST_IMG_FOLDER):
    os.makedirs(POST_IMG_FOLDER)

# Flask의 config 설정
app.config['PROFILE_IMG_FOLDER'] = PROFILE_IMG_FOLDER
app.config['POST_IMG_FOLDER'] = POST_IMG_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# models에서 정의한 db를 가져와 초기화
from web.models import db
db.init_app(app)
migrate = Migrate(app, db)  # Flask-Migrate 연결

# 라우트 모듈 가져오기
import web.routes