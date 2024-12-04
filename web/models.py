from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    mbti = db.Column(db.String(10), nullable=True)
    profile_image = db.Column(db.String(200), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    recommendations = db.relationship('Recommendation', backref='user', lazy=True)
    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message', backref='recipient', lazy=True, foreign_keys='Message.recipient_id')
    chat_messages = db.relationship('ChatMessage', backref='author', lazy=True)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mbti_type = db.Column(db.String(10), nullable=False)  # MBTI 유형별 채팅 구분
    user_id = db.Column(db.String(80), db.ForeignKey('user.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_post_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.String(80), db.ForeignKey('user.user_id'), nullable=False)
    views = db.Column(db.Integer, default=0)
    recommendations = db.Column(db.Integer, default=0)
    file_path = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(50), nullable=False)

    comments = db.relationship('Comment', backref='post', cascade='all, delete')
    recommendations_relation = db.relationship('Recommendation', backref='post', cascade='all, delete')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)
    author_id = db.Column(db.String(80), db.ForeignKey('user.user_id'), nullable=False)

class Recommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey('user.user_id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)
    category = db.Column(db.String(50), nullable=False)

    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_recommendation'),)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(80), db.ForeignKey('user.user_id'), nullable=False)  # 발신자
    recipient_id = db.Column(db.String(80), db.ForeignKey('user.user_id'), nullable=False)  # 수신자
    subject = db.Column(db.String(200), nullable=False)  # 제목
    content = db.Column(db.Text, nullable=False)  # 내용
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)  # 전송 시간
    is_read = db.Column(db.Boolean, default=False)  # 메시지 읽음 상태 추가
