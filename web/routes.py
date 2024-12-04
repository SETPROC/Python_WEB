from flask import render_template, request, redirect, url_for, session, flash, make_response, jsonify
from web import app, db
from web.models import User, Post, Comment,Recommendation,Message,ChatMessage
import hashlib
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import pytz
from sqlalchemy import desc, or_
from sqlalchemy.orm import joinedload
from flask import g
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_socketio import SocketIO, join_room, leave_room, emit
import random
import string
from dotenv import load_dotenv
from collections import defaultdict
from markupsafe import Markup

# 방별 유저 목록을 저장하는 딕셔너리
rooms_users = defaultdict(set)


socketio = SocketIO(app,manage_session=False)
load_dotenv('env.txt')
#이메일 발송 설정
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

hash_salt = os.getenv('HASH_SALT')

# 허용된 파일 확장자 목록
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_email(recipient, subject, body):
    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:  # TLS 포트 587
            server.starttls()  # TLS 활성화
            server.login(SMTP_USER, SMTP_PASSWORD)  # 로그인
            server.sendmail(SMTP_USER, recipient, msg.as_string())  # 이메일 전송
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")

# 어드민 확인 함수
def is_admin():
    return session.get('user_id') == 'admin'

# 채팅방 라우트
@app.route('/chat/<mbti_type>')
def chat(mbti_type):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(user_id=session['user_id']).first()
    if not user:
        flash("사용자 정보를 찾을 수 없습니다.", "danger")
        return redirect(url_for('login'))

    messages = ChatMessage.query.filter_by(mbti_type=mbti_type).options(joinedload(ChatMessage.author)).order_by(ChatMessage.timestamp).all()
    return render_template('chat.html', mbti_type=mbti_type, messages=messages, user_mbti=user.mbti, is_admin=is_admin())

# SocketIO 이벤트 핸들러
@socketio.on('join')
def handle_join(data):
    mbti_type = data['mbti_type']
    user_id = session.get('user_id')
    user = User.query.filter_by(user_id=user_id).first()

    if not is_admin() and user.mbti != mbti_type:
        return

    join_room(mbti_type)
    rooms_users[mbti_type].add(user_id)

    emit('user_list', list(rooms_users[mbti_type]), room=mbti_type)
    emit('status', {
        'msg': f'{user_id}님이 입장하였습니다.',
        'is_admin': is_admin()
    }, room=mbti_type)

@socketio.on('message')
def handle_message(data):
    mbti_type = data['mbti_type']
    user_id = session.get('user_id')
    user = User.query.filter_by(user_id=user_id).first()

    if not is_admin() and user.mbti != mbti_type:
        emit('error', {'msg': '해당 MBTI 채팅방에 메시지를 전송할 수 없습니다.'})
        return

    new_message = ChatMessage(mbti_type=mbti_type, user_id=user_id, content=data['message'])
    db.session.add(new_message)
    db.session.commit()

    profile_image = url_for('static', filename=user.profile_image) if user.profile_image else url_for('static', filename='img/default_profile.png')

    # 어드민 여부를 함께 전송
    emit('message', {
        'user_id': user_id,
        'msg': data['message'],
        'timestamp': datetime.now(pytz.timezone('Asia/Seoul')).strftime('%H:%M:%S'),
        'id': new_message.id,
        'profile_image': profile_image,
        'is_admin': is_admin()  # 어드민 여부 추가
    }, room=mbti_type)

# 메시지 삭제 라우트 (어드민 전용)
@app.route('/chat/<mbti_type>/delete_message/<int:message_id>', methods=['POST'])
def delete_message(mbti_type, message_id):
    if not is_admin():
        flash("권한이 없습니다.", "danger")
        return redirect(url_for('chat', mbti_type=mbti_type))

    message = ChatMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()

    flash("메시지가 삭제되었습니다.", "success")
    return redirect(url_for('chat', mbti_type=mbti_type))

# 메시지 삭제 이벤트 핸들러
@socketio.on('delete_message')
def handle_delete_message(data):
    message_id = data['id']
    mbti_type = data['mbti_type']

    if is_admin():
        message = ChatMessage.query.get(message_id)
        if message and message.mbti_type == mbti_type:
            db.session.delete(message)
            db.session.commit()
            emit('message_deleted', {'id': message_id}, room=mbti_type)
@socketio.on('leave')
def handle_leave(data):
    mbti_type = data['mbti_type']
    user_id = session.get('user_id')

    leave_room(mbti_type)
    rooms_users[mbti_type].discard(user_id)

    emit('user_list', list(rooms_users[mbti_type]), room=mbti_type)
    emit('status', {
        'msg': f'{user_id}님이 퇴장하였습니다.',
        'is_admin': is_admin()
    }, room=mbti_type)

            
@app.route('/find_id', methods=['POST'])
def find_id():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        # 이메일로 아이디 전송
        subject = "아이디 찾기 안내"
        body = f"회원님의 아이디는 {user.user_id} 입니다."
        send_email(user.email, subject, body)
        flash("아이디가 이메일로 발송되었습니다.", "success")
    else:
        flash("해당 이메일을 사용하는 계정을 찾을 수 없습니다.", "danger")
    
    return redirect(url_for('forgot'))

def generate_reset_token(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.route('/find_password', methods=['POST'])
def find_password():
    user_id = request.form['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    
    if user:
        # reset_token 생성 및 저장
        reset_token = generate_reset_token()
        user.reset_token = reset_token
        db.session.commit()
        
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        subject = "비밀번호 초기화 요청"
        body = f"비밀번호를 초기화하려면 다음 링크를 클릭하세요: {reset_link}"
        send_email(user.email, subject, body)
        
        flash("비밀번호 초기화 링크가 이메일로 발송되었습니다.", "success")
    else:
        flash("해당 아이디를 사용하는 계정을 찾을 수 없습니다.", "danger")
    
    return redirect(url_for('forgot'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first_or_404()
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            new_password = new_password + hash_salt
            hash_object = hashlib.sha256(new_password.encode('utf-8'))
            hash_pw = hash_object.hexdigest()
            user.password = hash_pw
            user.reset_token = None  # 사용한 토큰 삭제
            db.session.commit()
            flash("비밀번호가 성공적으로 초기화되었습니다.", "success")
            return redirect(url_for('login'))
        else:
            flash("비밀번호가 일치하지 않습니다.", "danger")
    
    return render_template('reset_password.html', token=token)

@app.before_request
def before_request():
    # 세션에 user_id가 있는 경우, 읽지 않은 메시지 수를 가져옴
    if 'user_id' in session:
        user_id = session['user_id']
        session['unread_count'] = Message.query.filter_by(recipient_id=user_id, is_read=False).count()
    else:
        session['unread_count'] = 0

@app.route('/')
def index():
    # 세션에 'user_id'가 있으면 로그인 상태
    if 'user_id' in session:
        return render_template('index.html', logged_in=True, user_id=session['user_id'])
    else:
        return render_template('index.html', logged_in=False)


@app.route('/mbtidescription')
def mbti_descript():
    return render_template('/mbtidescription.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password = password + hash_salt
        hash_object = hashlib.sha256(password.encode('utf-8'))
        hash_pw = hash_object.hexdigest()
        user = User.query.filter_by(user_id=username).first()

        if user and user.password == hash_pw:
            session['user_id'] = user.user_id
            return redirect(url_for('index'))
        else:
            flash('아이디 또는 비밀번호가 일치하지 않습니다.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # 세션에서 사용자 정보 삭제
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['user_id']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        mbti = request.form.get('mbti')  # 라디오 버튼으로 선택된 MBTI 값 가져오기

        # 비밀번호 일치 확인
        if password == confirm_password:
            # 중복 사용자 확인 (user_id 또는 email이 중복되는지 체크)
            existing_user = User.query.filter((User.user_id == user_id) | (User.email == email)).first()
            if existing_user is None:
                pw = password + hash_salt
                hash_object = hashlib.sha256(pw.encode('utf-8'))
                hash_pw = hash_object.hexdigest()
                # 새로운 사용자 저장
                new_user = User(user_id=user_id, email=email, password=hash_pw, mbti=mbti)
                db.session.add(new_user)
                db.session.commit()

                # 세션에 사용자 ID 저장 (로그인된 상태로 유지)
                session['user_id'] = user_id
                return redirect(url_for('index'))  # 회원가입 성공 후 메인 페이지로 이동
            else:
                flash('아이디나 이메일이 이미 사용 중입니다.', 'error') 
        else:
            flash('비밀번호가 일치하지 않습니다.', 'error') 

    return render_template('register.html')

#찾기 페이지
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    return render_template('forgot.html')


@app.route('/<category>')
def post_list(category):
    # 경로 구분: 특정 페이지로 바로 이동해야 하는 경우
    if category in ['login', 'profile', 'messages', 'forgot', 'register', 'logout', 'mbtidescription']:
        return redirect(url_for(category))
    
    # 카테고리 유효성 검증 (필요 시 확장 가능)
    valid_categories = ['free', 'discussion', 'concern', 'love']
    
    if category not in valid_categories:
        # 잘못된 카테고리일 경우 메인 페이지로 리다이렉트
        return redirect(url_for('index'))
    
    # 검색어를 받음
    search_query = request.args.get('search', '')
    mbti_filter = request.args.get('mbti_filter', '')  # MBTI 필터링 받기

    # 기본적으로 해당 카테고리의 게시글을 가져옴
    page = request.args.get('page', 1, type=int)
    
    query = Post.query.filter(Post.category == category)

    if search_query:
        # 검색어가 있을 경우 제목 또는 본문에서 검색어 포함 게시글 조회
        query = query.filter(
            (Post.title.ilike(f'%{search_query}%')) | 
            (Post.content.ilike(f'%{search_query}%'))
        )

    if mbti_filter:
        # MBTI 필터링이 있을 경우 해당 MBTI를 가진 작성자만 필터링
        query = query.join(User).filter(User.mbti == mbti_filter)

    posts = query.order_by(Post.created_at.desc()).paginate(page=page, per_page=10)

    # 응답 생성 및 캐시 비활성화
    response = make_response(render_template('post_list.html', category=category, posts=posts, search_query=search_query, mbti_filter=mbti_filter))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


@app.route('/<category>/write', methods=['GET', 'POST'])
def create_post(category):
    if request.method == 'POST':
        title = request.form['title']  # 제목
        content = request.form['content']  # 본문

        # 파일 업로드 처리
        file = request.files.get('image')  # 'image' 이름으로 파일을 받음
        file_path = None  # 파일 경로 초기화
        if file:
            # 파일이 첨부되었고, 허용된 형식인지 확인
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['POST_IMG_FOLDER'], filename)

                # 중복된 파일명 처리
                base, ext = os.path.splitext(filename)  # 파일명과 확장자 분리
                counter = 1
                while os.path.exists(file_path):
                    new_filename = f"{base}_{counter}{ext}"
                    file_path = os.path.join(app.config['POST_IMG_FOLDER'], new_filename)
                    counter += 1

                # 파일 저장
                file.save(file_path)
                # 파일 경로를 데이터베이스에 저장할 때는 'post_img/filename' 형태로 저장
                file_path = f"post_img/{os.path.basename(file_path)}"
            else:
                # 파일 형식이 허용되지 않으면 플래시 메시지를 띄우고 글쓰기 페이지로 리다이렉트
                flash('이미지 파일만 업로드할 수 있습니다. (png, jpg, jpeg, gif)', 'danger')
                return redirect(url_for('create_post', category=category))

        # 현재 로그인한 사용자의 ID와 MBTI 값 가져오기 (세션에서)
        user_id = session.get('user_id')
        user = User.query.filter_by(user_id=user_id).first()

        # 카테고리별로 가장 큰 category_post_id 값을 가져와서 1을 더함
        max_category_post_id = db.session.query(db.func.max(Post.category_post_id)).filter_by(category=category).scalar()
        next_category_post_id = (max_category_post_id or 0) + 1

        # 새 게시글 객체 생성
        new_post = Post(
            title=title,
            content=content,
            author_id=user.user_id,
            file_path=file_path,
            category=category,  # 카테고리 정보 저장
            category_post_id=next_category_post_id,  # 카테고리별 고유 게시글 번호
            created_at=datetime.now(pytz.timezone('Asia/Seoul'))  # 현재 시간
        )

        # 데이터베이스에 게시글 저장
        db.session.add(new_post)
        db.session.commit()

        flash('게시글이 성공적으로 등록되었습니다.', 'success')
        return redirect(url_for('post_list', category=category))
    
    # GET 요청 처리 (페이지 로드)
    return render_template('create_post.html', category=category)


@app.route('/<category>/content')
def content(category):
    # category_post_id를 URL에서 가져옴
    category_post_id = request.args.get('post_id', type=int)

    # 카테고리와 category_post_id를 기반으로 게시글 조회
    post = Post.query.filter_by(category=category, category_post_id=category_post_id).first()

    if not post:
        flash('해당 게시글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('post_list', category=category))

    # 조회수 증가
    post.views += 1
    db.session.commit()  # 변경 사항을 데이터베이스에 반영

    return render_template('content.html', category=category, post=post)

@app.route('/<category>/comment/<int:post_id>', methods=['POST'])
def create_comment(category, post_id):
    # 로그인한 사용자 확인
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    # 폼에서 댓글 내용 가져오기
    content = request.form.get('content')

    if not content:
        flash('댓글 내용을 입력해주세요.', 'danger')
        return redirect(url_for('content', category=category, post_id=post_id))

    # 사용자 정보 가져오기
    user = User.query.filter_by(user_id=session['user_id']).first()

    # 게시글 가져오기
    post = Post.query.filter_by(category=category, category_post_id=post_id).first()

    if not post:
        flash('해당 게시글을 찾을 수 없습니다.', 'danger')
        return redirect(url_for('post_list', category=category))

    # 댓글 객체 생성
    new_comment = Comment(
        content=content,
        author_id=user.user_id,
        post_id=post.id
    )

    # 댓글 저장
    db.session.add(new_comment)
    db.session.commit()

    flash('댓글이 성공적으로 작성되었습니다.', 'success')
    return redirect(url_for('content', category=category, post_id=post_id))


@app.route('/messages', methods=['GET', 'POST'])
def messages():
    user_id = session.get('user_id')

    if not user_id:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    # 사용자가 받은 쪽지 목록 가져오기 (최신순으로 정렬)
    messages = Message.query.filter_by(recipient_id=user_id).order_by(desc(Message.sent_at)).all()

    selected_message = None
    if request.method == 'POST':
        # 삭제 버튼을 클릭한 경우
        if 'delete_message' in request.form:
            message_id = request.form['delete_message']
            message_to_delete = Message.query.filter_by(id=message_id, recipient_id=user_id).first()
            if message_to_delete:
                db.session.delete(message_to_delete)
                db.session.commit()
                flash('쪽지가 삭제되었습니다.', 'success')
            return redirect(url_for('messages'))

        # 쪽지 선택 처리
        selected_message_id = request.form.get('selected_messages')
        if selected_message_id:
            selected_message = Message.query.filter_by(id=selected_message_id, recipient_id=user_id).first()

    return render_template('messages.html', messages=messages, selected_message=selected_message)


@app.route('/messages/write', methods=['GET', 'POST'])
def send_message():
    recipient = request.args.get('recipient', '')  # GET 요청으로 전달된 recipient 값
    if request.method == 'POST':
        recipient_id = request.form.get('recipient')
        subject = request.form.get('subject')
        content = request.form.get('message')
        sender_id = session.get('user_id')

        # 필드 검증
        if not recipient_id or not subject or not content:
            flash('모든 필드를 채워주세요.', 'danger')
            return redirect(url_for('send_message', recipient=recipient_id))

        # 수신자 확인
        recipient = User.query.filter_by(user_id=recipient_id).first()
        if not recipient:
            flash('존재하지 않는 수신자입니다.', 'danger')
            return redirect(url_for('send_message', recipient=recipient_id))

        # 쪽지 저장
        new_message = Message(sender_id=sender_id, recipient_id=recipient_id, subject=subject, content=content)
        db.session.add(new_message)
        db.session.commit()
        flash('쪽지가 전송되었습니다.', 'success')
        return redirect(url_for('messages'))

    return render_template('send_message.html', recipient=recipient)  # recipient 값을 템플릿으로 전달

# 한국 시간대 (KST)
kst = pytz.timezone('Asia/Seoul')

@app.route('/message/details/<int:message_id>', methods=['GET'])
def get_message_details(message_id):
    user_id = session.get('user_id')

    if not user_id:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    # Message 인스턴스를 가져옵니다.
    message = Message.query.filter_by(id=message_id, recipient_id=user_id).first_or_404()

    # 메시지를 읽은 것으로 표시
    if not message.is_read:
        message.is_read = True
        db.session.commit()
        
    # User 테이블에서 sender_id를 기준으로 mbti 정보를 가져옵니다.
    sender = User.query.filter_by(user_id=message.sender_id).first()
    sender_mbti = sender.mbti if sender and sender.mbti else 'N/A'

    # UTC로 저장된 시간을 KST로 변환
    sent_at_kst = message.sent_at.astimezone(kst)
    sent_at_formatted = sent_at_kst.strftime('%Y-%m-%d %p %I:%M')

    response = {
        'id': message.id,
        'sender_id': message.sender_id,
        'sender_mbti': sender_mbti,
        'content': message.content,
        'sent_at': sent_at_formatted
    }

    return jsonify(response)


@app.route('/delete_messages', methods=['POST'])
def delete_messages():
    selected_message_ids = request.form.getlist('message_ids')  # 선택된 메시지 ID 목록
    if selected_message_ids:
        # 선택된 메시지를 삭제
        Message.query.filter(Message.id.in_(selected_message_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash('선택된 메시지가 삭제되었습니다.', 'success')
    else:
        flash('삭제할 메시지를 선택하세요.', 'danger')
    return redirect(url_for('messages'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # 로그인한 사용자 확인
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    # 데이터베이스에서 현재 사용자 정보를 가져옴
    user = User.query.filter_by(user_id=session['user_id']).first()

    if request.method == 'POST':
        # 이메일 변경 처리
        new_email = request.form.get('email')
        if new_email and new_email != user.email:
            # 이메일 중복 확인
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user:
                flash('이미 사용 중인 이메일입니다.', 'danger')
                return redirect(url_for('profile'))
            user.email = new_email  # 중복이 없을 때만 업데이트

        # 프로필 이미지 업로드 처리
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file:
                if allowed_file(file.filename):
                    filename = secure_filename(f"{session['user_id']}_profile.{file.filename.rsplit('.', 1)[1].lower()}")
                    file_path = os.path.join(app.config['PROFILE_IMG_FOLDER'], filename)
                    file.save(file_path)
                    user.profile_image = f"profile_img/{filename}"
                else:
                    flash('허용되지 않는 파일 형식입니다. (png, jpg, jpeg, gif)', 'danger')
                    return redirect(url_for('profile'))

        # 새로운 MBTI 값 처리
        new_mbti = request.form.get('mbti')
        if new_mbti and new_mbti != user.mbti:
            user.mbti = new_mbti

        # 비밀번호 변경 처리
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        if new_password:
            if new_password == confirm_password:
                hash_pw = hashlib.sha256((new_password + hash_salt).encode('utf-8')).hexdigest()
                user.password = hash_pw
            else:
                flash('비밀번호가 일치하지 않습니다.', 'danger')
                return redirect(url_for('profile'))

        db.session.commit()
        flash('프로필이 성공적으로 업데이트되었습니다.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/remove_profile_image', methods=['POST'])
def remove_profile_image():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "로그인이 필요합니다."}), 403

    user = User.query.filter_by(user_id=session['user_id']).first()
    if not user:
        return jsonify({"success": False, "message": "사용자를 찾을 수 없습니다."}), 404

    # 현재 프로필 이미지 경로를 가져옴
    profile_image_path = user.profile_image
    if profile_image_path:
        # 프로필 이미지 경로에서 파일명을 추출하여 실제 파일 경로 생성
        file_path = os.path.join('web', 'static', profile_image_path)
        
        # 파일이 존재하면 삭제
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # 프로필 이미지 경로를 None으로 설정하여 삭제
        user.profile_image = None
        db.session.commit()

    return jsonify({"success": True, "message": "프로필 이미지가 성공적으로 삭제되었습니다."})


@app.route('/delete_account', methods=['POST'])
def delete_account():
    user = User.query.filter_by(user_id=session['user_id']).first()
    if not user:
        flash("사용자 정보를 찾을 수 없습니다.", "danger")
        return redirect(url_for('profile'))
    
    try:
        # 프로필 이미지가 존재하면 삭제
        if user.profile_image:
            profile_image_path = os.path.join('web', 'static', user.profile_image)
            if os.path.exists(profile_image_path):
                os.remove(profile_image_path)

        # 관련된 모든 데이터 삭제
        Post.query.filter_by(author_id=user.user_id).delete()
        Comment.query.filter_by(author_id=user.user_id).delete()
        ChatMessage.query.filter_by(user_id=user.user_id).delete()
        Recommendation.query.filter_by(user_id=user.user_id).delete()
        Message.query.filter((Message.sender_id == user.user_id) | (Message.recipient_id == user.user_id)).delete()
        
        # 사용자 삭제
        db.session.delete(user)
        db.session.commit()
        
        flash("회원 탈퇴가 완료되었습니다.", "success")
        session.pop('user_id', None)  # 세션에서 사용자 정보 삭제
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash("회원 탈퇴 중 오류가 발생했습니다.", "danger")
        return redirect(url_for('profile'))
    
@app.route('/<category>/delete/<int:post_id>', methods=['POST'])
def delete_post(category, post_id):
    # 게시글 조회
    post = Post.query.filter_by(category=category, category_post_id=post_id).first_or_404()
    
    # 세션에 저장된 사용자 ID가 작성자와 일치하거나 admin일 경우에만 삭제 가능
    if 'user_id' not in session or (session['user_id'] != post.author.user_id and session['user_id'] != 'admin'):
        flash('삭제 권한이 없습니다.', 'danger')
        return redirect(url_for('post_list', category=category))
    
    # 첨부 파일이 있는 경우 파일 삭제 처리
    if post.file_path:
        file_path = os.path.join(app.config['POST_IMG_FOLDER'], post.file_path.split('/')[-1])
        if os.path.exists(file_path):
            os.remove(file_path)

    # 게시글 삭제 처리 (cascade 옵션으로 연결된 추천과 댓글도 자동 삭제)
    db.session.delete(post)
    db.session.commit()

    flash('게시글이 삭제되었습니다.', 'success')
    return redirect(url_for('post_list', category=category))

@app.route('/<category>/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(category, comment_id):
    # 댓글 조회
    comment = Comment.query.get_or_404(comment_id)
    
    # 댓글과 연결된 post 객체를 명시적으로 로드하여 세션에 유지
    post = Post.query.get(comment.post_id)

    # 세션에 저장된 사용자 ID가 댓글 작성자이거나 admin일 경우에만 삭제 가능
    if 'user_id' not in session or (session['user_id'] != comment.author.user_id and session['user_id'] != 'admin'):
        flash('댓글 삭제 권한이 없습니다.', 'danger')
        return redirect(url_for('content', category=category, post_id=post.category_post_id))

    # 댓글 삭제 처리
    db.session.delete(comment)
    db.session.commit()

    flash('댓글이 삭제되었습니다.', 'success')
    return redirect(url_for('content', category=category, post_id=post.category_post_id))

@app.route('/<category>/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(category, post_id):
    post = Post.query.filter_by(category=category, category_post_id=post_id).first_or_404()
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files.get('image')

        # 기존 파일 경로 저장
        original_file_path = post.file_path

        if file:
            # 파일이 첨부되었고, 허용된 형식인지 확인
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                new_file_path = os.path.join(app.config['POST_IMG_FOLDER'], filename)

                # 중복된 파일명 처리
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(new_file_path):
                    new_filename = f"{base}_{counter}{ext}"
                    new_file_path = os.path.join(app.config['POST_IMG_FOLDER'], new_filename)
                    counter += 1

                # 기존 파일 삭제 처리
                if original_file_path:
                    old_file_path = os.path.join(app.config['POST_IMG_FOLDER'], original_file_path.split('/')[-1])
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                # 새 파일 저장
                file.save(new_file_path)
                # 새로운 파일 경로를 설정
                post.file_path = f"post_img/{os.path.basename(new_file_path)}"
            else:
                flash('이미지 파일만 업로드할 수 있습니다. (png, jpg, jpeg, gif)', 'danger')
                return redirect(url_for('edit_post', category=category, post_id=post_id))
        else:
            # 파일을 업로드하지 않으면 기존 파일 경로를 유지
            post.file_path = original_file_path

        # 제목과 내용을 업데이트
        post.title = title
        post.content = content
        db.session.commit()

        flash('게시글이 수정되었습니다.', 'success')
        return redirect(url_for('content', category=category, post_id=post_id))

    # GET 요청 처리 (페이지 로드) - 기존 데이터를 전달
    return render_template('edit_post.html', post=post, category=category)

@app.route('/<category>/recommend/<int:post_id>', methods=['POST'])
def recommend_post(category, post_id):
    # 로그인한 사용자 확인
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    post = Post.query.filter_by(category=category, category_post_id=post_id).first()

    if not post:
        flash('게시글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('post_list', category=category))

    # 이미 추천했는지 확인
    existing_recommendation = Recommendation.query.filter_by(user_id=user_id, post_id=post.id).first()
    if existing_recommendation:
        flash('이미 이 게시글을 추천하셨습니다.', 'danger')
        return redirect(url_for('content', category=category, post_id=post_id))

    # 새로운 추천 생성 - 카테고리 정보 포함
    new_recommendation = Recommendation(user_id=user_id, post_id=post.id, category=post.category)
    db.session.add(new_recommendation)

    # 게시글 추천 수 증가
    post.recommendations += 1
    db.session.commit()

    flash('추천이 반영되었습니다.', 'success')
    return redirect(url_for('content', category=category, post_id=post_id))

@app.route('/search_all', methods=['GET', 'POST'])
def search_all():
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)

    if search_query:
        # 검색어가 있는 경우 전체 게시판에서 제목 또는 본문에 검색어를 포함하는 게시글 조회
        posts = Post.query.filter(
            (Post.category.in_(['free', 'love', 'concern', 'discussion'])) &
            ((Post.title.ilike(f'%{search_query}%')) | (Post.content.ilike(f'%{search_query}%')))
        ).order_by(Post.created_at.desc()).paginate(page=page, per_page=10)
    else:
        # 검색어가 없는 경우 기본적으로 전체 게시판의 모든 게시글을 조회
        posts = Post.query.filter(
            Post.category.in_(['free', 'love', 'concern', 'discussion'])
        ).order_by(Post.created_at.desc()).paginate(page=page, per_page=10)

    # 검색 결과를 템플릿으로 전달
    return render_template('search_all.html', posts=posts, search_query=search_query)

# 관리자 페이지 라우트
@app.route('/admin')
def admin_dashboard():
    if not is_admin():
        flash("권한이 없습니다.", "danger")
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/user/<user_id>')
def view_user(user_id):
    if not is_admin():
        flash("권한이 없습니다.", "danger")
        return redirect(url_for('index'))

    user = User.query.filter_by(user_id=user_id).first_or_404()
    posts = Post.query.filter_by(author_id=user.user_id).order_by(Post.created_at.desc()).all()
    comments = Comment.query.filter_by(author_id=user.user_id).order_by(Comment.created_at.desc()).all()
    chat_messages = ChatMessage.query.filter_by(user_id=user.user_id).order_by(ChatMessage.timestamp.desc()).all()
    
    return render_template('view_user.html', user=user, posts=posts, comments=comments, chat_messages=chat_messages)

@app.route('/admin/delete_chats', methods=['POST'])
def delete_chats():
    data = request.get_json()
    ids = data.get('ids', [])
    ChatMessage.query.filter(ChatMessage.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'message': '선택된 채팅이 삭제되었습니다.'})

@app.route('/admin/delete_posts', methods=['POST'])
def delete_posts():
    data = request.get_json()
    ids = data.get('ids', [])
    Post.query.filter(Post.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'message': '선택된 게시글이 삭제되었습니다.'})

@app.route('/admin/delete_comments', methods=['POST'])
def delete_comments():
    data = request.get_json()
    ids = data.get('ids', [])
    Comment.query.filter(Comment.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'message': '선택된 댓글이 삭제되었습니다.'})

# 회원 탈퇴 라우트
@app.route('/admin/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin():
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('admin_board'))

    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('존재하지 않는 사용자입니다.', 'danger')
        return redirect(url_for('admin_board'))

    try:
        # 연관된 게시글, 댓글, 채팅 메시지, 추천, 쪽지 삭제
        Post.query.filter_by(author_id=user.user_id).delete()
        Comment.query.filter_by(author_id=user.user_id).delete()
        ChatMessage.query.filter_by(user_id=user.user_id).delete()
        Recommendation.query.filter_by(user_id=user.user_id).delete()
        Message.query.filter((Message.sender_id == user.user_id) | (Message.recipient_id == user.user_id)).delete()

        # 사용자 삭제
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': '회원이 성공적으로 탈퇴되었습니다.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '회원 탈퇴 중 오류가 발생했습니다.'}), 500

# MBTI 테스트 질문 리스트
questions = {
    "E_I": [
        "다른 사람과의 대화를 통해 에너지를 얻는다.",
        "혼자 있는 시간보다는 사람들과 함께 있는 시간이 더 좋다.",
        "낯선 사람과 쉽게 친해질 수 있다.",
        "많은 사람 앞에서 이야기하는 것을 즐긴다.",
        "대화를 주도적으로 이끌어 나가는 편이다."
    ],
    "S_N": [
        "세부적인 정보를 먼저 이해하려고 한다.",
        "현실적이고 실용적인 방법을 선호한다.",
        "현재의 문제에 집중하는 편이다.",
        "새로운 가능성보다는 확인된 결과를 믿는다.",
        "구체적인 데이터나 사실을 중요하게 생각한다."
    ],
    "T_F": [
        "결정을 내릴 때 논리적 이유를 우선한다.",
        "문제 해결에 있어 감정보다 사실을 중시한다.",
        "갈등 상황에서 공정성을 중요하게 생각한다.",
        "비판을 받더라도 잘 받아들이는 편이다.",
        "효율성과 생산성을 중시한다."
    ],
    "P_J": [
        "계획적인 생활을 선호한다.",
        "일의 마감을 지키는 것이 중요하다.",
        "정해진 일정에 따라 움직이는 것을 좋아한다.",
        "계획 없이 일하는 것은 스트레스를 준다.",
        "예측 가능한 상황을 선호한다."
    ]
}

# MBTI 결과 계산 함수
def calculate_mbti(answers):
    score = {'E': 0, 'I': 0, 'S': 0, 'N': 0, 'T': 0, 'F': 0, 'P': 0, 'J': 0}
    categories = list(questions.keys())
    for i, answer in enumerate(answers):
        category = categories[i // 5]
        if answer == '매우 그렇다':
            if category == 'E_I':
                score['E'] += 2
            elif category == 'S_N':
                score['S'] += 2
            elif category == 'T_F':
                score['T'] += 2
            elif category == 'P_J':
                score['P'] += 2
        elif answer == '그렇다':
            if category == 'E_I':
                score['E'] += 1
            elif category == 'S_N':
                score['S'] += 1
            elif category == 'T_F':
                score['T'] += 1
            elif category == 'P_J':
                score['P'] += 1
        elif answer == '그렇지 않다':
            if category == 'E_I':
                score['I'] += 1
            elif category == 'S_N':
                score['N'] += 1
            elif category == 'T_F':
                score['F'] += 1
            elif category == 'P_J':
                score['J'] += 1
        elif answer == '매우 그렇지 않다':
            if category == 'E_I':
                score['I'] += 2
            elif category == 'S_N':
                score['N'] += 2
            elif category == 'T_F':
                score['F'] += 2
            elif category == 'P_J':
                score['J'] += 2

    # 동점 여부 확인
    is_tie = (
        score['E'] == score['I'] or
        score['S'] == score['N'] or
        score['T'] == score['F'] or
        score['P'] == score['J']
    )

    # MBTI 계산
    mbti = (
        ('E' if score['E'] > score['I'] else 'I') +
        ('S' if score['S'] > score['N'] else 'N') +
        ('T' if score['T'] > score['F'] else 'F') +
        ('P' if score['P'] > score['J'] else 'J')
    )
    return mbti, is_tie


@app.route('/mbti', methods=['GET', 'POST'])
def mbti():
    # 세션 초기화
    if 'current_index' not in session:
        session['current_index'] = 0
        session['answers'] = []

    current_index = session['current_index']
    all_questions = [q for category in questions.values() for q in category]

    if request.method == 'POST':
        action = request.form.get('action')  # 'prev' 또는 'next'

        if action == 'next':  # 다음 버튼
            answer = request.form.get('answer')
            if not answer:
                flash('답변을 선택해주세요.', 'danger')
                return redirect(url_for('mbti'))

            # 현재 질문의 답변을 저장 또는 수정
            if current_index < len(session['answers']):
                session['answers'][current_index] = answer
            else:
                session['answers'].append(answer)

            # 마지막 질문이 아닌 경우 인덱스 증가
            if current_index < len(all_questions) - 1:
                session['current_index'] += 1
            else:
                # 마지막 질문의 답변까지 저장 후 결과 페이지로 이동
                result, is_tie = calculate_mbti(session['answers'])
                session.pop('current_index', None)
                session.pop('answers', None)
                return render_template('mbti_result.html', result=result, is_tie=is_tie)

        elif action == 'prev':  # 이전 버튼
            # 이전 버튼은 라디오 버튼 값 검사를 건너뜀
            if current_index > 0:
                session['current_index'] -= 1

        session.modified = True
        return redirect(url_for('mbti'))

    # 현재 질문 반환
    current_question = all_questions[current_index]
    return render_template('mbti.html', question=current_question, current_index=current_index)

# MBTI 결과 페이지 라우트
@app.route('/mbti/result')
def mbti_result():
    return render_template('mbti_result.html')

@app.route('/update_mbti', methods=['POST'])
def update_mbti():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.', 'danger')
        return redirect(url_for('login'))

    new_mbti = request.form.get('new_mbti')
    user = User.query.filter_by(user_id=session['user_id']).first()

    if not user:
        flash('사용자 정보를 찾을 수 없습니다.', 'danger')
        return redirect(url_for('profile'))

    try:
        user.mbti = new_mbti
        db.session.commit()
        flash(Markup(f"MBTI가 '{new_mbti}'(으)로 성공적으로 변경되었습니다."), 'success')
    except Exception as e:
        db.session.rollback()
        flash("MBTI 변경 중 오류가 발생했습니다.", 'danger')

    return redirect(url_for('profile'))
# if __name__ == '__main__':
#     app.run(host='0.0.0.0',port= 5000,debug=True)