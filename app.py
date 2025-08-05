from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from db_model import User, Message, Friend, db, SecurityLog
from id_generation import generate_id
from functools import wraps
import hashlib
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Database configuration for Vercel compatibility
def get_database_url():
    """Get database URL with proper format for different environments"""
    # For Vercel deployment, always use SQLite to avoid PostgreSQL build issues
    if os.environ.get('VERCEL'):
        return 'sqlite:///user_data.db'
    
    # For local development, use DATABASE_URL if provided
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Convert postgres:// to postgresql:// for compatibility
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        return database_url
    
    return 'sqlite:///user_data.db'

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # Only send cookies over HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS attacks
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Session timeout

# Vercel-specific configuration
if os.environ.get('VERCEL'):
    # Disable session cookies for serverless (use JWT or similar for production)
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    # Use in-memory storage for rate limiting (not ideal for serverless)
    rate_limit_storage = {}

# Apply ProxyFix for proper IP detection behind proxies
if os.environ.get('FLASK_ENV') == 'production' and not os.environ.get('VERCEL'):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

db.init_app(app)

# Rate limiting storage
rate_limit_storage = {}

def rate_limit(max_requests=5, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            current_time = time.time()
            key = f"{client_ip}:{f.__name__}"
            
            # Clean old entries
            if key in rate_limit_storage:
                rate_limit_storage[key] = [t for t in rate_limit_storage[key] if current_time - t < window]
            else:
                rate_limit_storage[key] = []
            
            # Check rate limit
            if len(rate_limit_storage[key]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
            
            # Add current request
            rate_limit_storage[key].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Security: Enhanced input validation
def validate_username(username):
    """Validate username format with enhanced security"""
    if not username or len(username) < 3 or len(username) > 20:
        return False
    # Only allow alphanumeric characters and underscores, no special characters
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    # Check for common attack patterns
    if any(pattern in username.lower() for pattern in ['admin', 'root', 'system', 'test']):
        return False
    return True

def validate_message_content(content):
    """Validate message content with enhanced security"""
    if not content or len(content.strip()) == 0:
        return False
    if len(content) > 1000:  # Limit message length
        return False
    # Check for potentially malicious content
    dangerous_patterns = [
        r'<script', r'javascript:', r'vbscript:', r'onload=', r'onerror=',
        r'<iframe', r'<object', r'<embed', r'<form', r'<input'
    ]
    content_lower = content.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, content_lower):
            return False
    return True

def sanitize_input(text):
    """Enhanced sanitize user input to prevent XSS"""
    if not text:
        return ""
    # Remove potentially dangerous HTML tags and attributes
    text = re.sub(r'<script.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<.*?javascript:.*?>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<.*?on\w+\s*=.*?>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<.*?>', '', text)
    # Remove any remaining potentially dangerous characters
    text = text.replace('javascript:', '').replace('vbscript:', '')
    return text.strip()

def validate_user_id(user_id):
    """Validate user ID format"""
    if not user_id or len(user_id) != 10:
        return False
    # Check if user_id contains only valid characters
    return bool(re.match(r'^[a-zA-Z0-9]{10}$', user_id))

# Enhanced login required decorator with session validation
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login_page'))
        
        # Validate session
        user_id = session['user_id']
        if not validate_user_id(user_id):
            session.clear()
            flash('Invalid session. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
        # Check if user still exists
        user = User.query.filter_by(id=user_id).first()
        if not user:
            session.clear()
            flash('User not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
        return f(*args, **kwargs)
    return decorated_function

# Enhanced password hashing
def hash_password(password):
    """Enhanced password hashing using werkzeug"""
    return generate_password_hash(password, method='pbkdf2:sha256')

def verify_password(password_hash, password):
    """Verify password using werkzeug"""
    return check_password_hash(password_hash, password)

# Update user's online status
def update_user_status(user_id, is_online=True):
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.is_online = is_online
        user.last_seen = datetime.utcnow()
        db.session.commit()

# Get online users (users active in last 5 minutes)
def get_online_users():
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(
        User.last_seen >= five_minutes_ago
    ).all()
    return online_users

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# Security logging
def log_security_event(user_id, action, success=True, ip_address=None, user_agent=None):
    """Log security events for audit trail"""
    try:
        if not ip_address:
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ',' in ip_address:
                ip_address = ip_address.split(',')[0].strip()
        
        if not user_agent:
            user_agent = request.headers.get('User-Agent', '')
        
        security_log = SecurityLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )
        
        db.session.add(security_log)
        db.session.commit()
    except Exception as e:
        # Don't let logging errors break the application
        print(f"Security logging error: {e}")

# Account lockout functionality
def check_account_lockout(user):
    """Check if account is locked due to failed login attempts"""
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return False

def lock_account(user, duration_minutes=15):
    """Lock account for specified duration"""
    user.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
    user.login_attempts = 0
    db.session.commit()

def increment_login_attempts(user):
    """Increment failed login attempts"""
    user.login_attempts += 1
    if user.login_attempts >= 5:  # Lock after 5 failed attempts
        lock_account(user)
    db.session.commit()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat', user_id=session['user_id']))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('chat', user_id=session['user_id']))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if 'user_id' in session:
        return redirect(url_for('chat', user_id=session['user_id']))
    return render_template('register.html')

@app.route('/register', methods=['POST'])
@rate_limit(max_requests=3, window=300)  # 3 attempts per 5 minutes
def register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Input validation
    if not username or not password or not confirm_password:
        flash('All fields are required.', 'error')
        return redirect(url_for('register_page'))
    
    if not validate_username(username):
        flash('Username must be 3-20 characters long and contain only letters, numbers, and underscores.', 'error')
        return redirect(url_for('register_page'))
    
    # Enhanced password validation
    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'error')
        return redirect(url_for('register_page'))
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('register_page'))
    
    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists.', 'error')
        return redirect(url_for('register_page'))
    
    # Create new user with enhanced security
    user_id = generate_id()
    hashed_password = hash_password(password)
    
    new_user = User(
        id=user_id,
        username=username,
        password=hashed_password
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login_page'))
    except Exception as e:
        db.session.rollback()
        flash('Registration failed. Please try again.', 'error')
        return redirect(url_for('register_page'))

@app.route('/login', methods=['POST'])
@rate_limit(max_requests=5, window=300)  # 5 attempts per 5 minutes
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Input validation
    if not username or not password:
        flash('Username and password are required.', 'error')
        log_security_event(None, 'login_failed', success=False)
        return redirect(url_for('login_page'))
    
    # Sanitize input
    username = sanitize_input(username)
    
    # Find user
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('Invalid username or password.', 'error')
        log_security_event(None, 'login_failed', success=False)
        return redirect(url_for('login_page'))
    
    # Check if account is locked
    if check_account_lockout(user):
        flash('Account is temporarily locked due to too many failed login attempts. Please try again later.', 'error')
        log_security_event(user.id, 'login_locked', success=False)
        return redirect(url_for('login_page'))
    
    if verify_password(user.password, password):
        # Clear any existing session
        session.clear()
        
        # Reset login attempts on successful login
        user.login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        # Set session data
        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True
        
        # Update user status
        update_user_status(user.id, True)
        
        # Log successful login
        log_security_event(user.id, 'login_success', success=True)
        
        flash('Login successful!', 'success')
        return redirect(url_for('chat', user_id=user.id))
    else:
        # Increment failed login attempts
        increment_login_attempts(user)
        
        flash('Invalid username or password.', 'error')
        log_security_event(user.id, 'login_failed', success=False)
        return redirect(url_for('login_page'))

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    if user_id:
        # Log the logout event
        log_security_event(user_id, 'logout', success=True)
        # Update user status
        update_user_status(user_id, False)
    
    # Clear session
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login_page'))

@app.route('/chat/<user_id>')
@login_required
def chat(user_id):
    # Ensure user can only access their own chat
    if user_id != session['user_id']:
        flash('Access denied.', 'error')
        log_security_event(session['user_id'], 'unauthorized_access', success=False)
        return redirect(url_for('chat', user_id=session['user_id']))
    
    # Log chat access
    log_security_event(user_id, 'chat_access', success=True)
    
    user = User.query.filter_by(id=user_id).first()
    if not user:
        session.clear()
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login_page'))
    
    return render_template('chat.html', user_id=user_id, username=user.username)

# API Routes for online status
@app.route('/api/update_status', methods=['POST'])
@login_required
def update_status():
    """Update user's online status"""
    update_user_status(session['user_id'], True)
    return jsonify({'success': True})

@app.route('/api/online_users')
@login_required
def get_online_users_api():
    """Get list of online users"""
    online_users = get_online_users()
    users_list = []
    for user in online_users:
        if user.id != session['user_id']:  # Exclude current user
            users_list.append({
                'id': user.id,
                'username': user.username,
                'last_seen': user.last_seen.isoformat(),
                'is_online': user.is_online
            })
    return jsonify({'success': True, 'users': users_list})

@app.route('/api/search_user/<user_id>')
@login_required
@rate_limit(max_requests=10, window=60)  # 10 searches per minute
def search_user(user_id):
    # Validate user_id format
    if not validate_user_id(user_id):
        return jsonify({'success': False, 'error': 'Invalid user ID format'})
    
    # Prevent searching for own ID
    if user_id == session['user_id']:
        return jsonify({'success': False, 'error': 'Cannot search for your own ID'})
    
    user = User.query.filter_by(id=user_id).first()
    if user:
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'is_online': user.is_online,
                'last_seen': user.last_seen.isoformat() if user.last_seen else None
            }
        })
    return jsonify({'success': False, 'error': 'User not found'})

@app.route('/api/messages/<other_user_id>')
@login_required
@rate_limit(max_requests=30, window=60)  # 30 requests per minute
def get_messages(other_user_id):
    # Validate user_id format
    if not validate_user_id(other_user_id):
        return jsonify({'success': False, 'error': 'Invalid user ID format'})
    
    current_user_id = session['user_id']
    
    # Get messages between current user and other user
    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user_id))
    ).order_by(Message.timestamp).all()
    
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg.id,
            'content': sanitize_input(msg.content),  # Sanitize content
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'timestamp': msg.timestamp.isoformat()
        })
    
    return jsonify({'success': True, 'messages': message_list})

@app.route('/api/send_message', methods=['POST'])
@login_required
@rate_limit(max_requests=20, window=60)  # 20 messages per minute
def send_message():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request data'})
    
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    # Input validation
    if not receiver_id or not content:
        return jsonify({'success': False, 'error': 'Missing receiver_id or content'})
    
    if not validate_user_id(receiver_id):
        return jsonify({'success': False, 'error': 'Invalid receiver ID format'})
    
    if not validate_message_content(content):
        return jsonify({'success': False, 'error': 'Invalid message content'})
    
    # Check if receiver exists
    receiver = User.query.filter_by(id=receiver_id).first()
    if not receiver:
        return jsonify({'success': False, 'error': 'Receiver not found'})
    
    # Prevent sending message to self
    if receiver_id == session['user_id']:
        return jsonify({'success': False, 'error': 'Cannot send message to yourself'})
    
    # Sanitize message content
    sanitized_content = sanitize_input(content)
    
    # Create new message
    message = Message(
        content=sanitized_content,
        sender_id=session['user_id'],
        receiver_id=receiver_id
    )
    
    try:
        db.session.add(message)
        db.session.commit()
        return jsonify({
            'success': True, 
            'message_id': message.id,
            'sender_id': session['user_id']
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to send message'})

@app.route('/api/conversations')
@login_required
def get_conversations():
    current_user_id = session['user_id']
    
    # Get all conversations where the current user is involved
    conversations = db.session.query(
        Message.sender_id,
        Message.receiver_id,
        Message.content,
        Message.timestamp
    ).filter(
        (Message.sender_id == current_user_id) | (Message.receiver_id == current_user_id)
    ).order_by(Message.timestamp.desc()).all()
    
    # Group conversations by the other user
    conversation_map = {}
    
    for msg in conversations:
        # Determine the other user in the conversation
        other_user_id = msg.sender_id if msg.sender_id != current_user_id else msg.receiver_id
        
        if other_user_id not in conversation_map:
            conversation_map[other_user_id] = {
                'user_id': other_user_id,
                'last_message': msg.content,
                'timestamp': msg.timestamp
            }
    
    # Convert to list and get user information
    conversation_list = []
    for other_user_id, conv_data in conversation_map.items():
        other_user = User.query.filter_by(id=other_user_id).first()
        if other_user:
            conversation_list.append({
                'user_id': other_user_id,
                'username': other_user.username,
                'last_message': conv_data['last_message'],
                'timestamp': conv_data['timestamp'].isoformat()
            })
    
    # Sort by timestamp (most recent first)
    conversation_list.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({'success': True, 'conversations': conversation_list})

# Friend system routes
@app.route('/api/send_friend_request', methods=['POST'])
@login_required
def send_friend_request():
    data = request.get_json()
    friend_id = data.get('friend_id')
    current_user_id = session['user_id']
    
    if not friend_id or friend_id == current_user_id:
        return jsonify({'success': False, 'error': 'Invalid friend ID'})
    
    # Check if friend request already exists
    existing_request = Friend.query.filter(
        ((Friend.user_id == current_user_id) & (Friend.friend_id == friend_id)) |
        ((Friend.user_id == friend_id) & (Friend.friend_id == current_user_id))
    ).first()
    
    if existing_request:
        return jsonify({'success': False, 'error': 'Friend request already exists'})
    
    # Create friend request
    friend_request = Friend(
        user_id=current_user_id,
        friend_id=friend_id,
        status='pending'
    )
    
    try:
        db.session.add(friend_request)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Friend request sent'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to send friend request'})

@app.route('/api/friend_requests')
@login_required
def get_friend_requests():
    current_user_id = session['user_id']
    
    # Get pending friend requests where current user is the receiver
    requests = Friend.query.filter_by(
        friend_id=current_user_id,
        status='pending'
    ).all()
    
    request_list = []
    for req in requests:
        sender = User.query.filter_by(id=req.user_id).first()
        if sender:
            request_list.append({
                'id': req.id,
                'user_id': req.user_id,
                'username': sender.username,
                'created_at': req.created_at.isoformat()
            })
    
    return jsonify({'success': True, 'requests': request_list})

@app.route('/api/respond_friend_request', methods=['POST'])
@login_required
def respond_friend_request():
    data = request.get_json()
    request_id = data.get('request_id')
    response = data.get('response')  # 'accept' or 'reject'
    current_user_id = session['user_id']
    
    if not request_id or response not in ['accept', 'reject']:
        return jsonify({'success': False, 'error': 'Invalid parameters'})
    
    friend_request = Friend.query.filter_by(
        id=request_id,
        friend_id=current_user_id,
        status='pending'
    ).first()
    
    if not friend_request:
        return jsonify({'success': False, 'error': 'Friend request not found'})
    
    friend_request.status = 'accepted' if response == 'accept' else 'rejected'
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'Friend request {response}ed'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Failed to respond to friend request'})

@app.route('/api/friends')
@login_required
def get_friends():
    current_user_id = session['user_id']
    
    # Get accepted friendships
    friendships = Friend.query.filter(
        ((Friend.user_id == current_user_id) | (Friend.friend_id == current_user_id)) &
        (Friend.status == 'accepted')
    ).all()
    
    friend_list = []
    for friendship in friendships:
        # Determine the friend's ID
        friend_id = friendship.friend_id if friendship.user_id == current_user_id else friendship.user_id
        friend = User.query.filter_by(id=friend_id).first()
        
        if friend:
            friend_list.append({
                'id': friend.id,
                'username': friend.username,
                'is_online': friend.is_online,
                'last_seen': friend.last_seen.isoformat() if friend.last_seen else None
            })
    
    return jsonify({'success': True, 'friends': friend_list})

# Error handlers with security
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)