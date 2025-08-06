from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from db_model import User, Message, Friend, db, SecurityLog, AdminAction, SystemSettings
from id_generation import generate_id
from functools import wraps
import hashlib
import os
import re
import secrets
import time
import sys
import traceback
import base64
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Database configuration for production compatibility
def get_database_url():
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
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

# Apply ProxyFix for proper IP detection behind proxies
if os.environ.get('FLASK_ENV') == 'production':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

db.init_app(app)

# Database initialization flag
db_initialized = False

def ensure_db_initialized():
    """Ensure database tables are created"""
    global db_initialized
    if not db_initialized:
        try:
            with app.app_context():
                db.create_all()
                db_initialized = True
                print("Database tables created successfully")
        except Exception as e:
            print(f"Database initialization failed: {e}")
            import traceback
            traceback.print_exc()

# Rate limiting storage (simplified for serverless)
# Rate limiting disabled for better user experience

def rate_limit(max_requests=5, window=60):
    """Rate limiting decorator (disabled for better user experience)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Rate limiting disabled - always allow requests
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
        
        # Check if user still exists and is active
        user = User.query.filter_by(id=user_id).first()
        if not user:
            session.clear()
            flash('User not found. Please log in again.', 'error')
            return redirect(url_for('login_page'))
        
        if not user.is_active:
            session.clear()
            flash('Your account has been deactivated. Please contact an administrator.', 'error')
            return redirect(url_for('login_page'))
        
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login_page'))
        
        user = User.query.filter_by(id=session['user_id']).first()
        if not user or not user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

# Permission required decorator
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login_page'))
            
            user = User.query.filter_by(id=session['user_id']).first()
            if not user or not user.has_permission(permission):
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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

# File upload validation
def allowed_file(filename):
    """Check if file extension is allowed"""
    if not filename:
        return False
    
    allowed_extensions = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp',
        'doc', 'docx', 'zip', 'rar', '7z', 'mp3', 'mp4',
        'avi', 'mov', 'xlsx', 'xls', 'ppt', 'pptx'
    }
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Admin action logging
def log_admin_action(admin_id, action_type, target_user_id=None, action_details=None):
    """Log admin actions for audit trail"""
    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()
        
        admin_action = AdminAction(
            admin_id=admin_id,
            target_user_id=target_user_id,
            action_type=action_type,
            action_details=action_details,
            ip_address=ip_address
        )
        
        db.session.add(admin_action)
        db.session.commit()
    except Exception as e:
        print(f"Admin action logging error: {e}")

# System settings management
def get_system_setting(key, default=None):
    """Get a system setting value"""
    try:
        setting = SystemSettings.query.filter_by(setting_key=key).first()
        if setting:
            return setting.setting_value
        return default
    except Exception as e:
        print(f"Error getting system setting {key}: {e}")
        return default

def set_system_setting(key, value, setting_type='string', description=None, updated_by=None):
    """Set a system setting value"""
    try:
        setting = SystemSettings.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = value
            setting.setting_type = setting_type
            if description:
                setting.description = description
            if updated_by:
                setting.updated_by = updated_by
        else:
            setting = SystemSettings(
                setting_key=key,
                setting_value=value,
                setting_type=setting_type,
                description=description,
                updated_by=updated_by
            )
            db.session.add(setting)
        
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error setting system setting {key}: {e}")
        return False

# Message encryption functions
def get_encryption_key():
    """Get or generate encryption key"""
    key = get_system_setting('encryption_key')
    if not key:
        # Generate a new key
        key = secrets.token_hex(32)
        set_system_setting('encryption_key', key, 'string', 'Message encryption key')
    return key

def encrypt_message(message):
    """Encrypt a message"""
    try:
        if not get_system_setting('enable_message_encryption', 'false') == 'true':
            return message
        
        key = get_encryption_key()
        
        # Simple XOR encryption (for demonstration - use proper encryption in production)
        encrypted = ''
        for i, char in enumerate(message):
            key_char = key[i % len(key)]
            encrypted += chr(ord(char) ^ ord(key_char))
        
        # Add encryption indicator
        return f"🔒{base64.b64encode(encrypted.encode()).decode()}"
    except Exception as e:
        print(f"Encryption error: {e}")
        return message

def decrypt_message(encrypted_message):
    """Decrypt a message"""
    try:
        if not encrypted_message.startswith('🔒'):
            return encrypted_message
        
        # Remove encryption indicator
        encrypted_data = encrypted_message[1:]
        
        key = get_encryption_key()
        
        # Decode base64
        encrypted = base64.b64decode(encrypted_data).decode()
        
        # Simple XOR decryption
        decrypted = ''
        for i, char in enumerate(encrypted):
            key_char = key[i % len(key)]
            decrypted += chr(ord(char) ^ ord(key_char))
        
        return decrypted
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_message

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
    """Main route with database initialization"""
    try:
        ensure_db_initialized()
        if 'user_id' in session:
            return redirect(url_for('chat', user_id=session['user_id']))
        return redirect(url_for('login_page'))
    except Exception as e:
        print(f"Error in index route: {e}")
        return jsonify({'error': 'Database initialization failed'}), 500

@app.route('/health')
def health_check():
    """Enhanced health check endpoint with database status"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        db_status = 'connected'
    except Exception as e:
        db_status = f'error: {str(e)}'
    
    return jsonify({
        'status': 'healthy', 
        'message': 'Server is running',
        'database': db_status,
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'database_url': get_database_url()[:20] + '...' if len(get_database_url()) > 20 else get_database_url()
    })

@app.route('/debug')
def debug_info():
    """Debug endpoint to check environment and configuration"""
    try:
        ensure_db_initialized()
        return jsonify({
            'app_loaded': True,
            'database_initialized': db_initialized,
            'environment': os.environ.get('FLASK_ENV', 'development'),
            'database_url': get_database_url(),
            'secret_key_set': bool(app.config.get('SECRET_KEY')),
            'python_version': sys.version
        })
    except Exception as e:
        return jsonify({
            'app_loaded': True,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/emergency-debug')
def emergency_debug():
    """Emergency debug endpoint with full environment info"""
    try:
        return jsonify({
            'status': 'emergency_debug',
            'environment_vars': {k: v for k, v in os.environ.items() if 'KEY' not in k.upper() and 'PASSWORD' not in k.upper()},
            'app_config': {k: v for k, v in app.config.items() if 'SECRET' not in k.upper()},
            'working_dir': os.getcwd(),
            'files_in_root': os.listdir('.'),
            'python_version': sys.version,
            'database_url': get_database_url(),
            'railway_env': bool(os.environ.get('RAILWAY_ENVIRONMENT')),
            'render_env': bool(os.environ.get('RENDER'))
        })
    except Exception as e:
        return jsonify({
            'status': 'emergency_debug_error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

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
        # Decrypt message content
        decrypted_content = decrypt_message(msg.content) if msg.content else None
        message_data = {
            'id': msg.id,
            'content': sanitize_input(decrypted_content) if decrypted_content else None,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'timestamp': msg.timestamp.isoformat(),
            'has_attachment': msg.has_attachment or False
        }
        
        # Add attachment information if present
        if msg.has_attachment:
            message_data.update({
                'attachment_filename': msg.attachment_filename,
                'attachment_original_name': msg.attachment_original_name,
                'attachment_type': msg.attachment_type,
                'attachment_size': msg.attachment_size
            })
        
        message_list.append(message_data)
    
    return jsonify({'success': True, 'messages': message_list})

@app.route('/api/send_message', methods=['POST'])
@login_required
@rate_limit(max_requests=20, window=60)  # 20 messages per minute
def send_message():
    # Check if it's a file upload or JSON data
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        # Handle file upload
        receiver_id = request.form.get('receiver_id')
        content = request.form.get('content', '').strip()
        file = request.files.get('file')
    else:
        # Handle JSON data (legacy support)
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid request data'})
        
        receiver_id = data.get('receiver_id')
        content = data.get('content', '').strip()
        file = None
    
    # Input validation
    if not receiver_id:
        return jsonify({'success': False, 'error': 'Missing receiver_id'})
    
    if not content and not file:
        return jsonify({'success': False, 'error': 'Message must contain text or file attachment'})
    
    if not validate_user_id(receiver_id):
        return jsonify({'success': False, 'error': 'Invalid receiver ID format'})
    
    if content and not validate_message_content(content):
        return jsonify({'success': False, 'error': 'Invalid message content'})
    
    # Check if receiver exists
    receiver = User.query.filter_by(id=receiver_id).first()
    if not receiver:
        return jsonify({'success': False, 'error': 'Receiver not found'})
    
    # Prevent sending message to self
    if receiver_id == session['user_id']:
        return jsonify({'success': False, 'error': 'Cannot send message to yourself'})
    
    # Handle file upload
    attachment_filename = None
    attachment_original_name = None
    attachment_type = None
    attachment_size = None
    
    if file and file.filename:
        # Validate file
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': 'File type not allowed'})
        
        # Check file size (10MB limit)
        file.seek(0, 2)  # Seek to end of file
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            return jsonify({'success': False, 'error': 'File size must be less than 10MB'})
        
        # Generate secure filename
        import uuid
        import os
        file_ext = os.path.splitext(file.filename)[1].lower()
        attachment_filename = f"{uuid.uuid4().hex}{file_ext}"
        attachment_original_name = file.filename
        attachment_size = file_size
        
        # Determine file type
        if file_ext.lower() in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            attachment_type = 'image'
        elif file_ext.lower() in ['.pdf']:
            attachment_type = 'document'
        else:
            attachment_type = 'other'
        
        # Save file
        try:
            upload_path = os.path.join(app.static_folder, 'uploads', attachment_filename)
            os.makedirs(os.path.dirname(upload_path), exist_ok=True)
            file.save(upload_path)
        except Exception as e:
            return jsonify({'success': False, 'error': 'Failed to save file'})
    
    # Sanitize message content if present
    encrypted_content = None
    if content:
        sanitized_content = sanitize_input(content)
        encrypted_content = encrypt_message(sanitized_content)
    
    # Create new message
    message = Message(
        content=encrypted_content,
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        has_attachment=bool(file and file.filename),
        attachment_filename=attachment_filename,
        attachment_original_name=attachment_original_name,
        attachment_type=attachment_type,
        attachment_size=attachment_size
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
        # Clean up uploaded file if database save failed
        if attachment_filename:
            try:
                upload_path = os.path.join(app.static_folder, 'uploads', attachment_filename)
                if os.path.exists(upload_path):
                    os.remove(upload_path)
            except:
                pass
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
                        # Decrypt message for conversation list
            decrypted_content = decrypt_message(msg.content)
            conversation_map[other_user_id] = {
                'user_id': other_user_id,
                'last_message': decrypted_content,
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

# Admin Dashboard Routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    return redirect(url_for('admin_users'))

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin users management page"""
    return render_template('admin_users.html')

@app.route('/admin/messages')
@admin_required
def admin_messages():
    """Admin messages management page"""
    return render_template('admin_messages.html')

@app.route('/admin/logs')
@admin_required
def admin_logs():
    """Admin logs page"""
    return render_template('admin_logs.html')

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """Admin settings page"""
    return render_template('admin_settings.html')

@app.route('/setup-admin', methods=['GET', 'POST'])
def setup_admin():
    """Setup admin user for first deployment"""
    try:
        # Check if admin already exists
        admin_exists = User.query.filter_by(is_admin=True).first()
        
        if admin_exists:
            flash('Admin user already exists. Please log in.', 'info')
            return redirect(url_for('login_page'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email', '')
            
            # Validate input
            if not username or not password:
                flash('Username and password are required.', 'error')
                return render_template('setup_admin.html')
            
            if not validate_username(username):
                flash('Invalid username. Use 3-20 alphanumeric characters.', 'error')
                return render_template('setup_admin.html')
            
            if len(password) < 6:
                flash('Password must be at least 6 characters.', 'error')
                return render_template('setup_admin.html')
            
            # Check if username exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return render_template('setup_admin.html')
            
            # Create admin user
            from id_generation import generate_id
            admin_user = User(
                id=generate_id(),
                username=username,
                password=hash_password(password),
                is_admin=True,
                is_active=True,
                is_verified=True,
                role='super_admin',
                permissions='all',
                created_at=datetime.utcnow()
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            # Initialize system settings
            from create_admin import initialize_system_settings
            initialize_system_settings()
            
            flash('Admin user created successfully! You can now log in.', 'success')
            return redirect(url_for('login_page'))
        
        return render_template('setup_admin.html')
        
    except Exception as e:
        flash(f'Error creating admin: {str(e)}', 'error')
        return render_template('setup_admin.html')

# Admin API Routes
@app.route('/api/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_get_users():
    """Get all users for admin dashboard or create new user"""
    try:
        if request.method == 'POST':
            # Create new user
            data = request.get_json()
            admin_id = session['user_id']
            
            # Validate required fields
            if not data.get('username') or not data.get('password'):
                return jsonify({'success': False, 'error': 'Username and password are required'}), 400
            
            # Check if username already exists
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'success': False, 'error': 'Username already exists'}), 400
            
            # Validate username
            if not validate_username(data['username']):
                return jsonify({'success': False, 'error': 'Invalid username format'}), 400
            
            # Create new user
            from id_generation import generate_id
            new_user = User(
                id=generate_id(),
                username=data['username'],
                password=hash_password(data['password']),
                role=data.get('role', 'user'),
                is_admin=data.get('is_admin', False),
                is_active=data.get('is_active', True),
                is_verified=data.get('is_verified', False),
                permissions=data.get('permissions', ''),
                created_at=datetime.utcnow()
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            log_admin_action(admin_id, 'create_user', new_user.id, f"Created user: {data['username']}")
            
            return jsonify({
                'success': True, 
                'message': f'User {data["username"]} created successfully',
                'user_id': new_user.id
            })
        
        # GET request - return users list
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search', '')
        
        query = User.query
        
        if search:
            # Enhanced search - search by username, role, or status
            search_lower = search.lower()
            query = query.filter(
                db.or_(
                    User.username.contains(search),
                    User.role.contains(search_lower),
                    db.case(
                        (User.is_active == True, 'active'),
                        (User.is_active == False, 'inactive'),
                        else_='unknown'
                    ).contains(search_lower)
                )
            )
        
        users = query.paginate(page=page, per_page=per_page, error_out=False)
        
        user_list = []
        for user in users.items:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'is_verified': user.is_verified,
                'role': user.role,
                'permissions': user.permissions,
                'created_at': user.created_at.isoformat(),
                'last_seen': user.last_seen.isoformat() if user.last_seen else None,
                'is_online': user.is_online,
                'login_attempts': user.login_attempts,
                'notes': getattr(user, 'notes', '')  # Add notes field if it exists
            })
        
        return jsonify({
            'success': True,
            'users': user_list,
            'total': users.total,
            'pages': users.pages,
            'current_page': page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/user/<user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def admin_manage_user(user_id):
    """Manage a specific user"""
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if request.method == 'GET':
            return jsonify({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'is_admin': user.is_admin,
                    'is_active': user.is_active,
                    'is_verified': user.is_verified,
                    'role': user.role,
                    'permissions': user.permissions,
                    'created_at': user.created_at.isoformat(),
                    'last_seen': user.last_seen.isoformat() if user.last_seen else None,
                    'login_attempts': user.login_attempts,
                    'locked_until': user.locked_until.isoformat() if user.locked_until else None
                }
            })
        
        elif request.method == 'PUT':
            data = request.get_json()
            admin_id = session['user_id']
            
            # Update user fields
            if 'is_admin' in data:
                user.is_admin = data['is_admin']
                log_admin_action(admin_id, 'update_user_admin', user_id, f"Admin status: {data['is_admin']}")
            
            if 'is_active' in data:
                user.is_active = data['is_active']
                log_admin_action(admin_id, 'update_user_status', user_id, f"Active status: {data['is_active']}")
            
            if 'is_verified' in data:
                user.is_verified = data['is_verified']
                log_admin_action(admin_id, 'update_user_verified', user_id, f"Verified status: {data['is_verified']}")
            
            if 'role' in data:
                user.role = data['role']
                log_admin_action(admin_id, 'update_user_role', user_id, f"Role: {data['role']}")
            
            if 'permissions' in data:
                user.permissions = data['permissions']
                log_admin_action(admin_id, 'update_user_permissions', user_id, f"Permissions updated")
            
            if 'password' in data and data['password']:
                user.password = hash_password(data['password'])
                log_admin_action(admin_id, 'update_user_password', user_id, "Password updated")
            
            if 'notes' in data:
                # Add notes field if it doesn't exist in the model
                if hasattr(user, 'notes'):
                    user.notes = data['notes']
                    log_admin_action(admin_id, 'update_user_notes', user_id, "Notes updated")
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'User updated successfully'})
        
        elif request.method == 'DELETE':
            admin_id = session['user_id']
            
            # Hard delete - remove user completely
            username = user.username
            try:
                # Create admin action log entry (but don't commit yet)
                ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
                if ',' in ip_address:
                    ip_address = ip_address.split(',')[0].strip()
                
                admin_action = AdminAction(
                    admin_id=admin_id,
                    target_user_id=user_id,
                    action_type='delete_user',
                    action_details=f'User {username} deleted permanently',
                    ip_address=ip_address
                )
                db.session.add(admin_action)
                
                # Delete the user
                db.session.delete(user)
                db.session.commit()
                
                return jsonify({'success': True, 'message': f'User {username} deleted successfully'})
            except Exception as delete_error:
                db.session.rollback()
                return jsonify({'success': False, 'error': f'Failed to delete user: {str(delete_error)}'}), 500
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/messages')
@admin_required
def admin_get_messages():
    """Get messages for admin review"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        flagged_only = request.args.get('flagged_only', 'false').lower() == 'true'
        
        query = Message.query
        
        if flagged_only:
            query = query.filter_by(is_flagged=True)
        
        messages = query.order_by(Message.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        
        message_list = []
        for msg in messages.items:
            sender = User.query.filter_by(id=msg.sender_id).first()
            receiver = User.query.filter_by(id=msg.receiver_id).first()
            
            message_list.append({
                'id': msg.id,
                'content': msg.content,
                'sender': sender.username if sender else 'Unknown',
                'receiver': receiver.username if receiver else 'Unknown',
                'timestamp': msg.timestamp.isoformat(),
                'is_flagged': msg.is_flagged,
                'flagged_reason': msg.flagged_reason,
                'is_deleted': msg.is_deleted
            })
        
        return jsonify({
            'success': True,
            'messages': message_list,
            'total': messages.total,
            'pages': messages.pages,
            'current_page': page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/message/<message_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_manage_message(message_id):
    """Manage a specific message"""
    try:
        message = Message.query.filter_by(id=message_id).first()
        if not message:
            return jsonify({'success': False, 'error': 'Message not found'}), 404
        
        admin_id = session['user_id']
        
        if request.method == 'PUT':
            data = request.get_json()
            
            if 'is_flagged' in data:
                message.is_flagged = data['is_flagged']
                if data['is_flagged']:
                    message.flagged_reason = data.get('flagged_reason', 'Flagged by admin')
                    message.flagged_by = admin_id
                    message.flagged_at = datetime.utcnow()
                    log_admin_action(admin_id, 'flag_message', message.sender_id, f"Message {message_id} flagged")
                else:
                    message.flagged_reason = None
                    message.flagged_by = None
                    message.flagged_at = None
                    log_admin_action(admin_id, 'unflag_message', message.sender_id, f"Message {message_id} unflagged")
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Message updated successfully'})
        
        elif request.method == 'DELETE':
            # Soft delete
            message.is_deleted = True
            db.session.commit()
            
            log_admin_action(admin_id, 'delete_message', message.sender_id, f"Message {message_id} deleted")
            return jsonify({'success': True, 'message': 'Message deleted successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/logs')
@admin_required
def admin_get_logs():
    """Get admin action logs"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        log_type = request.args.get('type', 'all')  # all, security, admin
        
        if log_type == 'security':
            query = SecurityLog.query
        elif log_type == 'admin':
            query = AdminAction.query
        else:
            # Return both types
            security_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(per_page//2).all()
            admin_logs = AdminAction.query.order_by(AdminAction.timestamp.desc()).limit(per_page//2).all()
            
            log_list = []
            for log in security_logs:
                log_list.append({
                    'type': 'security',
                    'id': log.id,
                    'user_id': log.user_id,
                    'action': log.action,
                    'timestamp': log.timestamp.isoformat(),
                    'success': log.success,
                    'ip_address': log.ip_address
                })
            
            for log in admin_logs:
                log_list.append({
                    'type': 'admin',
                    'id': log.id,
                    'admin_id': log.admin_id,
                    'target_user_id': log.target_user_id,
                    'action_type': log.action_type,
                    'timestamp': log.timestamp.isoformat(),
                    'ip_address': log.ip_address
                })
            
            # Sort by timestamp
            log_list.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return jsonify({
                'success': True,
                'logs': log_list[:per_page],
                'total': len(log_list),
                'current_page': page
            })
        
        logs = query.order_by(query.column.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        
        log_list = []
        for log in logs.items:
            if log_type == 'security':
                log_list.append({
                    'type': 'security',
                    'id': log.id,
                    'user_id': log.user_id,
                    'action': log.action,
                    'timestamp': log.timestamp.isoformat(),
                    'success': log.success,
                    'ip_address': log.ip_address
                })
            else:
                log_list.append({
                    'type': 'admin',
                    'id': log.id,
                    'admin_id': log.admin_id,
                    'target_user_id': log.target_user_id,
                    'action_type': log.action_type,
                    'timestamp': log.timestamp.isoformat(),
                    'ip_address': log.ip_address
                })
        
        return jsonify({
            'success': True,
            'logs': log_list,
            'total': logs.total,
            'pages': logs.pages,
            'current_page': page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/stats')
@admin_required
def admin_get_stats():
    """Get system statistics"""
    try:
        from datetime import datetime, timedelta
        
        # Basic counts
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        admin_users = User.query.filter_by(is_admin=True).count()
        online_users = User.query.filter_by(is_online=True).count()
        total_messages = Message.query.count()
        flagged_messages = Message.query.filter_by(is_flagged=True).count()
        total_friendships = Friend.query.count()
        pending_friendships = Friend.query.filter_by(status='pending').count()
        
        # Time-based statistics
        one_month_ago = datetime.utcnow() - timedelta(days=30)
        new_users_month = User.query.filter(User.created_at >= one_month_ago).count()
        
        one_week_ago = datetime.utcnow() - timedelta(days=7)
        new_users_week = User.query.filter(User.created_at >= one_week_ago).count()
        
        today = datetime.utcnow().date()
        new_users_today = User.query.filter(
            db.func.date(User.created_at) == today
        ).count()
        
        # Role distribution
        role_stats = db.session.query(
            User.role, 
            db.func.count(User.id)
        ).group_by(User.role).all()
        
        role_distribution = {role: count for role, count in role_stats}
        
        # Recent activity
        recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
        recent_messages = Message.query.order_by(Message.timestamp.desc()).limit(5).all()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'active_users': active_users,
                'admin_users': admin_users,
                'online_users': online_users,
                'new_users_month': new_users_month,
                'new_users_week': new_users_week,
                'new_users_today': new_users_today,
                'total_messages': total_messages,
                'flagged_messages': flagged_messages,
                'total_friendships': total_friendships,
                'pending_friendships': pending_friendships,
                'role_distribution': role_distribution
            },
            'recent_users': [
                {
                    'id': user.id,
                    'username': user.username,
                    'created_at': user.created_at.isoformat()
                } for user in recent_users
            ],
            'recent_messages': [
                {
                    'id': msg.id,
                    'content': msg.content[:50] + '...' if len(msg.content) > 50 else msg.content,
                    'timestamp': msg.timestamp.isoformat()
                } for msg in recent_messages
            ]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings_api():
    """Get or update system settings"""
    try:
        if request.method == 'GET':
            # Get all system settings
            settings = SystemSettings.query.all()
            settings_dict = {}
            for setting in settings:
                settings_dict[setting.setting_key] = setting.setting_value
            
            return jsonify({
                'success': True,
                'settings': settings_dict
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            admin_id = session['user_id']
            
            # Update settings
            for key, value in data.items():
                set_system_setting(key, str(value), updated_by=admin_id)
            
            log_admin_action(admin_id, 'update_settings', action_details=f"Updated settings: {list(data.keys())}")
            
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully'
            })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/clear-logs', methods=['POST'])
@admin_required
def admin_clear_logs():
    """Clear all system logs"""
    try:
        admin_id = session['user_id']
        
        # Clear security logs
        SecurityLog.query.delete()
        
        # Clear admin action logs
        AdminAction.query.delete()
        
        db.session.commit()
        
        log_admin_action(admin_id, 'clear_logs', action_details='All logs cleared')
        
        return jsonify({
            'success': True,
            'message': 'All logs cleared successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/reset-settings', methods=['POST'])
@admin_required
def admin_reset_settings():
    """Reset all settings to defaults"""
    try:
        admin_id = session['user_id']
        
        # Delete all settings
        SystemSettings.query.delete()
        db.session.commit()
        
        # Reinitialize default settings
        from create_admin import initialize_system_settings
        initialize_system_settings()
        
        log_admin_action(admin_id, 'reset_settings', action_details='All settings reset to defaults')
        
        return jsonify({
            'success': True,
            'message': 'Settings reset to defaults successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/export-data')
@admin_required
def admin_export_data():
    """Export system data"""
    try:
        from flask import send_file
        import json
        import tempfile
        
        # Collect system data
        data = {
            'export_date': datetime.utcnow().isoformat(),
            'users': [],
            'messages': [],
            'settings': []
        }
        
        # Export users (without passwords)
        users = User.query.all()
        for user in users:
            data['users'].append({
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'role': user.role,
                'created_at': user.created_at.isoformat(),
                'last_seen': user.last_seen.isoformat() if user.last_seen else None
            })
        
        # Export messages
        messages = Message.query.all()
        for msg in messages:
            data['messages'].append({
                'id': msg.id,
                'content': msg.content,
                'sender_id': msg.sender_id,
                'receiver_id': msg.receiver_id,
                'timestamp': msg.timestamp.isoformat(),
                'is_flagged': msg.is_flagged,
                'is_deleted': msg.is_deleted
            })
        
        # Export settings
        settings = SystemSettings.query.all()
        for setting in settings:
            data['settings'].append({
                'key': setting.setting_key,
                'value': setting.setting_value,
                'type': setting.setting_type,
                'description': setting.description
            })
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f, indent=2)
            temp_file = f.name
        
        return send_file(temp_file, as_attachment=True, download_name=f'system-export-{datetime.now().strftime("%Y%m%d")}.json')
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Error handlers with security
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Enhanced 500 error handler with debugging"""
    import traceback
    import sys
    
    # Log the error details
    print(f"500 Error: {error}")
    print("Traceback:")
    traceback.print_exc()
    
    # Try to rollback database session if there's an active transaction
    try:
        db.session.rollback()
    except Exception as e:
        print(f"Database rollback failed: {e}")
    
    # Return a more informative error response
    return jsonify({
        'error': 'Internal server error',
        'message': 'Something went wrong. Please try again.',
        'debug_info': {
            'error_type': str(type(error).__name__),
            'error_message': str(error)
        }
    }), 500

# Rate limit error handler removed - no longer needed

if __name__ == '__main__':
    with app.app_context():
        ensure_db_initialized()
    app.run(debug=True, port=5001)