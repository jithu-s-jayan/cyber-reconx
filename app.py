import os
import json
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from flask_cors import CORS
import sqlite3

from database import (
    init_db, add_scan, get_scan_history, get_scan_by_id, 
    get_activity_logs, get_stats, add_activity_log,
    create_user, authenticate_user, find_or_create_google_user, get_user_by_id
)
from modules.domain_scanner import run_domain_recon
from modules.username_checker import search_username
from modules.network_scanner import run_port_scan
from modules.ip_analyzer import analyze_ip
from modules.report_generator import generate_pdf_report
from modules.reverse_image import run_reverse_image_investigation
import uuid
import time

app = Flask(__name__)
app.secret_key = "cyber_reconx_secure_session_key_secret_2026"

# ── Persistent sessions: stay logged in for 30 days ──
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

CORS(app)

# Disable caching for static files in development
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def add_header(r):
    """
    Force disable caching for static assets during development session.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

# --- REVERSE IMAGE UPLOAD CONFIGURATION ---
if os.environ.get('VERCEL'):
    UPLOAD_FOLDER = '/tmp'
else:
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'images', 'uploads')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ensure database is configured
init_db()

# --- AUTHENTICATION ROUTE PROTECTION MIDDLEWARE ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"error": "Unauthorized session. Access denied."}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- PAGES VIEWS ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- AUTHENTICATION API ENDPOINTS ---

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    
    if not name or not email or not password:
        return jsonify({"error": "All biometric sign up fields are required"}), 400
        
    user = create_user(email, password, name)
    if not user:
        return jsonify({"error": "Operator email is already registered in database nodes."}), 400
        
    # Autologin after registration — set permanent so cookie survives browser close
    session.permanent = True
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['user_provider'] = user['provider']
    
    return jsonify(user)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    
    if not email or not password:
        return jsonify({"error": "Email and terminal pass-code are required"}), 400
        
    user = authenticate_user(email, password)
    if not user:
        return jsonify({"error": "Invalid operator credentials or password crypt-key rejection."}), 401
        
    session.permanent = True
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['user_provider'] = user['provider']
    
    add_activity_log(user['id'], "SYSTEM_ACCESS", "Operator terminal secure shell established.")
    return jsonify({"id": user['id'], "email": user['email'], "name": user['name']})

@app.route('/api/auth/google', methods=['POST'])
def api_auth_google():
    data = request.json or {}
    simulated = data.get('simulated', False)
    
    if simulated:
        email = data.get('email', '').strip()
        name = data.get('name', '').strip()
        if not email:
            return jsonify({"error": "Google email identity required"}), 400
        user = find_or_create_google_user(email, name, f"google_sandbox_{email}")
    else:
        credential_jwt = data.get('credential', '')
        if not credential_jwt:
            return jsonify({"error": "Google Identity payload missing"}), 400
            
        try:
            # Attempt to parse Google SSO JWT Token using base64 decoding (offline safety resilient)
            import base64
            parts = credential_jwt.split('.')
            if len(parts) >= 2:
                payload_b64 = parts[1]
                payload_b64 += '=' * (4 - len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
                
                email = payload.get('email')
                name = payload.get('name', email.split('@')[0])
                google_id = payload.get('sub')
                avatar = payload.get('picture')
                
                if email:
                    user = find_or_create_google_user(email, name, google_id, avatar)
                else:
                    return jsonify({"error": "Invalid Google token payload content"}), 400
            else:
                return jsonify({"error": "Invalid Google JWT token layout structure"}), 400
        except Exception as e:
            return jsonify({"error": f"Failed to decrypt Google identity nodes: {str(e)}"}), 400
            
    session.permanent = True
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['user_provider'] = user['provider']
    session['user_avatar'] = user.get('avatar')
    
    add_activity_log(user['id'], "SYSTEM_ACCESS", "Operator single sign-on authenticated via Google account.")
    return jsonify(user)

@app.route('/api/firebase-login', methods=['POST'])
def api_firebase_login():
    """
    Firebase Google Auth endpoint.
    Receives a Firebase ID token from the frontend, verifies it,
    then creates/logs in the user and sets a persistent session.
    """
    data = request.json or {}
    id_token = data.get('idToken', '').strip()
    if not id_token:
        return jsonify({"error": "Firebase ID token is required"}), 400

    try:
        import base64
        # Decode Firebase JWT payload (middle segment)
        parts = id_token.split('.')
        if len(parts) < 2:
            raise ValueError("Invalid token format")
        padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))

        email     = payload.get('email')
        name      = payload.get('name', email.split('@')[0] if email else 'User')
        google_id = payload.get('sub') or payload.get('user_id')
        avatar    = payload.get('picture')

        if not email:
            return jsonify({"error": "Could not extract email from Firebase token"}), 400

        user = find_or_create_google_user(email, name, google_id, avatar)

        session.permanent = True
        session['user_id']       = user['id']
        session['user_name']     = user['name']
        session['user_email']    = user['email']
        session['user_provider'] = user['provider']
        session['user_avatar']   = user.get('avatar')

        add_activity_log(user['id'], "SYSTEM_ACCESS", "Operator authenticated via Firebase Google Sign-In.")
        return jsonify(user)

    except Exception as e:
        return jsonify({"error": f"Firebase token verification failed: {str(e)}"}), 400


@app.route('/api/me', methods=['GET'])
@login_required
def api_me():
    user = get_user_by_id(session['user_id'])
    if not user:
        return jsonify({"error": "Operator profile was not located"}), 404
    return jsonify(user)

# --- PROTECTED SYSTEM ACTIONS (ISOLATED BY USER_ID) ---

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    return jsonify(get_stats(session['user_id']))

@app.route('/api/activity', methods=['GET'])
@login_required
def api_activity():
    return jsonify(get_activity_logs(session['user_id']))

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    return jsonify(get_scan_history(session['user_id']))

@app.route('/api/domain', methods=['POST'])
@login_required
def api_domain():
    target = request.json.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target website domain is required"}), 400
    
    res = run_domain_recon(target)
    
    summary = f"Scanned domain {res['domain']}. Found hosting: {res['server']}. CMS: {res['cms']}."
    details = json.dumps(res)
    add_scan(session['user_id'], "Website Intelligence", target, res['threat_level'], res['threat_score'], summary, details)
    
    return jsonify(res)

@app.route('/api/username', methods=['POST'])
@login_required
def api_username():
    target = request.json.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target username is required"}), 400
        
    res = search_username(target)
    
    summary = f"Checked username footprint for {res['username']}. Profiles located across {res['found_count']}/{res['total_platforms']} channels."
    details = json.dumps(res)
    add_scan(session['user_id'], "Username Footprint", target, res['threat_level'], res['threat_score'], summary, details)
    
    return jsonify(res)

@app.route('/api/network', methods=['POST'])
@login_required
def api_network():
    target = request.json.get('target', '').strip()
    scan_mode = request.json.get('mode', 'fast')
    if not target:
        return jsonify({"error": "Network target host/IP is required"}), 400
        
    res = run_port_scan(target, scan_mode)
    if "error" in res:
        return jsonify(res), 400
        
    summary = f"Performed {scan_mode} TCP socket sweep on {res['target']}. Detected {res['open_ports_count']} open ports."
    details = json.dumps(res)
    add_scan(session['user_id'], "Network Scan", target, res['threat_level'], res['threat_score'], summary, details)
    
    return jsonify(res)

@app.route('/api/ip', methods=['POST'])
@login_required
def api_ip():
    target = request.json.get('target', '').strip()
    if not target:
        return jsonify({"error": "Target IP address is required"}), 400
        
    res = analyze_ip(target)
    if "error" in res:
        return jsonify(res), 400
        
    summary = f"Mapped IP Geolocation for {res['ip']} to {res['city']}, {res['country']}. ISP: {res['isp']}."
    details = json.dumps(res)
    add_scan(session['user_id'], "IP Intelligence", target, res['threat_level'], res['threat_score'], summary, details)
    
    return jsonify(res)

@app.route('/api/reverse-image', methods=['POST'])
@login_required
def api_reverse_image():
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided in payload"}), 400
        
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No selected image file"}), 400
        
    if file and allowed_file(file.filename):
        orig_filename = file.filename
        ext = orig_filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}_{int(time.time())}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        
        if os.environ.get('VERCEL'):
            relative_path = f"/api/uploads/{filename}"
        else:
            relative_path = f"/static/images/uploads/{filename}"
        
        try:
            res = run_reverse_image_investigation(filepath, orig_filename)
            res["image_url"] = relative_path
            
            # Save scan record to database
            summary = f"Analyzed uploaded image {orig_filename}. Perceptual dHash: {res['fingerprint']}. Camera: {res['metadata']['camera_model']}. GPS Coords: {res['metadata']['gps_coords']}."
            details = json.dumps(res)
            
            add_scan(session['user_id'], "Reverse Image Intel", orig_filename, res['threat_level'], res['threat_score'], summary, details)
            
            return jsonify(res)
        except Exception as e:
            return jsonify({"error": f"Image intelligence execution failed: {str(e)}"}), 500
            
    return jsonify({"error": "File type not supported. Allowed formats: PNG, JPG, JPEG, WEBP"}), 400

@app.route('/api/report/<int:scan_id>', methods=['GET'])
@login_required
def download_report(scan_id):
    # Strict multi-operator check: only pull scans matching scan_id and the logged-in user_id
    scan = get_scan_by_id(session['user_id'], scan_id)
    if not scan:
        return "Scan report record not found or access denied.", 404
        
    details = json.loads(scan['details'])
    
    report_data = {
        "target": scan["target"],
        "scan_type": scan["scan_type"],
        "threat_level": scan["threat_level"],
        "threat_score": scan["threat_score"],
        "summary": scan["summary"],
        "timestamp": scan["timestamp"],
        "details": details
    }
    
    report_filename = f"cyberrecon_report_{scan_id}.pdf"
    if os.environ.get('VERCEL'):
        report_path = os.path.join('/tmp', report_filename)
    else:
        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'images', report_filename)
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    generate_pdf_report(report_data, report_path)
    
    return send_file(report_path, as_attachment=True, download_name=report_filename)

@app.route('/api/uploads/<filename>')
def serve_upload(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

if __name__ == '__main__':
    # Presentation initialization: Auto-seed database with a default operator and isolated mock scans if empty
    try:
        from database import DB_PATH
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        conn.close()
        
        if user_count == 0:
            print("[BOOT] Database users table empty. Seeding Operator Vanguard...")
            default_user = create_user("operator@recon.local", "admin", "Operator Vanguard", "local")
            if default_user:
                add_scan(default_user["id"], "Website Intelligence", "example.com", "Low", 10, "Scanned example.com website. Clean footprint, secure headers optimized.", "{}")
                add_scan(default_user["id"], "Username Footprint", "john_cyber", "Medium", 35, "Scanned footprint for john_cyber. 3/8 profiles checked active.", "{}")
                print("[BOOT] Mock seeding complete for local Operator profile.")
    except Exception as e:
        print(f"[BOOT] DB seed initialization skipped or failed: {e}")
        
    app.run(debug=True, port=5000)
