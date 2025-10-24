from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
from PIL import Image  
from werkzeug.security import generate_password_hash, check_password_hash
import re  
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid  
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  


DB_PATH = 'database.db'


REPORTS_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'Reports Images')
LOSTFOUND_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'Lost and Found Images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS users''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       student_id TEXT,
                       name TEXT,
                       role TEXT DEFAULT 'student',
                       UNIQUE(student_id, role))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS reports
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       user_id INTEGER, 
                       issue_type TEXT,
                       location TEXT,
                       description TEXT,
                       photo TEXT,
                       status TEXT,
                       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY (user_id) REFERENCES users(id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS lost_found
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       item_name TEXT,
                       description TEXT,
                       photo TEXT,
                       status TEXT,
                       contact_info TEXT,
                       timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

    # Create upload folders if they don't exist
    for folder in [REPORTS_UPLOAD_FOLDER, LOSTFOUND_UPLOAD_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)

def validate_student_id(student_id):
    """Validate that student ID contains only numbers and dashes in correct format"""
    # Check if empty
    if not student_id:
        return False
    
    # Check if contains only numbers and dashes
    if not re.match(r'^[0-9-]+$', student_id):
        return False
    
    # Check format: YY-XXXXX where Y is year and X is number (e.g., 24-35960)
    if not re.match(r'^\d{2}-\d{5}$', student_id):
        return False
    
    return True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied: Admin privileges required', 'danger')
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all active reports
        cursor.execute("""
            SELECT r.issue_type, r.location, r.description, r.photo, r.status, u.name, r.id,
                   CASE 
                       WHEN julianday('now') - julianday(r.timestamp) < 1 THEN 
                           ROUND((julianday('now') - julianday(r.timestamp)) * 24) || ' hours ago'
                       ELSE 
                           ROUND(julianday('now') - julianday(r.timestamp)) || ' days ago'
                   END as time_ago
            FROM reports r
            JOIN users u ON r.user_id = u.id
            WHERE r.status != 'Resolved'
            ORDER BY 
                CASE r.status 
                    WHEN 'In Progress' THEN 0 
                    WHEN 'Pending' THEN 1 
                    ELSE 2 
                END,
                r.id DESC
        """)
        reports = cursor.fetchall()
        
        # Get all lost and found items
        cursor.execute("""
            SELECT item_name, description, photo, status, contact_info, id,
                   CASE 
                       WHEN julianday('now') - julianday(timestamp) < 1 THEN 
                           ROUND((julianday('now') - julianday(timestamp)) * 24) || ' hours ago'
                       ELSE 
                           ROUND(julianday('now') - julianday(timestamp)) || ' days ago'
                   END as time_ago
            FROM lost_found
            WHERE status != 'Returned'
            ORDER BY 
                CASE status 
                    WHEN 'In Progress' THEN 0 
                    WHEN 'Pending' THEN 1 
                    ELSE 2 
                END,
                id DESC
        """)
        lost_found_items = cursor.fetchall()
        
        conn.close()
        return render_template('home.html', reports=reports, lost_found_items=lost_found_items)
    except Exception as e:
        print(f"Error loading home page: {str(e)}")
        return render_template('home.html', reports=[], lost_found_items=[])

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))

    if request.method == "POST":
        student_id = request.form.get('student_id', '').strip()
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'student').strip()

        if not all([student_id, name, role]):
            flash('Please fill in all fields', 'danger')
            return render_template('index.html')

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE student_id = ? AND name = ? AND role = ?",
                         (student_id, name, role))
            user = cursor.fetchone()
            conn.close()

            if user:
                session['user_id'] = user[0]
                session['name'] = name
                session['role'] = role
                session['student_id'] = student_id

                flash(f'Welcome back, {name}!', 'success')
                if role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid credentials. Please check your ID, name, and role or sign up if you are a new user.', 'danger')
                return render_template('index.html')

        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
            return render_template('index.html')

    return render_template('index.html')

@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route("/student_dashboard")
@login_required
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('admin_dashboard'))
    return render_template('student_dashboard.html')

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        student_id = request.form.get('student_id', '').strip()
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'student').strip()

        # Validate student ID format only for students
        if role == 'student' and not validate_student_id(student_id):
            flash('Invalid Student ID format. Please use format: YY-XXXXX (e.g., 24-35960)', 'danger')
            return render_template('signup.html')

        try:
            with sqlite3.connect(DB_PATH, timeout=20) as conn:
                cursor = conn.cursor()
                
                # Check if ID already exists for the given role
                cursor.execute("SELECT * FROM users WHERE student_id = ? AND role = ?", (student_id, role))
                existing_user = cursor.fetchone()
                
                if existing_user:
                    flash(f'This ID is already registered as a {role}', 'danger')
                    return render_template('signup.html')
                
                cursor.execute("INSERT INTO users (student_id, name, role) VALUES (?, ?, ?)",
                             (student_id, name, role))
                
                # Get the user ID of the newly created user
                cursor.execute("SELECT id FROM users WHERE student_id = ? AND role = ?", (student_id, role))
                user_id = cursor.fetchone()[0]
                
                # Log the user in by setting session variables
                session['user_id'] = user_id
                session['name'] = name
                session['role'] = role
                session['student_id'] = student_id
                
                # Return success page and redirect to appropriate dashboard
                redirect_url = url_for('admin_dashboard') if role == 'admin' else url_for('student_dashboard')
                return render_template('success_message.html',
                                    title="Registration Successful!",
                                    message=f"Welcome to CCSFix, {name}!",
                                    redirect_url=redirect_url,
                                    button_text="Continue to Dashboard")
                
        except sqlite3.IntegrityError:
            flash('ID already exists', 'danger')
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                flash('System is busy, please try again in a moment', 'warning')
            else:
                flash(f'Database error: {str(e)}', 'danger')
        except Exception as e:
            flash(f'Error during registration: {str(e)}', 'danger')
    
    return render_template('signup.html')

@app.route("/logout")
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file, upload_type='report'):
    if file and allowed_file(file.filename):
        # Create a unique filename with timestamp and UUID
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}.{ext}"
        
        # Choose the appropriate upload folder based on type
        upload_folder = REPORTS_UPLOAD_FOLDER if upload_type == 'report' else LOSTFOUND_UPLOAD_FOLDER
        
        # Ensure upload directory exists
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        filepath = os.path.join(upload_folder, unique_filename)
        
        # Process and save the image
        try:
            image = Image.open(file)
            image = image.convert('RGB')  # Convert to RGB format
            image.thumbnail((800, 800))   # Resize if too large
            image.save(filepath, quality=85, optimize=True)  # Optimize file size
            return os.path.join('static', 'uploads', 'Reports Images' if upload_type == 'report' else 'Lost and Found Images', unique_filename)
        except Exception as e:
            print(f"Error processing image: {str(e)}")
            return None
    return None

def delete_image(photo_path):
    if photo_path:
        try:
            full_path = os.path.join(app.root_path, photo_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                return True
        except Exception as e:
            print(f"Error deleting image: {str(e)}")
    return False

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        issue_type = request.form.get('issueType', '').strip()
        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()
        
        if not all([issue_type, location, description]):
            flash('Please fill in all required fields', 'danger')
            return render_template('report.html')
        
        photo = request.files.get('photo')
        photo_path = save_image(photo, 'report') if photo else None
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO reports (user_id, issue_type, location, description, photo, status) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session['user_id'], issue_type, location, description, photo_path, 'Pending'))
            conn.commit()
            conn.close()
            
            flash('Your report has been submitted successfully!', 'success')
            return redirect(url_for('complaints'))
        except Exception as e:
            flash(f'Error submitting report: {str(e)}', 'danger')
            return render_template('report.html')

    return render_template('report.html')

@app.route("/view_lostfound")
@login_required
def view_lostfound():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM lost_found")
        items = cursor.fetchall()
        conn.close()
        return render_template('view_lostfound.html', items=items)
    except Exception as e:
        flash(f'Error fetching lost/found items: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))

@app.route("/lostfound", methods=["GET", "POST"])
def lostfound():
    if 'user_id' not in session:
        flash('Please log in to submit a lost & found item', 'danger')
        return redirect(url_for('login'))

    if request.method == "POST":
        item_name = request.form.get('itemName', '').strip()
        description = request.form.get('description', '').strip()
        student_name = request.form.get('studentName', '').strip()
        block = request.form.get('block', '').strip()
        contact_info = f"Name: {student_name}, Block: {block}"
        
        if not all([item_name, description, student_name, block]):
            flash('Please fill in all required fields', 'danger')
            return render_template('lostfound.html')
        
        photo = request.files.get('photo')
        photo_path = save_image(photo, 'lostfound') if photo else None
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO lost_found (item_name, description, photo, status, contact_info) 
                VALUES (?, ?, ?, ?, ?)
            """, (item_name, description, photo_path, 'Pending', contact_info))
            conn.commit()
            conn.close()
            
            flash('Your lost & found item has been submitted successfully!', 'success')
            return redirect(url_for('view_lostfound'))
        except Exception as e:
            flash(f'Error submitting item: {str(e)}', 'danger')
            return render_template('lostfound.html')
            
    return render_template('lostfound.html')

@app.route("/admin")
@admin_required
def admin():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM reports 
            WHERE status != 'Resolved'
            ORDER BY 
                CASE status 
                    WHEN 'In Progress' THEN 0 
                    WHEN 'Pending' THEN 1 
                    ELSE 2 
                END,
                id DESC
        """)
        reports = cursor.fetchall()
        conn.close()
        return render_template('admin.html', reports=reports)
    except Exception as e:
        flash(f'Error fetching reports: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route("/update_status/<int:report_id>", methods=["POST"])
@admin_required
def update_status(report_id):
    new_status = request.form.get('status', '').strip()
    if not new_status:
        flash('Invalid status value', 'danger')
        return redirect(url_for('admin'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if new_status.lower() == 'resolved':
            # Get the photo path before deleting
            cursor.execute("SELECT photo FROM reports WHERE id = ?", (report_id,))
            result = cursor.fetchone()
            if result and result[0]:
                photo_path = result[0]
                # Delete the photo file if it exists
                if delete_image(photo_path):
                    flash('Report has been marked as resolved and removed from the system.', 'success')
                else:
                    flash('Error deleting image', 'danger')
            
            # Delete the report
            cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        else:
            # Just update the status
            cursor.execute("UPDATE reports SET status = ? WHERE id = ?", (new_status, report_id))
            flash('Report status has been updated.', 'success')
            
        conn.commit()
        conn.close()
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))

@app.route("/complaints")
@login_required
def complaints():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First, get any resolved reports to show temporarily
        cursor.execute("""
            SELECT issue_type, location, description, photo, status 
            FROM reports 
            WHERE user_id = ? AND status = 'Resolved'
            ORDER BY id DESC
            LIMIT 5
        """, (session['user_id'],))
        resolved_complaints = cursor.fetchall()
        
        # Then get active reports
        cursor.execute("""
            SELECT issue_type, location, description, photo, status 
            FROM reports 
            WHERE user_id = ? AND status != 'Resolved'
            ORDER BY 
                CASE status 
                    WHEN 'In Progress' THEN 0 
                    WHEN 'Pending' THEN 1 
                    ELSE 2 
                END,
                id DESC
        """, (session['user_id'],))
        active_complaints = cursor.fetchall()
        
        conn.close()
        return render_template("complaints.html", 
                            complaints=active_complaints,
                            resolved_complaints=resolved_complaints)
    except Exception as e:
        flash(f'Error loading complaints: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))

@app.route("/admin_lostfound")
@admin_required
def admin_lostfound():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM lost_found")
        items = cursor.fetchall()
        # Simple matching: group by item_name
        matches = []
        for i, item1 in enumerate(items):
            for j, item2 in enumerate(items):
                if i != j and item1[1].lower() == item2[1].lower():
                    matches.append((item1, item2))
        conn.close()
        return render_template('admin_lostfound.html', items=items, matches=matches)
    except Exception as e:
        flash(f'Error fetching lost/found items: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route("/update_lostfound_status/<int:item_id>", methods=["POST"])
@admin_required
def update_lostfound_status(item_id):
    new_status = request.form['status']
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if new_status.lower() == 'returned':
            # Get the photo path before deleting
            cursor.execute("SELECT photo FROM lost_found WHERE id = ?", (item_id,))
            result = cursor.fetchone()
            if result and result[0]:
                photo_path = result[0]
                # Delete the photo file if it exists
                if delete_image(photo_path):
                    flash('Item has been returned and removed from the system.', 'success')
                else:
                    flash('Error deleting image', 'danger')
            
            # Delete the item
            cursor.execute("DELETE FROM lost_found WHERE id = ?", (item_id,))
        else:
            # Just update the status
            cursor.execute("UPDATE lost_found SET status = ? WHERE id = ?", (new_status, item_id))
            flash('Item status has been updated.', 'success')
            
        conn.commit()
        conn.close()
        return redirect(url_for('admin_lostfound'))
    except Exception as e:
        flash(f'Error updating status: {str(e)}', 'danger')
        return redirect(url_for('admin_lostfound'))

def send_email(issue_type, location):
    pass  # Function removed, left as a stub for compatibility

@app.route("/reportsandlostfound_dashboard")
@login_required
def reportsandlostfound_dashboard():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all active reports
        cursor.execute("""
            SELECT r.issue_type, r.location, r.description, r.photo, r.status, u.name
            FROM reports r
            JOIN users u ON r.user_id = u.id
            WHERE r.status != 'Resolved'
            ORDER BY 
                CASE r.status 
                    WHEN 'In Progress' THEN 0 
                    WHEN 'Pending' THEN 1 
                    ELSE 2 
                END,
                r.id DESC
        """)
        reports = cursor.fetchall()
        
        # Get all lost and found items
        cursor.execute("""
            SELECT item_name, description, photo, status, contact_info
            FROM lost_found
            WHERE status != 'Returned'
            ORDER BY 
                CASE status 
                    WHEN 'In Progress' THEN 0 
                    WHEN 'Pending' THEN 1 
                    ELSE 2 
                END,
                id DESC
        """)
        lost_found_items = cursor.fetchall()
        
        conn.close()
        return render_template('reportsandlostfound_dashboard.html', 
                            reports=reports, 
                            lost_found_items=lost_found_items)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))

if __name__ == '__main__':
    print("\nAccess your website at:")
    print("1. From your computer: http://127.0.0.1:5000")
    print("2. From other devices (phone, etc): http://192.168.1.39:5000\n")
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
