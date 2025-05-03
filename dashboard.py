from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import datetime
import json
import asyncio
import sqlite3
import dashboard_db as db
try:
    import discord
except ImportError:
    discord = None
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import io
import base64
from functools import wraps

# Directory for templates and static files
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

# Create directories if they don't exist
os.makedirs(template_dir, exist_ok=True)
os.makedirs(static_dir, exist_ok=True)
os.makedirs(os.path.join(static_dir, 'css'), exist_ok=True)

# Initialize Flask app
app = Flask(__name__, 
           template_folder=template_dir,
           static_folder=static_dir)

# Use a fixed secret key for session management
app.secret_key = 'stackbuffer_dashboard_secret_key'  # More stable than os.urandom(24)

# Store the bot instance
bot_instance = None

def run_dashboard(bot=None):
    """Run the dashboard with the bot instance"""
    global bot_instance
    bot_instance = bot

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Admin privileges required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    # Make sure the database is initialized
    try:
        import dashboard_db
        dashboard_db.init_db()
    except Exception as e:
        print(f"Error initializing database from index route: {e}")
    
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

def generate_captcha():
    """Generate a simple math CAPTCHA question and answer"""
    import random
    
    # Generate two random numbers between 1 and 10
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    
    # Choose a random operation (addition, subtraction, or multiplication)
    operations = [
        ('+', lambda x, y: x + y),
        ('-', lambda x, y: x - y),
        ('×', lambda x, y: x * y)
    ]
    
    # For subtraction, ensure the result is positive
    if num1 < num2:
        num1, num2 = num2, num1
        
    op_symbol, op_func = random.choice(operations)
    
    # Create the question and calculate the answer
    question = f"{num1} {op_symbol} {num2} = ?"
    answer = op_func(num1, num2)
    
    return question, answer

def log_failed_login(username, ip_address, reason):
    """Log failed login attempts for security monitoring"""
    try:
        # Log to the login_attempts table
        db.log_login_attempt(username, ip_address, False, reason)
    except Exception as e:
        print(f"Error logging failed login: {e}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Generate a new CAPTCHA for GET requests
    captcha_question, captcha_answer = generate_captcha()
    
    # Get client IP address
    ip_address = request.remote_addr
    
    # Check for too many failed login attempts
    is_blocked, block_seconds, attempt_count = db.check_login_attempts(ip_address)
    if is_blocked:
        minutes = block_seconds // 60
        seconds = block_seconds % 60
        flash(f'Too many failed login attempts. Please try again in {minutes} minutes and {seconds} seconds.', 'danger')
        return render_template('login.html', captcha_question=captcha_question)
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            captcha_question = request.form.get('captcha_question')
            captcha_answer_input = request.form.get('captcha_answer')
            
            # Check for too many failed login attempts for this specific username
            is_blocked, block_seconds, attempt_count = db.check_login_attempts(ip_address, username)
            if is_blocked:
                minutes = block_seconds // 60
                seconds = block_seconds % 60
                flash(f'Too many failed login attempts for this account. Please try again in {minutes} minutes and {seconds} seconds.', 'danger')
                return render_template('login.html', captcha_question=captcha_question)
            
            # Validate all required fields
            if not username or not password or not captcha_answer_input:
                flash('All fields are required', 'danger')
                return render_template('login.html', captcha_question=captcha_question)
            
            # Verify CAPTCHA
            # Parse the question to get the expected answer
            import re
            
            # Extract numbers and operation from the question
            match = re.match(r'(\d+)\s*([+\-×])\s*(\d+)\s*=\s*\?', captcha_question)
            if not match:
                flash('Invalid CAPTCHA question', 'danger')
                new_captcha_question, _ = generate_captcha()
                return render_template('login.html', captcha_question=new_captcha_question)
                
            num1 = int(match.group(1))
            op = match.group(2)
            num2 = int(match.group(3))
            
            # Calculate the expected answer
            if op == '+':
                expected_answer = num1 + num2
            elif op == '-':
                expected_answer = num1 - num2
            elif op == '×':
                expected_answer = num1 * num2
            else:
                expected_answer = None
            
            # Verify the CAPTCHA answer
            try:
                user_answer = int(captcha_answer_input)
                if user_answer != expected_answer:
                    log_failed_login(username, ip_address, "Incorrect CAPTCHA")
                    flash('Incorrect CAPTCHA answer. Please try again.', 'danger')
                    new_captcha_question, _ = generate_captcha()
                    return render_template('login.html', captcha_question=new_captcha_question)
            except ValueError:
                log_failed_login(username, ip_address, "Invalid CAPTCHA input")
                flash('Invalid CAPTCHA answer. Please enter a number.', 'danger')
                new_captcha_question, _ = generate_captcha()
                return render_template('login.html', captcha_question=new_captcha_question)
            
            # Verify user credentials
            user = db.verify_user(username, password)
            if user:
                # Log successful login
                db.log_login_attempt(username, ip_address, True)
                
                # Set session variables
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session['role'] = user['role']
                session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Get the next parameter if it exists
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                    
                return redirect(url_for('dashboard'))
            else:
                # Log failed login
                log_failed_login(username, ip_address, "Invalid credentials")
                flash('Invalid username or password', 'danger')
                
                # Generate a new CAPTCHA
                new_captcha_question, _ = generate_captcha()
                return render_template('login.html', captcha_question=new_captcha_question)
                
        except Exception as e:
            print(f"Error in login route: {e}")
            flash('An error occurred during login', 'danger')
            
            # Generate a new CAPTCHA
            new_captcha_question, _ = generate_captcha()
            return render_template('login.html', captcha_question=new_captcha_question)
    
    # For GET requests, render the login page with a new CAPTCHA
    return render_template('login.html', captcha_question=captcha_question)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
    
@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def users():
    """User management page"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_user':
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            is_admin = request.form.get('is_admin') == 'true'
            role = request.form.get('role', 'user')
            
            # Validate input
            if not username or not password or not confirm_password:
                flash('All fields are required', 'danger')
                return redirect(url_for('users'))
                
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('users'))
                
            # Add the user
            user_id = db.add_user(username, password, is_admin, role)
            
            if user_id:
                flash(f'User {username} added successfully', 'success')
            else:
                flash('Failed to add user. Username may already exist.', 'danger')
                
        elif action == 'delete_user':
            user_id = request.form.get('user_id')
            
            if not user_id:
                flash('User ID is required', 'danger')
                return redirect(url_for('users'))
                
            # Don't allow deleting yourself
            if str(session.get('user_id')) == user_id:
                flash('You cannot delete your own account', 'danger')
                return redirect(url_for('users'))
                
            # Delete the user
            success = db.delete_user(user_id)
            
            if success:
                flash('User deleted successfully', 'success')
            else:
                flash('Failed to delete user. Cannot delete the last admin.', 'danger')
                
        elif action == 'toggle_admin':
            user_id = request.form.get('user_id')
            
            if not user_id:
                flash('User ID is required', 'danger')
                return redirect(url_for('users'))
                
            # Don't allow changing your own admin status
            if str(session.get('user_id')) == user_id:
                flash('You cannot change your own admin status', 'danger')
                return redirect(url_for('users'))
                
            # Toggle admin status
            success = db.toggle_admin_status(user_id)
            
            if success:
                flash('User admin status updated successfully', 'success')
            else:
                flash('Failed to update user admin status. Cannot remove admin status from the last admin.', 'danger')
                
        elif action == 'change_username':
            user_id = request.form.get('user_id')
            new_username = request.form.get('new_username')
            
            if not user_id or not new_username:
                flash('User ID and new username are required', 'danger')
                return redirect(url_for('users'))
                
            # Change the username
            success = db.change_username(user_id, new_username)
            
            if success:
                # If the user is changing their own username, update the session
                if str(session.get('user_id')) == user_id:
                    session['username'] = new_username
                    
                flash('Username updated successfully', 'success')
            else:
                flash('Failed to update username. Username may already exist.', 'danger')
                
        elif action == 'change_role':
            user_id = request.form.get('user_id')
            new_role = request.form.get('new_role')
            
            if not user_id or not new_role:
                flash('User ID and new role are required', 'danger')
                return redirect(url_for('users'))
                
            # Don't allow owners to change their own role
            if str(session.get('user_id')) == user_id and session.get('role') == 'owner':
                flash('As an owner, you cannot change your own role', 'danger')
                return redirect(url_for('users'))
                
            # Change the role
            success = db.update_user_role(user_id, new_role)
            
            if success:
                # If the user is changing their own role, update the session
                if str(session.get('user_id')) == user_id:
                    session['role'] = new_role
                    
                flash('User role updated successfully', 'success')
            else:
                flash('Failed to update user role', 'danger')
        
        return redirect(url_for('users'))
    
    # Get all users
    users_list = db.get_all_users()
    
    return render_template('users.html', users=users_list)

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        stats = db.get_statistics()
        
        # Create charts
        url_chart = create_url_chart(stats)
        media_chart = create_media_chart(stats)
        violation_chart = create_violation_chart(stats)
        
        return render_template('dashboard.html', 
                              stats=stats, 
                              url_chart=url_chart,
                              media_chart=media_chart,
                              violation_chart=violation_chart)
    except Exception as e:
        print(f"Error in dashboard route: {e}")
        # Return a basic dashboard with empty stats
        empty_stats = {
            'total_url_scans': 0,
            'malicious_url_count': 0,
            'safe_url_count': 0,
            'total_media_scans': 0,
            'nsfw_media_count': 0,
            'safe_media_count': 0,
            'total_violations': 0,
            'violations_by_type': {},
            'recent_url_scans': 0,
            'recent_media_scans': 0,
            'recent_violations': 0,
            'top_malicious_users': {},
            'top_nsfw_users': {},
            'media_by_type': {}
        }
        flash('An error occurred while loading dashboard data', 'danger')
        return render_template('dashboard.html', 
                              stats=empty_stats, 
                              url_chart=None,
                              media_chart=None,
                              violation_chart=None)

@app.route('/url_scans')
@login_required
def url_scans():
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
        
    limit = 20
    offset = (page - 1) * limit
    
    # Get filter parameters
    user_id = request.args.get('user_id')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    is_malicious = request.args.get('is_malicious')
    
    if is_malicious is not None:
        is_malicious = is_malicious.lower() == 'true'
    
    try:
        # Get URL scans with filters
        scans = db.get_url_scans(limit, offset, user_id, from_date, to_date, is_malicious)
        
        # Get total count for pagination (limit to 1000 for performance)
        total_scans = len(db.get_url_scans(1000, 0, user_id, from_date, to_date, is_malicious))
        total_pages = max(1, (total_scans + limit - 1) // limit)
        
        # Ensure page is within valid range
        if page > total_pages:
            page = 1
            offset = 0
            scans = db.get_url_scans(limit, offset, user_id, from_date, to_date, is_malicious)
    except Exception as e:
        print(f"Error in url_scans route: {e}")
        scans = []
        total_pages = 1
    
    # Get Safe Display Mode setting from database
    safe_display_mode = db.is_safe_display_mode_enabled()
    
    # For backward compatibility, also get the session-based safe mode
    session_safe_mode = session.get('safe_mode', True)
    
    # Use Safe Display Mode from database, but fall back to session setting if needed
    safe_mode = safe_display_mode or session_safe_mode
    
    return render_template('url_scans.html', 
                          scans=scans, 
                          page=page, 
                          total_pages=total_pages,
                          safe_mode=safe_mode,
                          safe_display_mode=safe_display_mode,
                          filters={
                              'user_id': user_id,
                              'from_date': from_date,
                              'to_date': to_date,
                              'is_malicious': is_malicious
                          })

@app.route('/toggle_safe_mode', methods=['POST'])
@login_required
def toggle_safe_mode():
    """Toggle safe mode for URL display"""
    try:
        data = request.get_json()
        safe_mode = data.get('safe_mode', True)
        
        # Check if global Safe Display Mode is enabled
        safe_display_mode = db.is_safe_display_mode_enabled()
        
        # Store the preference in the session
        session['safe_mode'] = safe_mode
        
        # If Safe Display Mode is enabled globally, we'll inform the user
        return jsonify({
            'success': True, 
            'safe_mode': safe_mode,
            'safe_display_mode': safe_display_mode,
            'effective_safe_mode': safe_display_mode or safe_mode
        })
    except Exception as e:
        print(f"Error toggling safe mode: {e}")
        return jsonify({'success': False, 'error': str(e)})
                          
@app.route('/media_scans')
@login_required
def media_scans():
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
        
    limit = 20
    offset = (page - 1) * limit
    
    # Get filter parameters
    user_id = request.args.get('user_id')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    is_nsfw = request.args.get('is_nsfw')
    content_type = request.args.get('content_type')
    
    if is_nsfw is not None:
        is_nsfw = is_nsfw.lower() == 'true'
    
    try:
        # Get media scans with filters
        scans = db.get_media_scans(limit, offset, user_id, from_date, to_date, is_nsfw, content_type)
        
        # Get total count for pagination (limit to 1000 for performance)
        total_scans = len(db.get_media_scans(1000, 0, user_id, from_date, to_date, is_nsfw, content_type))
        total_pages = max(1, (total_scans + limit - 1) // limit)
        
        # Ensure page is within valid range
        if page > total_pages:
            page = 1
            offset = 0
            scans = db.get_media_scans(limit, offset, user_id, from_date, to_date, is_nsfw, content_type)
    except Exception as e:
        print(f"Error in media_scans route: {e}")
        scans = []
        total_pages = 1
    
    # Get Safe Display Mode setting
    safe_display_mode = db.is_safe_display_mode_enabled()
    
    return render_template('media_scans.html', 
                          scans=scans, 
                          page=page, 
                          total_pages=total_pages,
                          safe_display_mode=safe_display_mode,
                          filters={
                              'user_id': user_id,
                              'from_date': from_date,
                              'to_date': to_date,
                              'is_nsfw': is_nsfw,
                              'content_type': content_type
                          })

@app.route('/violations')
@login_required
def violations():
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
        
    limit = 20
    offset = (page - 1) * limit
    
    # Get filter parameters
    user_id = request.args.get('user_id')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    violation_type = request.args.get('violation_type')
    
    try:
        # Get violations with filters
        violations_list = db.get_violations(limit, offset, user_id, from_date, to_date, violation_type)
        
        # Get total count for pagination (limit to 1000 for performance)
        total_violations = len(db.get_violations(1000, 0, user_id, from_date, to_date, violation_type))
        total_pages = max(1, (total_violations + limit - 1) // limit)
        
        # Ensure page is within valid range
        if page > total_pages:
            page = 1
            offset = 0
            violations_list = db.get_violations(limit, offset, user_id, from_date, to_date, violation_type)
    except Exception as e:
        print(f"Error in violations route: {e}")
        violations_list = []
        total_pages = 1
    
    # Get Safe Display Mode setting
    safe_display_mode = db.is_safe_display_mode_enabled()
    
    return render_template('violations.html', 
                          violations=violations_list, 
                          page=page, 
                          total_pages=total_pages,
                          safe_display_mode=safe_display_mode,
                          filters={
                              'user_id': user_id,
                              'from_date': from_date,
                              'to_date': to_date,
                              'violation_type': violation_type
                          })

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            action = request.form.get('action', 'change_password')
            
            # Handle password change
            if action == 'change_password':
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                # Basic validation
                if not current_password or not new_password or not confirm_password:
                    flash('All fields are required', 'danger')
                    return redirect(url_for('settings'))
                
                # Verify current password
                user = db.verify_user(session['username'], current_password)
                if not user:
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('settings'))
                
                # Check if new passwords match
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('settings'))
                
                # Check password strength
                if len(new_password) < 6:
                    flash('New password must be at least 6 characters long', 'danger')
                    return redirect(url_for('settings'))
                
                # Change password
                if db.change_password(session['username'], new_password):
                    flash('Password changed successfully', 'success')
                else:
                    flash('Failed to change password', 'danger')
            
            # Handle Safe Mode settings (admin only)
            elif action == 'update_safe_mode' and session.get('is_admin'):
                # Get form values
                safe_mode_enabled = request.form.get('safe_mode_enabled') == 'true'
                safe_mode_threshold = request.form.get('safe_mode_threshold', 'medium')
                safe_display_mode = request.form.get('safe_display_mode') == 'true'
                
                # Validate threshold value
                if safe_mode_threshold not in ['low', 'medium', 'high']:
                    safe_mode_threshold = 'medium'
                
                # Update settings
                db.update_setting('safe_mode_enabled', 'true' if safe_mode_enabled else 'false', session.get('username'))
                db.update_setting('safe_mode_threshold', safe_mode_threshold, session.get('username'))
                db.update_setting('safe_display_mode', 'true' if safe_display_mode else 'false', session.get('username'))
                
                # Log the action
                db.log_system_event(f"Admin {session['username']} updated Safe Mode settings: enabled={safe_mode_enabled}, threshold={safe_mode_threshold}, display_mode={safe_display_mode}")
                
                flash('Safe Mode settings updated successfully', 'success')
            
            # Handle data clearing actions (admin only)
            elif session.get('is_admin'):
                if action == 'clear_url_scans':
                    if db.clear_url_scans():
                        flash('All URL scan data has been cleared successfully', 'success')
                        # Log the action
                        db.log_system_event(f"Admin {session['username']} cleared all URL scan data")
                    else:
                        flash('Error clearing URL scan data', 'danger')
                
                elif action == 'clear_media_scans':
                    if db.clear_media_scans():
                        flash('All media scan data has been cleared successfully', 'success')
                        # Log the action
                        db.log_system_event(f"Admin {session['username']} cleared all media scan data")
                    else:
                        flash('Error clearing media scan data', 'danger')
                
                elif action == 'clear_violations':
                    if db.clear_violations():
                        flash('All violation data has been cleared successfully', 'success')
                        # Log the action
                        db.log_system_event(f"Admin {session['username']} cleared all violation data")
                    else:
                        flash('Error clearing violation data', 'danger')
                
                elif action == 'clear_all_data':
                    if db.clear_all_scan_data():
                        flash('All scan data has been reset successfully', 'success')
                        # Log the action
                        db.log_system_event(f"Admin {session['username']} performed a complete scan data reset")
                    else:
                        flash('Error resetting scan data', 'danger')
            else:
                flash('You do not have permission to perform this action', 'danger')
                
            return redirect(url_for('settings'))
        except Exception as e:
            print(f"Error in settings route: {e}")
            flash('An error occurred', 'danger')
            return redirect(url_for('settings'))
    
    # Get current Safe Mode settings
    safe_mode_enabled = db.is_safe_mode_enabled()
    safe_mode_threshold = db.get_safe_mode_threshold()
    safe_display_mode = db.is_safe_display_mode_enabled()
    
    return render_template('settings.html', 
                          safe_mode_enabled=safe_mode_enabled,
                          safe_mode_threshold=safe_mode_threshold,
                          safe_display_mode=safe_display_mode)

@app.route('/api/stats')
@login_required
def api_stats():
    stats = db.get_statistics()
    return jsonify(stats)

@app.route('/system', methods=['GET', 'POST'])
@login_required
@admin_required
def system_management():
    """System management page for bot operations"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'refresh_bot':
            try:
                if bot_instance:
                    # Log the refresh action
                    db.log_system_event(
                        event_type="Bot Refresh",
                        user_id=session.get('user_id'),
                        username=session.get('username'),
                        details="Bot refresh via dashboard"
                    )
                    
                    # Reload modules
                    import importlib
                    import sys
                    
                    # List of modules to reload
                    modules_to_reload = [
                        'dashboard_db',
                        # Add other modules here if needed
                    ]
                    
                    # Reload each module
                    for module_name in modules_to_reload:
                        if module_name in sys.modules:
                            importlib.reload(sys.modules[module_name])
                            print(f"[REFRESH] Module {module_name} is opnieuw geladen")
                    
                    # Update the database connection
                    db.init_db()
                    
                    flash('Bot is vernieuwd! Nieuwe code is nu actief.', 'success')
                else:
                    flash('Bot instance is niet beschikbaar. Kan niet vernieuwen.', 'danger')
            except Exception as e:
                flash(f'Fout bij vernieuwen van de bot: {e}', 'danger')
                print(f"[ERROR] Fout bij bot refresh: {e}")
        
        return redirect(url_for('system_management'))
    
    # Get system events for display
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
        
    limit = 20
    offset = (page - 1) * limit
    
    # Get filter parameters
    event_type = request.args.get('event_type')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    try:
        # Get system events with filters
        events = db.get_system_events(limit, offset, event_type, None, from_date, to_date)
        
        # Get total count for pagination
        total_events = len(db.get_system_events(1000, 0, event_type, None, from_date, to_date))
        total_pages = max(1, (total_events + limit - 1) // limit)
        
        # Ensure page is within valid range
        if page > total_pages:
            page = 1
            offset = 0
            events = db.get_system_events(limit, offset, event_type, None, from_date, to_date)
    except Exception as e:
        print(f"Error in system_management route: {e}")
        events = []
        total_pages = 1
    
    # Get bot status
    bot_status = {
        'connected': bot_instance is not None,
        'username': bot_instance.user.name if bot_instance and hasattr(bot_instance, 'user') else 'N/A',
        'id': bot_instance.user.id if bot_instance and hasattr(bot_instance, 'user') else 'N/A',
        'servers': len(bot_instance.guilds) if bot_instance and hasattr(bot_instance, 'guilds') else 0,
    }
    
    return render_template('system.html', 
                          events=events, 
                          page=page, 
                          total_pages=total_pages,
                          bot_status=bot_status,
                          filters={
                              'event_type': event_type,
                              'from_date': from_date,
                              'to_date': to_date
                          })
    
@app.route('/moderation', methods=['GET', 'POST'])
@login_required
def moderation():
    """Show moderation page with timeouts and bans"""
    # Handle direct user ID actions
    if request.method == 'POST':
        action = request.form.get('action')
        user_input = request.form.get('user_id')
        
        if not user_input:
            flash('Gebruikers-ID of gebruikersnaam is vereist', 'danger')
            return redirect(url_for('moderation'))
            
        # Try to find the user by name or ID
        user = db.get_user_by_name_or_id(user_input)
        
        # If we found a user, use their ID, otherwise use the input as is
        user_id = user['user_id'] if user else user_input
            
        # Get guild_id for all actions
        guild_id = request.form.get('guild_id')
        reason = request.form.get('reason')
        
        if action in ['unmute', 'unban', 'untimeout'] and not guild_id:
            flash('Server selectie is vereist', 'danger')
            return redirect(url_for('moderation'))
            
        # Get guild name for display
        guild_name = "Unknown Server"
        if guild_id:
            # Get guilds from both the database and the bot
            db_guilds = db.get_guilds()
            bot_guilds = []
            
            # If bot is available, get its guilds
            if bot_instance and hasattr(bot_instance, 'get_bot_guilds'):
                bot_guilds = bot_instance.get_bot_guilds()
            
            # Combine guilds from both sources
            guilds = db_guilds.copy()
            
            # Add bot guilds if not already in the list
            for bot_guild in bot_guilds:
                if not any(g['guild_id'] == bot_guild['guild_id'] for g in guilds):
                    guilds.append(bot_guild)
            
            # Find the guild name
            for guild in guilds:
                if guild['guild_id'] == guild_id:
                    guild_name = guild['guild_name']
                    break
                    
            # If still unknown and bot is available, try to get directly from bot
            if guild_name == "Unknown Server" and bot_instance:
                try:
                    discord_guild = bot_instance.get_guild(int(guild_id))
                    if discord_guild:
                        guild_name = discord_guild.name
                except Exception as e:
                    print(f"Error getting guild name from bot: {e}")
        
        if action == 'unmute':
            # Check if user is muted
            mutes = db.get_muted_users()
            user_mutes = [mute for mute in mutes if mute['user_id'] == user_id and mute['guild_id'] == guild_id]
            
            if user_mutes:
                success = True
                for mute in user_mutes:
                    if not db.remove_mute(mute['id']):
                        success = False
                
                if success:
                    flash(f'Mute voor gebruiker {user_id} in server {guild_name} succesvol verwijderd', 'success')
                else:
                    flash(f'Fout bij verwijderen van mute voor gebruiker {user_id}', 'danger')
            else:
                flash(f'Geen actieve mute gevonden voor gebruiker {user_id} in server {guild_name}', 'warning')
                
        elif action == 'untimeout':
            # Check if user is timed out in the database
            timeouts = db.get_active_timeouts()
            user_timeouts = [timeout for timeout in timeouts if timeout['user_id'] == user_id and timeout['guild_id'] == guild_id]
            
            # Try to remove timeout directly in Discord even if not in database
            direct_removal_attempted = False
            
            if user_timeouts:
                # Remove from database
                success = True
                for timeout in user_timeouts:
                    if not db.remove_timeout(timeout['id']):
                        success = False
                
                if success:
                    flash(f'Timeout voor gebruiker {user_id} in server {guild_name} succesvol verwijderd', 'success')
                else:
                    flash(f'Fout bij verwijderen van timeout voor gebruiker {user_id}', 'danger')
            else:
                # No timeout in database, but we'll still try to remove it directly in Discord
                flash(f'Geen actieve timeout gevonden in database voor gebruiker {user_id} in server {guild_name}, proberen direct te verwijderen...', 'warning')
                direct_removal_attempted = True
            
            # Force immediate timeout removal if bot is available (whether in database or not)
            if bot_instance:
                try:
                    # Schedule the timeout removal
                    async def remove_timeout_now():
                        try:
                            guild = bot_instance.get_guild(int(guild_id))
                            if guild:
                                try:
                                    # Try to get member by ID
                                    try:
                                        member = guild.get_member(int(user_id))
                                    except ValueError:
                                        # If user_id is not a valid integer, try to find by name
                                        if discord:
                                            member = discord.utils.get(guild.members, name=user_id)
                                        else:
                                            member = None
                                        
                                    if member:
                                        # Check if member is actually timed out
                                        is_timed_out = False
                                        try:
                                            if hasattr(member, 'communication_disabled_until') and member.communication_disabled_until is not None:
                                                is_timed_out = True
                                        except Exception:
                                            pass
                                        
                                        # Always try to remove timeout, even if we don't detect it
                                        # This is because the API might not correctly report the timeout status
                                        try:
                                            await member.timeout(None, reason="Timeout removed via dashboard")
                                            print(f"Attempted to remove timeout for {member} in {guild}")
                                            
                                            # Verify the timeout was removed
                                            await asyncio.sleep(1)  # Wait a moment for the API to update
                                            member = guild.get_member(member.id)  # Refresh member data
                                            
                                            if hasattr(member, 'communication_disabled_until') and member.communication_disabled_until is None:
                                                print(f"Verified timeout removal for {member} in {guild}")
                                                if direct_removal_attempted:
                                                    # Update the flash message if this was a direct removal
                                                    flash(f'Timeout voor gebruiker {user_id} in server {guild_name} succesvol direct verwijderd', 'success')
                                            else:
                                                print(f"Warning: Timeout may not have been removed for {member} in {guild}")
                                        except Exception as e:
                                            print(f"Error removing timeout: {e}")
                                    else:
                                        print(f"Could not find member {user_id} in guild {guild.name}")
                                except Exception as e:
                                    print(f"Error immediately removing timeout: {e}")
                            else:
                                print(f"Could not find guild with ID {guild_id}")
                        except Exception as e:
                            print(f"Error in immediate timeout removal: {e}")
                    
                    # Run the coroutine in the bot's event loop
                    bot_instance.loop.create_task(remove_timeout_now())
                except Exception as e:
                    print(f"Error scheduling timeout removal: {e}")
                
        elif action == 'unban':
            # Check if user is banned
            bans = db.get_banned_users()
            user_bans = [ban for ban in bans if ban['user_id'] == user_id and ban['guild_id'] == guild_id]
            
            if user_bans:
                success = True
                for ban in user_bans:
                    if not db.remove_ban(ban['id']):
                        success = False
                
                if success:
                    flash(f'Ban voor gebruiker {user_id} in server {guild_name} succesvol verwijderd', 'success')
                else:
                    flash(f'Fout bij verwijderen van ban voor gebruiker {user_id}', 'danger')
            else:
                flash(f'Geen actieve ban gevonden voor gebruiker {user_id} in server {guild_name}', 'warning')
                
        elif action == 'timeout':
            # Get additional parameters
            guild_id = request.form.get('guild_id')
            duration = request.form.get('duration')
            reason = request.form.get('reason')
            
            if not guild_id:
                flash('Server ID is vereist', 'danger')
                return redirect(url_for('moderation'))
                
            if not duration:
                flash('Timeout duur is vereist', 'danger')
                return redirect(url_for('moderation'))
                
            try:
                duration_days = float(duration)
                
                # Get guild name
                guilds = db.get_guilds()
                guild_name = "Unknown Server"
                for guild in guilds:
                    if guild['guild_id'] == guild_id:
                        guild_name = guild['guild_name']
                        break
                
                # Add timeout to database
                if db.add_timeout(user_id, f"User {user_id}", guild_id, guild_name, duration_days, reason):
                    flash(f'Timeout voor gebruiker {user_id} succesvol toegevoegd voor {duration_days} dagen', 'success')
                    
                    # Force immediate timeout application if bot is available
                    if bot_instance:
                        try:
                            # Schedule the timeout application
                            async def apply_timeout_now():
                                try:
                                    guild = bot_instance.get_guild(int(guild_id))
                                    if guild:
                                        try:
                                            # Try to get member by ID
                                            try:
                                                member = guild.get_member(int(user_id))
                                            except ValueError:
                                                # If user_id is not a valid integer, try to find by name
                                                if discord:
                                                    member = discord.utils.get(guild.members, name=user_id)
                                                else:
                                                    member = None
                                                
                                            if member:
                                                # Calculate timeout duration
                                                duration = datetime.timedelta(days=duration_days)
                                                
                                                # Apply the timeout
                                                await member.timeout(duration, reason=reason or "Timeout applied via dashboard")
                                                print(f"Immediately applied timeout for {member} in {guild} for {duration_days} days")
                                                
                                                # Verify the timeout was applied
                                                await asyncio.sleep(1)  # Wait a moment for the API to update
                                                member = guild.get_member(member.id)  # Refresh member data
                                                
                                                if hasattr(member, 'communication_disabled_until') and member.communication_disabled_until is not None:
                                                    print(f"Verified timeout application for {member} in {guild}")
                                                else:
                                                    print(f"Warning: Timeout may not have been applied for {member} in {guild}")
                                            else:
                                                print(f"Could not find member {user_id} in guild {guild.name}")
                                        except Exception as e:
                                            print(f"Error immediately applying timeout: {e}")
                                except Exception as e:
                                    print(f"Error in immediate timeout application: {e}")
                            
                            # Run the coroutine in the bot's event loop
                            bot_instance.loop.create_task(apply_timeout_now())
                        except Exception as e:
                            print(f"Error scheduling timeout application: {e}")
                else:
                    flash(f'Fout bij toevoegen van timeout voor gebruiker {user_id}', 'danger')
            except ValueError:
                flash('Timeout duur moet een getal zijn', 'danger')
                
        elif action == 'mute':
            # Get additional parameters
            guild_id = request.form.get('guild_id')
            reason = request.form.get('reason')
            
            if not guild_id:
                flash('Server ID is vereist', 'danger')
                return redirect(url_for('moderation'))
                
            # Get guild name
            guilds = db.get_guilds()
            guild_name = "Unknown Server"
            for guild in guilds:
                if guild['guild_id'] == guild_id:
                    guild_name = guild['guild_name']
                    break
            
            # Add mute to database
            if db.add_mute(user_id, f"User {user_id}", guild_id, guild_name, reason):
                flash(f'Mute voor gebruiker {user_id} succesvol toegevoegd', 'success')
            else:
                flash(f'Fout bij toevoegen van mute voor gebruiker {user_id}', 'danger')
                
        elif action == 'ban':
            # Get additional parameters
            guild_id = request.form.get('guild_id')
            reason = request.form.get('reason')
            
            if not guild_id:
                flash('Server ID is vereist', 'danger')
                return redirect(url_for('moderation'))
                
            # Get guild name
            guilds = db.get_guilds()
            guild_name = "Unknown Server"
            for guild in guilds:
                if guild['guild_id'] == guild_id:
                    guild_name = guild['guild_name']
                    break
            
            # Add ban to database
            if db.log_ban(user_id, f"User {user_id}", guild_id, guild_name, reason):
                flash(f'Ban voor gebruiker {user_id} succesvol toegevoegd', 'success')
            else:
                flash(f'Fout bij toevoegen van ban voor gebruiker {user_id}', 'danger')
        
        return redirect(url_for('moderation'))
    
    # Get active timeouts, bans, and mutes for display
    timeouts = db.get_active_timeouts()
    bans = db.get_banned_users()
    mutes = db.get_muted_users()
    
    # Get guilds from both the database and the bot
    db_guilds = db.get_guilds()
    bot_guilds = []
    
    # If bot is available, get its guilds
    if bot_instance and hasattr(bot_instance, 'get_bot_guilds'):
        bot_guilds = bot_instance.get_bot_guilds()
    
    # Combine guilds from both sources, avoiding duplicates
    guilds = db_guilds.copy()
    bot_guild_ids = [g['guild_id'] for g in guilds]
    
    for guild in bot_guilds:
        if guild['guild_id'] not in bot_guild_ids:
            guilds.append(guild)
    
    return render_template('moderation.html', 
                          timeouts=timeouts,
                          bans=bans,
                          mutes=mutes,
                          guilds=guilds)

@app.route('/remove_timeout/<int:timeout_id>', methods=['POST'])
@login_required
def remove_timeout(timeout_id):
    """Remove a timeout"""
    # First get the timeout details before removing from database
    timeout = None
    try:
        conn = sqlite3.connect(db.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM timeouts WHERE id = ?', (timeout_id,))
        timeout = dict(cursor.fetchone())
        conn.close()
    except Exception as e:
        print(f"Error getting timeout details: {e}")
    
    # Remove from database
    if db.remove_timeout(timeout_id):
        if timeout and bot_instance:
            # Schedule the timeout removal in Discord
            try:
                async def remove_timeout_now():
                    try:
                        guild = bot_instance.get_guild(int(timeout['guild_id']))
                        if guild:
                            try:
                                # Try to get member by ID
                                try:
                                    member = guild.get_member(int(timeout['user_id']))
                                except ValueError:
                                    # If user_id is not a valid integer, try to find by name
                                    if discord:
                                        member = discord.utils.get(guild.members, name=timeout['username'])
                                    else:
                                        member = None
                                
                                if member:
                                    # Check if the bot has permission to moderate members
                                    bot_member = guild.get_member(bot_instance.user.id)
                                    if not bot_member.guild_permissions.moderate_members:
                                        print(f"⚠️ BOT HEEFT GEEN PERMISSIES: De bot heeft geen 'Moderate Members' permissie in {guild.name}!")
                                        flash(f"⚠️ De bot heeft geen 'Moderate Members' permissie in {guild.name}!", 'warning')
                                    else:
                                        # Remove the timeout
                                        await member.timeout(None, reason="Timeout removed via dashboard")
                                        print(f"Removed timeout for {member} in {guild}")
                                        flash(f'Timeout voor {member} in {guild.name} succesvol verwijderd in Discord', 'success')
                                else:
                                    print(f"Could not find member {timeout['user_id']} in guild {guild.name}")
                                    flash(f"Kon gebruiker {timeout['username']} niet vinden in server {guild.name}", 'warning')
                            except Exception as e:
                                print(f"Error immediately removing timeout: {e}")
                                flash(f"Fout bij verwijderen van timeout in Discord: {e}", 'warning')
                        else:
                            print(f"Could not find guild with ID {timeout['guild_id']}")
                            flash(f"Kon server met ID {timeout['guild_id']} niet vinden", 'warning')
                    except Exception as e:
                        print(f"Error in immediate timeout removal: {e}")
                        flash(f"Fout bij verwijderen van timeout: {e}", 'warning')
                
                # Run the coroutine in the bot's event loop
                bot_instance.loop.create_task(remove_timeout_now())
            except Exception as e:
                print(f"Error scheduling timeout removal: {e}")
                flash(f"Fout bij plannen van timeout verwijdering: {e}", 'warning')
        else:
            flash('Timeout verwijderd uit database, maar kon niet verwijderen in Discord', 'warning')
    else:
        flash('Fout bij verwijderen van timeout uit database', 'danger')
    
    return redirect(url_for('moderation'))

@app.route('/remove_ban/<int:ban_id>', methods=['POST'])
@login_required
def remove_ban(ban_id):
    """Remove a ban"""
    # First get the ban details before removing from database
    ban = None
    try:
        conn = sqlite3.connect(db.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM bans WHERE id = ?', (ban_id,))
        ban = dict(cursor.fetchone())
        conn.close()
    except Exception as e:
        print(f"Error getting ban details: {e}")
    
    # Remove from database
    if db.remove_ban(ban_id):
        if ban and bot_instance:
            # Schedule the ban removal in Discord
            try:
                async def remove_ban_now():
                    try:
                        guild = bot_instance.get_guild(int(ban['guild_id']))
                        if guild:
                            try:
                                # Check if the bot has permission to ban members
                                bot_member = guild.get_member(bot_instance.user.id)
                                if not bot_member.guild_permissions.ban_members:
                                    print(f"⚠️ BOT HEEFT GEEN PERMISSIES: De bot heeft geen 'Ban Members' permissie in {guild.name}!")
                                    flash(f"⚠️ De bot heeft geen 'Ban Members' permissie in {guild.name}!", 'warning')
                                else:
                                    # Try to get user by ID
                                    try:
                                        user_id = int(ban['user_id'])
                                        # Unban the user
                                        try:
                                            await guild.unban(discord.Object(id=user_id), reason="Unbanned via dashboard")
                                            print(f"Unbanned user {user_id} from {guild}")
                                            flash(f'Ban voor gebruiker {ban["username"]} in {guild.name} succesvol verwijderd in Discord', 'success')
                                        except discord.NotFound:
                                            print(f"User {user_id} not found in ban list for {guild}")
                                            flash(f"Gebruiker {ban['username']} niet gevonden in ban lijst voor {guild.name}", 'warning')
                                        except Exception as e:
                                            print(f"Error unbanning user {user_id}: {e}")
                                            flash(f"Fout bij unbannen van gebruiker {ban['username']}: {e}", 'warning')
                                    except ValueError:
                                        # If user_id is not a valid integer
                                        print(f"Invalid user ID: {ban['user_id']}")
                                        flash(f"Ongeldige gebruiker ID: {ban['user_id']}", 'warning')
                            except Exception as e:
                                print(f"Error immediately removing ban: {e}")
                                flash(f"Fout bij verwijderen van ban in Discord: {e}", 'warning')
                        else:
                            print(f"Could not find guild with ID {ban['guild_id']}")
                            flash(f"Kon server met ID {ban['guild_id']} niet vinden", 'warning')
                    except Exception as e:
                        print(f"Error in immediate ban removal: {e}")
                        flash(f"Fout bij verwijderen van ban: {e}", 'warning')
                
                # Run the coroutine in the bot's event loop
                bot_instance.loop.create_task(remove_ban_now())
            except Exception as e:
                print(f"Error scheduling ban removal: {e}")
                flash(f"Fout bij plannen van ban verwijdering: {e}", 'warning')
        else:
            flash('Ban verwijderd uit database, maar kon niet verwijderen in Discord', 'warning')
    else:
        flash('Fout bij verwijderen van ban uit database', 'danger')
    
    return redirect(url_for('moderation'))

@app.route('/remove_mute/<int:mute_id>', methods=['POST'])
@login_required
def remove_mute(mute_id):
    """Remove a mute"""
    # First get the mute details before removing from database
    mute = None
    try:
        conn = sqlite3.connect(db.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM mutes WHERE id = ?', (mute_id,))
        mute = dict(cursor.fetchone())
        conn.close()
    except Exception as e:
        print(f"Error getting mute details: {e}")
    
    # Remove from database
    if db.remove_mute(mute_id):
        if mute and bot_instance:
            # Schedule the mute removal in Discord
            try:
                async def remove_mute_now():
                    try:
                        guild = bot_instance.get_guild(int(mute['guild_id']))
                        if guild:
                            try:
                                # Try to get member by ID
                                try:
                                    member = guild.get_member(int(mute['user_id']))
                                except ValueError:
                                    # If user_id is not a valid integer, try to find by name
                                    if discord:
                                        member = discord.utils.get(guild.members, name=mute['username'])
                                    else:
                                        member = None
                                
                                if member:
                                    # Check if the bot has permission to manage roles
                                    bot_member = guild.get_member(bot_instance.user.id)
                                    if not bot_member.guild_permissions.manage_roles:
                                        print(f"⚠️ BOT HEEFT GEEN PERMISSIES: De bot heeft geen 'Manage Roles' permissie in {guild.name}!")
                                        flash(f"⚠️ De bot heeft geen 'Manage Roles' permissie in {guild.name}!", 'warning')
                                    else:
                                        # Find the Muted role
                                        muted_role = discord.utils.get(guild.roles, name="Muted")
                                        if muted_role:
                                            if muted_role in member.roles:
                                                # Remove the Muted role
                                                await member.remove_roles(muted_role, reason="Unmuted via dashboard")
                                                print(f"Removed mute for {member} in {guild}")
                                                flash(f'Mute voor {member} in {guild.name} succesvol verwijderd in Discord', 'success')
                                            else:
                                                print(f"Member {member} doesn't have the Muted role in {guild}")
                                                flash(f"Gebruiker {member} heeft geen Muted rol in {guild.name}", 'warning')
                                        else:
                                            print(f"Could not find Muted role in {guild}")
                                            flash(f"Kon Muted rol niet vinden in {guild.name}", 'warning')
                                else:
                                    print(f"Could not find member {mute['user_id']} in guild {guild.name}")
                                    flash(f"Kon gebruiker {mute['username']} niet vinden in server {guild.name}", 'warning')
                            except Exception as e:
                                print(f"Error immediately removing mute: {e}")
                                flash(f"Fout bij verwijderen van mute in Discord: {e}", 'warning')
                        else:
                            print(f"Could not find guild with ID {mute['guild_id']}")
                            flash(f"Kon server met ID {mute['guild_id']} niet vinden", 'warning')
                    except Exception as e:
                        print(f"Error in immediate mute removal: {e}")
                        flash(f"Fout bij verwijderen van mute: {e}", 'warning')
                
                # Run the coroutine in the bot's event loop
                bot_instance.loop.create_task(remove_mute_now())
            except Exception as e:
                print(f"Error scheduling mute removal: {e}")
                flash(f"Fout bij plannen van mute verwijdering: {e}", 'warning')
        else:
            flash('Mute verwijderd uit database, maar kon niet verwijderen in Discord', 'warning')
    else:
        flash('Fout bij verwijderen van mute uit database', 'danger')
    
    return redirect(url_for('moderation'))

def create_url_chart(stats):
    """Create a pie chart for URL scan results"""
    # Check if there's any data to display
    total_urls = stats['safe_url_count'] + stats['malicious_url_count']
    if total_urls == 0:
        return None
    
    labels = ['Safe URLs', 'Malicious URLs']
    sizes = [stats['safe_url_count'], stats['malicious_url_count']]
    colors = ['#4CAF50', '#F44336']
    
    try:
        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        plt.title('URL Scan Results')
        
        # Save the plot to a base64 string
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_png = buffer.getvalue()
        buffer.close()
        
        plt.close()
        
        return base64.b64encode(image_png).decode('utf-8')
    except Exception as e:
        print(f"Error creating URL chart: {e}")
        plt.close()  # Make sure to close the figure in case of error
        return None
        
def create_media_chart(stats):
    """Create a pie chart for media scan results"""
    # Check if there's any data to display
    total_media = stats.get('safe_media_count', 0) + stats.get('nsfw_media_count', 0)
    if total_media == 0:
        return None
    
    labels = ['Safe Media', 'NSFW Media']
    sizes = [stats.get('safe_media_count', 0), stats.get('nsfw_media_count', 0)]
    colors = ['#4CAF50', '#F44336']
    
    try:
        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        plt.title('Media Scan Results')
        
        # Save the plot to a base64 string
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_png = buffer.getvalue()
        buffer.close()
        
        plt.close()
        
        return base64.b64encode(image_png).decode('utf-8')
    except Exception as e:
        print(f"Error creating media chart: {e}")
        plt.close()  # Make sure to close the figure in case of error
        return None

def create_violation_chart(stats):
    """Create a bar chart for violations by type"""
    if not stats.get('violations_by_type') or len(stats['violations_by_type']) == 0:
        return None
    
    try:
        labels = list(stats['violations_by_type'].keys())
        values = list(stats['violations_by_type'].values())
        
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color='#2196F3')
        plt.xlabel('Violation Type')
        plt.ylabel('Count')
        plt.title('Violations by Type')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save the plot to a base64 string
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_png = buffer.getvalue()
        buffer.close()
        
        plt.close()
        
        return base64.b64encode(image_png).decode('utf-8')
    except Exception as e:
        print(f"Error creating violation chart: {e}")
        plt.close()  # Make sure to close the figure in case of error
        return None

@app.errorhandler(500)
def internal_error(error):
    print(f"Internal server error: {error}")
    return render_template('error.html', error=error), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error=error), 404

# Initialize the database when this module is imported
try:
    import dashboard_db
    dashboard_db.init_db()
    print("Dashboard database initialized on module import")
except Exception as e:
    print(f"Error initializing dashboard database on module import: {e}")

# Make sure the static CSS file exists
try:
    css_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'css')
    css_file = os.path.join(css_dir, 'style.css')
    if not os.path.exists(css_file):
        print(f"CSS file not found, creating: {css_file}")
        with open(css_file, 'w') as f:
            f.write("""
/* Custom CSS for Silcas Bot Dashboard */
body {
    padding-top: 56px;
    background-color: #0a0a0a; /* Slightly lighter black for better contrast */
    color: #ffffff; /* White text */
    font-size: 16px; /* Larger base font size */
}
.sidebar {
    position: fixed;
    top: 56px;
    bottom: 0;
    left: 0;
    z-index: 100;
    padding: 48px 0 0;
    box-shadow: inset -1px 0 0 rgba(255, 0, 0, .5), 0 0 10px rgba(255, 0, 0, 0.3); /* Stronger red shadow */
    background-color: #0f0f0f; /* Slightly lighter black for sidebar */
    color: white;
    width: 260px; /* Slightly wider sidebar */
}
.sidebar-sticky {
    position: relative;
    top: 0;
    height: calc(100vh - 48px);
    padding-top: .5rem;
    overflow-x: hidden;
    overflow-y: auto;
}
.sidebar .nav-link {
    font-weight: 600; /* Bolder text */
    color: rgba(255, 255, 255, .95); /* Brighter white text */
    padding: 0.7rem 1.2rem; /* Larger padding */
    margin-bottom: 5px; /* Space between items */
    border-radius: 5px; /* Rounded corners */
    transition: all 0.3s ease; /* Smooth transition */
    font-size: 1.05rem; /* Slightly larger font */
}
.sidebar .nav-link:hover {
    color: #ffffff; /* White text on hover */
    background-color: rgba(255, 0, 0, .15); /* Slight red background on hover */
    transform: translateX(5px); /* Slight movement on hover */
}
.sidebar .nav-link.active {
    color: #ffffff; /* White text when active */
    background-color: rgba(255, 0, 0, .25); /* Stronger red background */
    border-left: 4px solid #ff3333; /* Red border on active */
    font-weight: 700; /* Bolder when active */
}
.sidebar .nav-link i {
    margin-right: 12px; /* More space after icon */
    color: #ff3333; /* Brighter red icons */
    font-size: 1.2rem; /* Larger icons */
    width: 25px; /* Fixed width for alignment */
    text-align: center; /* Center icons */
}
.main-content {
    margin-left: 260px; /* Match sidebar width */
    padding: 2.5rem; /* More padding */
    background-color: #0a0a0a; /* Slightly lighter black background */
}
.card {
    margin-bottom: 2rem; /* More space between cards */
    box-shadow: 0 0.25rem 0.5rem rgba(255, 0, 0, 0.3), 0 0 15px rgba(255, 0, 0, 0.1); /* Stronger red shadow */
    background-color: #151515; /* Slightly lighter dark gray background */
    border: 2px solid #ff3333; /* Thicker, brighter red border */
    border-radius: 8px; /* More rounded corners */
    overflow: hidden; /* Keep content inside rounded corners */
    transition: transform 0.3s ease, box-shadow 0.3s ease; /* Animation */
}
.card:hover {
    transform: translateY(-5px); /* Slight lift on hover */
    box-shadow: 0 0.5rem 1rem rgba(255, 0, 0, 0.4), 0 0 20px rgba(255, 0, 0, 0.2); /* Stronger shadow on hover */
}
.card-header {
    background-color: #0f0f0f; /* Slightly lighter black background */
    border-bottom: 2px solid #ff3333; /* Thicker red border */
    color: #ffffff; /* White text */
    padding: 1rem 1.25rem; /* More padding */
    font-weight: 600; /* Bolder text */
    font-size: 1.2rem; /* Larger font */
}
.stat-card {
    text-align: center;
    padding: 2rem; /* More padding */
    background-color: #151515; /* Slightly lighter dark gray background */
    border: 2px solid #ff3333; /* Thicker, brighter red border */
    border-radius: 8px; /* Rounded corners */
    transition: transform 0.3s ease, box-shadow 0.3s ease; /* Animation */
    height: 100%; /* Full height */
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    box-shadow: 0 0.25rem 0.5rem rgba(255, 0, 0, 0.2); /* Red shadow */
}
.stat-card:hover {
    transform: translateY(-5px); /* Slight lift on hover */
    box-shadow: 0 0.5rem 1rem rgba(255, 0, 0, 0.3); /* Stronger shadow on hover */
}
.stat-card i {
    font-size: 3rem; /* Larger icons */
    margin-bottom: 1.25rem; /* More space below icon */
    color: #ff3333; /* Brighter red icons */
    background: linear-gradient(45deg, #ff3333, #ff6666); /* Gradient effect */
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 0 2px rgba(255, 0, 0, 0.5)); /* Glow effect */
}
.stat-card .stat-value {
    font-size: 2.5rem; /* Larger value */
    font-weight: bold;
    color: #ffffff; /* White text */
    margin-bottom: 0.5rem; /* Space below value */
    text-shadow: 0 0 10px rgba(255, 255, 255, 0.3); /* Glow effect */
}
.stat-card .stat-label {
    font-size: 1.1rem; /* Larger label */
    color: #ffffff; /* White text */
    font-weight: 600; /* Bolder text */
    text-transform: uppercase; /* Uppercase text */
    letter-spacing: 1px; /* Spaced letters */
}
/* Button styles */
.btn {
    font-weight: 600;
}
.btn-primary {
    background-color: #ff3333;
    border-color: #ff3333;
    color: #ffffff;
}
.btn-primary:hover, .btn-primary:focus {
    background-color: #ff5555;
    border-color: #ff5555;
    color: #ffffff;
}
.btn-danger {
    background-color: #ff3333;
    border-color: #ff3333;
    color: #ffffff;
}
.btn-danger:hover, .btn-danger:focus {
    background-color: #ff5555;
    border-color: #ff5555;
    color: #ffffff;
}
.btn-success {
    background-color: #00cc44;
    border-color: #00cc44;
    color: #ffffff;
}
.btn-success:hover, .btn-success:focus {
    background-color: #00ee55;
    border-color: #00ee55;
    color: #ffffff;
}
.btn-outline-danger {
    border-color: #ff3333;
    color: #ffffff;
}
.btn-outline-danger:hover, .btn-outline-danger:focus {
    background-color: #ff3333;
    border-color: #ff3333;
    color: #ffffff;
}

/* Form styles */
.form-label {
    color: #ffffff;
    font-weight: 600;
}
.form-control {
    background-color: #0f0f0f;
    border: 2px solid #ff3333;
    color: #ffffff;
}
.form-control:focus {
    background-color: #0f0f0f;
    border-color: #ff6666;
    color: #ffffff;
    box-shadow: 0 0 0 0.25rem rgba(255, 51, 51, 0.25);
}
.form-select {
    background-color: #0f0f0f;
    border: 2px solid #ff3333;
    color: #ffffff;
}
.form-select:focus {
    background-color: #0f0f0f;
    border-color: #ff6666;
    color: #ffffff;
    box-shadow: 0 0 0 0.25rem rgba(255, 51, 51, 0.25);
}
.input-group-text {
    background-color: #0f0f0f;
    border: 2px solid #ff3333;
    color: #ffffff;
}

/* Table styles */
table {
    color: #ffffff;
}
.table {
    color: #ffffff;
    border-color: rgba(255, 51, 51, 0.2);
}
.table th {
    color: #ffffff;
    font-weight: 600;
    border-color: rgba(255, 51, 51, 0.3);
}
.table td {
    color: #ffffff;
    border-color: rgba(255, 51, 51, 0.2);
}

/* Alert styles */
.alert {
    background-color: #151515;
    color: #ffffff;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    font-weight: 500;
    font-size: 1.1rem;
    margin-bottom: 1.5rem;
}
.alert-success {
    border: 2px solid #00ff66;
    box-shadow: 0 0 15px rgba(0, 255, 102, 0.2);
}
.alert-danger {
    border: 2px solid #ff3333;
    box-shadow: 0 0 15px rgba(255, 51, 51, 0.2);
}
.alert-warning {
    border: 2px solid #ffcc00;
    box-shadow: 0 0 15px rgba(255, 204, 0, 0.2);
}
.alert-info {
    border: 2px solid #33b5ff;
    box-shadow: 0 0 15px rgba(51, 181, 255, 0.2);
}

@media (max-width: 767.98px) {
    .sidebar {
        width: 100%;
        height: auto;
        position: relative;
        top: 0;
    }
    .main-content {
        margin-left: 0;
    }
}
"""
            )
except Exception as e:
    print(f"Error creating CSS file: {e}")

# Create the necessary directories
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(script_dir, 'templates'), exist_ok=True)
    os.makedirs(os.path.join(script_dir, 'static'), exist_ok=True)
    os.makedirs(os.path.join(script_dir, 'static', 'css'), exist_ok=True)
except Exception as e:
    print(f"Error creating dashboard directories: {e}")

@app.route('/privacy')
def privacy():
    """Display the privacy policy"""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Display the terms of service"""
    return render_template('terms.html')

if __name__ == '__main__':
    # Run the Flask app directly if this script is executed
    app.run(host='0.0.0.0', port=5000, debug=True)