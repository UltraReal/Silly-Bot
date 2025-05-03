import sqlite3
import os
import datetime
import json

# Database file path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.db')

def init_db():
    """Initialize the database with required tables"""
    try:
        # Make sure the directory exists
        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create URL scans table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_like TEXT NOT NULL,
            url TEXT NOT NULL,
            is_malicious INTEGER NOT NULL,
            scan_result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create media scans table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS media_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_like TEXT NOT NULL,
            media_url TEXT NOT NULL,
            content_type TEXT NOT NULL,
            is_nsfw INTEGER NOT NULL,
            scan_result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create violations table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_like TEXT NOT NULL,
            content TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            scan_result TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create users table for dashboard login
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dashboard_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            role TEXT DEFAULT 'user'
        )
        ''')
        
        # Create system events table for tracking bot operations
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user_id TEXT,
            username TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create settings table for bot configuration
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS bot_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_name TEXT UNIQUE NOT NULL,
            setting_value TEXT NOT NULL,
            updated_by TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Add default admin user if it doesn't exist
        cursor.execute('SELECT * FROM dashboard_users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            # Default password: "admin" - you should change this immediately
            import hashlib
            default_password = hashlib.sha256('admin'.encode()).hexdigest()
            cursor.execute('INSERT INTO dashboard_users (username, password_hash, is_admin, role) VALUES (?, ?, ?, ?)',
                          ('admin', default_password, 1, 'owner'))
        
        # Add default settings if they don't exist
        cursor.execute('SELECT * FROM bot_settings WHERE setting_name = ?', ('safe_mode_enabled',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO bot_settings (setting_name, setting_value, updated_by) VALUES (?, ?, ?)',
                          ('safe_mode_enabled', 'false', 'system'))
            
        cursor.execute('SELECT * FROM bot_settings WHERE setting_name = ?', ('safe_mode_threshold',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO bot_settings (setting_name, setting_value, updated_by) VALUES (?, ?, ?)',
                          ('safe_mode_threshold', 'medium', 'system'))
                          
        cursor.execute('SELECT * FROM bot_settings WHERE setting_name = ?', ('safe_display_mode',))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO bot_settings (setting_name, setting_value, updated_by) VALUES (?, ?, ?)',
                          ('safe_display_mode', 'false', 'system'))
                          
        # Check if the role column exists in the dashboard_users table
        cursor.execute("PRAGMA table_info(dashboard_users)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        # If the role column doesn't exist, add it
        if 'role' not in column_names:
            print("Adding 'role' column to dashboard_users table...")
            cursor.execute('ALTER TABLE dashboard_users ADD COLUMN role TEXT DEFAULT "user"')
            
            # Update existing users to have appropriate roles
            cursor.execute('UPDATE dashboard_users SET role = "user" WHERE is_admin = 0')
            cursor.execute('UPDATE dashboard_users SET role = "owner" WHERE is_admin = 1')
            conn.commit()
        
        conn.commit()
        conn.close()
        print("Dashboard database initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing database: {e}")
        return False

def log_url_scan(user_id, username, ip_like, url, is_malicious, scan_result, threat_level="low"):
    """
    Enhanced function to log a URL scan to the database with more detailed information
    
    Parameters:
    - user_id: Discord user ID
    - username: Discord username
    - ip_like: IP-like identifier for the user
    - url: URL that was scanned
    - is_malicious: Whether the URL was detected as malicious
    - scan_result: Results from scanning the URL
    - threat_level: Severity of the threat if malicious ("low", "medium", "high", "critical")
    """
    # Make sure the url_scans table has the necessary columns
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if we need to add new columns to the table
    cursor.execute("PRAGMA table_info(url_scans)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Add threat_level column if it doesn't exist
    if "threat_level" not in columns:
        cursor.execute("ALTER TABLE url_scans ADD COLUMN threat_level TEXT")
        print("[DATABASE] Added threat_level column to url_scans table")
    
    # Get current timestamp in ISO format
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Extract domain from URL for easier querying
    domain = ""
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
    except:
        pass
    
    # Add domain column if it doesn't exist
    if "domain" not in columns:
        cursor.execute("ALTER TABLE url_scans ADD COLUMN domain TEXT")
        print("[DATABASE] Added domain column to url_scans table")
    
    # Insert the URL scan with all available information
    try:
        cursor.execute('''
        INSERT INTO url_scans (
            user_id, username, ip_like, url, domain, is_malicious, 
            scan_result, timestamp, threat_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(user_id),
            username,
            ip_like,
            url,
            domain,
            1 if is_malicious else 0,
            scan_result,
            timestamp,
            threat_level
        ))
        
        conn.commit()
        print(f"[DATABASE] Successfully logged URL scan for user {username} (ID: {user_id})")
    except Exception as e:
        print(f"[DATABASE] Error logging URL scan: {e}")
    finally:
        conn.close()
    
def log_media_scan(user_id, username, ip_like, media_url, content_type, is_nsfw, scan_result, threat_level="medium"):
    """
    Enhanced function to log a media scan to the database with more detailed information
    
    Parameters:
    - user_id: Discord user ID
    - username: Discord username
    - ip_like: IP-like identifier for the user
    - media_url: URL of the media that was scanned
    - content_type: Type of media content (image, video, etc.)
    - is_nsfw: Whether the media was detected as NSFW
    - scan_result: Results from scanning the media
    - threat_level: Severity of the threat if NSFW ("low", "medium", "high", "critical")
    """
    # Make sure the media_scans table has the necessary columns
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if we need to add new columns to the table
    cursor.execute("PRAGMA table_info(media_scans)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Add threat_level column if it doesn't exist
    if "threat_level" not in columns:
        cursor.execute("ALTER TABLE media_scans ADD COLUMN threat_level TEXT")
        print("[DATABASE] Added threat_level column to media_scans table")
    
    # Get current timestamp in ISO format
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Extract filename from URL for easier reference
    filename = ""
    try:
        import os
        from urllib.parse import urlparse
        parsed_url = urlparse(media_url)
        filename = os.path.basename(parsed_url.path)
    except:
        pass
    
    # Add filename column if it doesn't exist
    if "filename" not in columns:
        cursor.execute("ALTER TABLE media_scans ADD COLUMN filename TEXT")
        print("[DATABASE] Added filename column to media_scans table")
    
    # Insert the media scan with all available information
    try:
        cursor.execute('''
        INSERT INTO media_scans (
            user_id, username, ip_like, media_url, filename, content_type, 
            is_nsfw, scan_result, timestamp, threat_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(user_id),
            username,
            ip_like,
            media_url,
            filename,
            content_type,
            1 if is_nsfw else 0,
            scan_result,
            timestamp,
            threat_level
        ))
        
        conn.commit()
        print(f"[DATABASE] Successfully logged media scan for user {username} (ID: {user_id})")
    except Exception as e:
        print(f"[DATABASE] Error logging media scan: {e}")
    finally:
        conn.close()

def log_violation(user_id, username, ip_like, content, violation_type, scan_result=None, threat_level="medium", additional_info=None):
    """
    Enhanced function to log a violation to the database with more detailed information
    
    Parameters:
    - user_id: Discord user ID
    - username: Discord username
    - ip_like: IP-like identifier for the user
    - content: Content that triggered the violation
    - violation_type: Type of violation
    - scan_result: Results from scanning the content
    - threat_level: Severity of the threat ("low", "medium", "high", "critical")
    - additional_info: Any additional information to include
    """
    # Make sure the violations table has the necessary columns
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if we need to add new columns to the table
    cursor.execute("PRAGMA table_info(violations)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Add threat_level column if it doesn't exist
    if "threat_level" not in columns:
        cursor.execute("ALTER TABLE violations ADD COLUMN threat_level TEXT")
        print("[DATABASE] Added threat_level column to violations table")
    
    # Add additional_info column if it doesn't exist
    if "additional_info" not in columns:
        cursor.execute("ALTER TABLE violations ADD COLUMN additional_info TEXT")
        print("[DATABASE] Added additional_info column to violations table")
    
    # Get current timestamp in ISO format
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Insert the violation with all available information
    try:
        cursor.execute('''
        INSERT INTO violations (
            user_id, username, ip_like, content, violation_type, 
            scan_result, timestamp, threat_level, additional_info
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(user_id),
            username,
            ip_like,
            content,
            violation_type,
            scan_result,
            timestamp,
            threat_level,
            additional_info
        ))
        
        conn.commit()
        print(f"[DATABASE] Successfully logged violation for user {username} (ID: {user_id})")
    except Exception as e:
        print(f"[DATABASE] Error logging violation: {e}")
    finally:
        conn.close()
    
def log_system_event(event_type, user_id=None, username=None, details=None):
    """Log a system event to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO system_events (event_type, user_id, username, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            event_type,
            str(user_id) if user_id else None,
            username,
            details,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error logging system event: {e}")
        return False
        
def log_login_attempt(username, ip_address, success, reason=None):
    """Log login attempts for security monitoring"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if login_attempts table exists, create it if not
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            success INTEGER NOT NULL,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        cursor.execute(
            'INSERT INTO login_attempts (username, ip_address, success, reason) VALUES (?, ?, ?, ?)',
            (username, ip_address, 1 if success else 0, reason)
        )
        
        # Also log to system events for consistency
        event_type = "Login Success" if success else "Login Failure"
        details = f"IP: {ip_address}" + (f", Reason: {reason}" if reason else "")
        
        cursor.execute('''
        INSERT INTO system_events (event_type, username, details, timestamp)
        VALUES (?, ?, ?, ?)
        ''', (
            event_type,
            username,
            details,
            datetime.datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        print(f"Error logging login attempt: {e}")
        return False
        
def get_login_statistics():
    """Get statistics about login attempts for the system management page"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Total login attempts
        cursor.execute('SELECT COUNT(*) FROM login_attempts')
        total_attempts = cursor.fetchone()[0]
        
        # Successful login attempts
        cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 1')
        successful_attempts = cursor.fetchone()[0]
        
        # Failed login attempts
        cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 0')
        failed_attempts = cursor.fetchone()[0]
        
        # Recent failed attempts (last 24 hours)
        yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
        cursor.execute('SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND timestamp > ?', (yesterday,))
        recent_failed_attempts = cursor.fetchone()[0]
        
        # Top 5 IPs with failed attempts
        cursor.execute('''
        SELECT ip_address, COUNT(*) as count 
        FROM login_attempts 
        WHERE success = 0 
        GROUP BY ip_address 
        ORDER BY count DESC 
        LIMIT 5
        ''')
        top_failed_ips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Top 5 usernames with failed attempts
        cursor.execute('''
        SELECT username, COUNT(*) as count 
        FROM login_attempts 
        WHERE success = 0 
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 5
        ''')
        top_failed_usernames = [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'failed_attempts': failed_attempts,
            'recent_failed_attempts': recent_failed_attempts,
            'top_failed_ips': top_failed_ips,
            'top_failed_usernames': top_failed_usernames
        }
    except Exception as e:
        print(f"Error getting login statistics: {e}")
        return {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'recent_failed_attempts': 0,
            'top_failed_ips': [],
            'top_failed_usernames': []
        }

def check_login_attempts(ip_address, username=None, window_minutes=15, max_attempts=5):
    """
    Check if there have been too many failed login attempts from this IP or for this username
    
    Args:
        ip_address: The IP address to check
        username: Optional username to check
        window_minutes: Time window in minutes to check for attempts
        max_attempts: Maximum number of failed attempts allowed in the window
        
    Returns:
        tuple: (blocked, remaining_seconds, attempt_count)
            - blocked: True if too many failed attempts
            - remaining_seconds: Seconds until the block expires
            - attempt_count: Number of failed attempts in the window
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Calculate the timestamp for the start of the window
        window_start = (datetime.datetime.now() - datetime.timedelta(minutes=window_minutes)).isoformat()
        
        # Query for failed attempts from this IP
        if username:
            # Check both IP and username
            cursor.execute('''
            SELECT COUNT(*), MAX(timestamp) FROM login_attempts 
            WHERE ip_address = ? AND username = ? AND success = 0 AND timestamp > ?
            ''', (ip_address, username, window_start))
        else:
            # Check IP only
            cursor.execute('''
            SELECT COUNT(*), MAX(timestamp) FROM login_attempts 
            WHERE ip_address = ? AND success = 0 AND timestamp > ?
            ''', (ip_address, window_start))
            
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, 0, 0
            
        attempt_count, last_attempt = result
        
        # If we've exceeded the maximum attempts
        if attempt_count >= max_attempts:
            # Calculate how long until the window expires
            if last_attempt:
                last_attempt_time = datetime.datetime.fromisoformat(last_attempt)
                window_end = last_attempt_time + datetime.timedelta(minutes=window_minutes)
                now = datetime.datetime.now()
                
                if now < window_end:
                    remaining_seconds = int((window_end - now).total_seconds())
                    return True, remaining_seconds, attempt_count
            
        return False, 0, attempt_count
        
    except Exception as e:
        print(f"Error checking login attempts: {e}")
        return False, 0, 0

def get_url_scans(limit=100, offset=0, user_id=None, from_date=None, to_date=None, is_malicious=None):
    """Get URL scans from the database with optional filtering"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url_scans'")
        if not cursor.fetchone():
            return []
        
        query = "SELECT * FROM url_scans WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if from_date:
            query += " AND timestamp >= ?"
            params.append(from_date)
        
        if to_date:
            query += " AND timestamp <= ?"
            params.append(to_date)
        
        if is_malicious is not None:
            query += " AND is_malicious = ?"
            params.append(1 if is_malicious else 0)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return results
    except Exception as e:
        print(f"Error getting URL scans: {e}")
        return []
        
def get_media_scans(limit=100, offset=0, user_id=None, from_date=None, to_date=None, is_nsfw=None, content_type=None):
    """Get media scans from the database with optional filtering"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='media_scans'")
        if not cursor.fetchone():
            return []
        
        query = "SELECT * FROM media_scans WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if from_date:
            query += " AND timestamp >= ?"
            params.append(from_date)
        
        if to_date:
            query += " AND timestamp <= ?"
            params.append(to_date)
        
        if is_nsfw is not None:
            query += " AND is_nsfw = ?"
            params.append(1 if is_nsfw else 0)
            
        if content_type:
            query += " AND content_type = ?"
            params.append(content_type)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return results
    except Exception as e:
        print(f"Error getting media scans: {e}")
        return []

def get_system_events(limit=100, offset=0, event_type=None, user_id=None, from_date=None, to_date=None):
    """Get system events from the database with optional filtering"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_events'")
        if not cursor.fetchone():
            return []
        
        query = "SELECT * FROM system_events WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
            
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if from_date:
            query += " AND timestamp >= ?"
            params.append(from_date)
        
        if to_date:
            query += " AND timestamp <= ?"
            params.append(to_date)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return results
    except Exception as e:
        print(f"Error getting system events: {e}")
        return []

def get_violations(limit=100, offset=0, user_id=None, from_date=None, to_date=None, violation_type=None):
    """Get violations from the database with optional filtering"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='violations'")
        if not cursor.fetchone():
            return []
        
        query = "SELECT * FROM violations WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if from_date:
            query += " AND timestamp >= ?"
            params.append(from_date)
        
        if to_date:
            query += " AND timestamp <= ?"
            params.append(to_date)
        
        if violation_type:
            query += " AND violation_type = ?"
            params.append(violation_type)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return results
    except Exception as e:
        print(f"Error getting violations: {e}")
        return []

def get_statistics():
    """Get statistics for the dashboard"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        stats = {}
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url_scans'")
        if not cursor.fetchone():
            # Tables don't exist yet, return empty stats
            return {
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
        
        # Total URL scans
        cursor.execute("SELECT COUNT(*) FROM url_scans")
        stats['total_url_scans'] = cursor.fetchone()[0]
        
        # Malicious URL count
        cursor.execute("SELECT COUNT(*) FROM url_scans WHERE is_malicious = 1")
        stats['malicious_url_count'] = cursor.fetchone()[0]
        
        # Safe URL count
        cursor.execute("SELECT COUNT(*) FROM url_scans WHERE is_malicious = 0")
        stats['safe_url_count'] = cursor.fetchone()[0]
        
        # Check if media_scans table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='media_scans'")
        if cursor.fetchone():
            # Total media scans
            cursor.execute("SELECT COUNT(*) FROM media_scans")
            stats['total_media_scans'] = cursor.fetchone()[0]
            
            # NSFW media count
            cursor.execute("SELECT COUNT(*) FROM media_scans WHERE is_nsfw = 1")
            stats['nsfw_media_count'] = cursor.fetchone()[0]
            
            # Safe media count
            cursor.execute("SELECT COUNT(*) FROM media_scans WHERE is_nsfw = 0")
            stats['safe_media_count'] = cursor.fetchone()[0]
            
            # Media by type
            cursor.execute("SELECT content_type, COUNT(*) FROM media_scans GROUP BY content_type")
            stats['media_by_type'] = dict(cursor.fetchall())
        else:
            stats['total_media_scans'] = 0
            stats['nsfw_media_count'] = 0
            stats['safe_media_count'] = 0
            stats['media_by_type'] = {}
        
        # Total violations
        cursor.execute("SELECT COUNT(*) FROM violations")
        stats['total_violations'] = cursor.fetchone()[0]
        
        # Violations by type
        cursor.execute("SELECT violation_type, COUNT(*) FROM violations GROUP BY violation_type")
        stats['violations_by_type'] = dict(cursor.fetchall())
        
        # Recent activity (last 7 days)
        seven_days_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).isoformat()
        
        cursor.execute("SELECT COUNT(*) FROM url_scans WHERE timestamp >= ?", (seven_days_ago,))
        stats['recent_url_scans'] = cursor.fetchone()[0]
        
        if 'total_media_scans' in stats and stats['total_media_scans'] > 0:
            cursor.execute("SELECT COUNT(*) FROM media_scans WHERE timestamp >= ?", (seven_days_ago,))
            stats['recent_media_scans'] = cursor.fetchone()[0]
        else:
            stats['recent_media_scans'] = 0
        
        cursor.execute("SELECT COUNT(*) FROM violations WHERE timestamp >= ?", (seven_days_ago,))
        stats['recent_violations'] = cursor.fetchone()[0]
        
        # Top users with malicious URLs
        cursor.execute("""
        SELECT username, COUNT(*) as count 
        FROM url_scans 
        WHERE is_malicious = 1 
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 5
        """)
        stats['top_malicious_users'] = dict(cursor.fetchall())
        
        # Top users with NSFW media
        if 'total_media_scans' in stats and stats['total_media_scans'] > 0:
            cursor.execute("""
            SELECT username, COUNT(*) as count 
            FROM media_scans 
            WHERE is_nsfw = 1 
            GROUP BY username 
            ORDER BY count DESC 
            LIMIT 5
            """)
            stats['top_nsfw_users'] = dict(cursor.fetchall())
        else:
            stats['top_nsfw_users'] = {}
        
        conn.close()
        return stats
    except Exception as e:
        print(f"Error getting statistics: {e}")
        # Return empty stats in case of error
        return {
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

def clear_url_scans():
    """Clear all URL scan data from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url_scans'")
        if cursor.fetchone():
            # Delete all records from the table
            cursor.execute("DELETE FROM url_scans")
            
            # Reset the auto-increment counter
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='url_scans'")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error clearing URL scans: {e}")
        return False

def clear_media_scans():
    """Clear all media scan data from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='media_scans'")
        if cursor.fetchone():
            # Delete all records from the table
            cursor.execute("DELETE FROM media_scans")
            
            # Reset the auto-increment counter
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='media_scans'")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error clearing media scans: {e}")
        return False

def clear_violations():
    """Clear all violation data from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='violations'")
        if cursor.fetchone():
            # Delete all records from the table
            cursor.execute("DELETE FROM violations")
            
            # Reset the auto-increment counter
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='violations'")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error clearing violations: {e}")
        return False

def clear_all_scan_data():
    """Clear all scan data (URLs, media, violations) from the database"""
    url_success = clear_url_scans()
    media_success = clear_media_scans()
    violations_success = clear_violations()
    
    return url_success and media_success and violations_success

def get_setting(setting_name, default_value=None):
    """Get a setting value from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT setting_value FROM bot_settings WHERE setting_name = ?", (setting_name,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return result[0]
        return default_value
    except Exception as e:
        print(f"Error getting setting {setting_name}: {e}")
        return default_value

def update_setting(setting_name, setting_value, updated_by="system"):
    """Update a setting in the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if setting exists
        cursor.execute("SELECT id FROM bot_settings WHERE setting_name = ?", (setting_name,))
        if cursor.fetchone():
            # Update existing setting
            cursor.execute(
                "UPDATE bot_settings SET setting_value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_name = ?",
                (setting_value, updated_by, setting_name)
            )
        else:
            # Insert new setting
            cursor.execute(
                "INSERT INTO bot_settings (setting_name, setting_value, updated_by) VALUES (?, ?, ?)",
                (setting_name, setting_value, updated_by)
            )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating setting {setting_name}: {e}")
        return False

def is_safe_mode_enabled():
    """Check if Safe Mode is enabled"""
    return get_setting('safe_mode_enabled', 'false').lower() == 'true'

def get_safe_mode_threshold():
    """Get the Safe Mode threshold level"""
    return get_setting('safe_mode_threshold', 'medium')
    
def is_safe_display_mode_enabled():
    """Check if Safe Display Mode is enabled"""
    return get_setting('safe_display_mode', 'false').lower() == 'true'

def verify_user(username, password):
    """Verify dashboard user credentials"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    cursor.execute('SELECT id, username, is_admin, role FROM dashboard_users WHERE username = ? AND password_hash = ?',
                  (username, password_hash))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'is_admin': bool(user[2]),
            'role': user[3] or 'user'  # Default to 'user' if NULL
        }
    return None

def change_password(username, new_password):
    """Change a user's password"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    import hashlib
    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    cursor.execute('UPDATE dashboard_users SET password_hash = ? WHERE username = ?',
                  (password_hash, username))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success
    
def get_all_users():
    """Get all dashboard users"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, is_admin, role FROM dashboard_users ORDER BY username')
    users = [{'id': row[0], 'username': row[1], 'is_admin': bool(row[2]), 'role': row[3] or 'user'} for row in cursor.fetchall()]
    
    conn.close()
    return users
    
def add_user(username, password, is_admin=False, role='user'):
    """Add a new dashboard user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        import hashlib
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute('INSERT INTO dashboard_users (username, password_hash, is_admin, role) VALUES (?, ?, ?, ?)',
                      (username, password_hash, 1 if is_admin else 0, role))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log the action
        log_system_event(f"New user created: {username} (Role: {role}, Admin: {'Yes' if is_admin else 'No'})")
        
        return user_id
    except Exception as e:
        print(f"Error adding user: {e}")
        return None
        
def delete_user(user_id):
    """Delete a dashboard user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First get the username for logging
        cursor.execute('SELECT username FROM dashboard_users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False
            
        username = user[0]
        
        # Don't allow deleting the last admin
        cursor.execute('SELECT COUNT(*) FROM dashboard_users WHERE is_admin = 1')
        admin_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT is_admin FROM dashboard_users WHERE id = ?', (user_id,))
        is_admin = cursor.fetchone()[0]
        
        if is_admin and admin_count <= 1:
            conn.close()
            return False  # Can't delete the last admin
        
        cursor.execute('DELETE FROM dashboard_users WHERE id = ?', (user_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if success:
            # Log the action
            log_system_event(f"User deleted: {username}")
        
        return success
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False
        
def toggle_admin_status(user_id):
    """Toggle a user's admin status"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First check if this is an admin and if it's the last one
        cursor.execute('SELECT username, is_admin FROM dashboard_users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False
            
        username, is_admin = user
        
        # If removing admin status, make sure it's not the last admin
        if is_admin:
            cursor.execute('SELECT COUNT(*) FROM dashboard_users WHERE is_admin = 1')
            admin_count = cursor.fetchone()[0]
            
            if admin_count <= 1:
                conn.close()
                return False  # Can't remove admin status from the last admin
        
        # Toggle the admin status
        new_status = 0 if is_admin else 1
        cursor.execute('UPDATE dashboard_users SET is_admin = ? WHERE id = ?', (new_status, user_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if success:
            # Log the action
            action = "removed from" if is_admin else "granted to"
            log_system_event(f"Admin privileges {action} user: {username}")
        
        return success
    except Exception as e:
        print(f"Error toggling admin status: {e}")
        return False
        
def change_username(user_id, new_username):
    """Change a user's username"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First get the old username for logging
        cursor.execute('SELECT username FROM dashboard_users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False
            
        old_username = user[0]
        
        # Check if the new username already exists
        cursor.execute('SELECT id FROM dashboard_users WHERE username = ? AND id != ?', (new_username, user_id))
        if cursor.fetchone():
            conn.close()
            return False  # Username already exists
        
        # Update the username
        cursor.execute('UPDATE dashboard_users SET username = ? WHERE id = ?', (new_username, user_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if success:
            # Log the action
            log_system_event(f"Username changed: {old_username} → {new_username}")
        
        return success
    except Exception as e:
        print(f"Error changing username: {e}")
        return False
        
def update_user_role(user_id, new_role):
    """Update a user's role"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First get the username and old role for logging
        cursor.execute('SELECT username, role FROM dashboard_users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return False
            
        username, old_role = user
        old_role = old_role or 'user'  # Default to 'user' if NULL
        
        # Update the role
        cursor.execute('UPDATE dashboard_users SET role = ? WHERE id = ?', (new_role, user_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if success:
            # Log the action
            log_system_event(f"Role changed for {username}: {old_role} → {new_role}")
        
        return success
    except Exception as e:
        print(f"Error updating user role: {e}")
        return False

# Functions for managing timeouts and bans
def get_active_timeouts():
    """Get a list of currently timed out users"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create the timeouts table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS timeouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            timeout_until TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        conn.commit()
        
        # Get current time in ISO format
        current_time = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Get active timeouts (where timeout_until is in the future)
        cursor.execute('''
        SELECT * FROM timeouts 
        WHERE timeout_until > ? 
        ORDER BY timeout_until DESC
        ''', (current_time,))
        
        timeouts = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return timeouts
    except Exception as e:
        print(f"Error getting active timeouts: {e}")
        return []
        
def get_timeout_by_user_id(user_id):
    """Get a timeout by user ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get current time in ISO format
        current_time = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Get active timeout for the user
        cursor.execute('''
        SELECT * FROM timeouts 
        WHERE user_id = ? AND timeout_until > ? 
        ORDER BY timeout_until DESC
        LIMIT 1
        ''', (user_id, current_time))
        
        timeout = cursor.fetchone()
        
        conn.close()
        return dict(timeout) if timeout else None
    except Exception as e:
        print(f"Error getting timeout by user ID: {e}")
        return None
        
def get_timeout_by_username(username):
    """Get a timeout by username"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get current time in ISO format
        current_time = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Get active timeout for the user
        cursor.execute('''
        SELECT * FROM timeouts 
        WHERE username LIKE ? AND timeout_until > ? 
        ORDER BY timeout_until DESC
        LIMIT 1
        ''', (f"%{username}%", current_time))
        
        timeout = cursor.fetchone()
        
        conn.close()
        return dict(timeout) if timeout else None
    except Exception as e:
        print(f"Error getting timeout by username: {e}")
        return None
        
def get_user_by_name_or_id(name_or_id):
    """Get a user by name or ID from any of the moderation tables"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Try to find the user in timeouts
        cursor.execute('''
        SELECT user_id, username FROM timeouts 
        WHERE user_id = ? OR username LIKE ? 
        LIMIT 1
        ''', (name_or_id, f"%{name_or_id}%"))
        
        user = cursor.fetchone()
        
        if not user:
            # Try to find the user in bans
            cursor.execute('''
            SELECT user_id, username FROM bans 
            WHERE user_id = ? OR username LIKE ? 
            LIMIT 1
            ''', (name_or_id, f"%{name_or_id}%"))
            
            user = cursor.fetchone()
        
        if not user:
            # Try to find the user in mutes
            cursor.execute('''
            SELECT user_id, username FROM mutes 
            WHERE user_id = ? OR username LIKE ? 
            LIMIT 1
            ''', (name_or_id, f"%{name_or_id}%"))
            
            user = cursor.fetchone()
        
        conn.close()
        return dict(user) if user else None
    except Exception as e:
        print(f"Error getting user by name or ID: {e}")
        return None

def get_banned_users():
    """Get a list of banned users"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create the bans table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        conn.commit()
        
        # Get all bans
        cursor.execute('''
        SELECT * FROM bans 
        ORDER BY timestamp DESC
        ''')
        
        bans = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return bans
    except Exception as e:
        print(f"Error getting banned users: {e}")
        return []
        
def get_ban_by_user_id(user_id):
    """Get a ban by user ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get ban for the user
        cursor.execute('''
        SELECT * FROM bans 
        WHERE user_id = ? 
        ORDER BY timestamp DESC
        LIMIT 1
        ''', (user_id,))
        
        ban = cursor.fetchone()
        
        conn.close()
        return dict(ban) if ban else None
    except Exception as e:
        print(f"Error getting ban by user ID: {e}")
        return None

def log_timeout(user_id, username, guild_id, guild_name, timeout_until, reason=None):
    """Log a timeout action to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create the timeouts table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS timeouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            timeout_until TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        conn.commit()
        
        # Get current time in ISO format
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Insert the timeout record
        cursor.execute('''
        INSERT INTO timeouts (user_id, username, guild_id, guild_name, timeout_until, reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, username, guild_id, guild_name, timeout_until, reason, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error logging timeout: {e}")
        return False
        
def add_timeout(user_id, username, guild_id, guild_name, duration_days, reason=None):
    """Add a timeout to the database with a specified duration in days"""
    try:
        # Calculate timeout end time
        timeout_until = (datetime.datetime.now(datetime.UTC) + 
                         datetime.timedelta(days=duration_days)).isoformat()
        
        # Log the timeout
        return log_timeout(user_id, username, guild_id, guild_name, timeout_until, reason)
    except Exception as e:
        print(f"Error adding timeout: {e}")
        return False
        
def add_mute(user_id, username, guild_id, guild_name, reason=None):
    """Add a mute to the database (permanent)"""
    try:
        # Create the mutes table if it doesn't exist
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS mutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        conn.commit()
        
        # Get current time in ISO format
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Insert the mute record
        cursor.execute('''
        INSERT INTO mutes (user_id, username, guild_id, guild_name, reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, guild_id, guild_name, reason, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error adding mute: {e}")
        return False
        
def get_muted_users():
    """Get a list of muted users"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create the mutes table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS mutes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        conn.commit()
        
        # Get all mutes
        cursor.execute('''
        SELECT * FROM mutes 
        ORDER BY timestamp DESC
        ''')
        
        mutes = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return mutes
    except Exception as e:
        print(f"Error getting muted users: {e}")
        return []
        
def remove_mute_by_user_id(user_id):
    """Remove a mute from the database by user ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete the mute record
        cursor.execute('DELETE FROM mutes WHERE user_id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing mute by user ID: {e}")
        return False
        
def remove_mute(mute_id):
    """Remove a mute from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete the mute record
        cursor.execute('DELETE FROM mutes WHERE id = ?', (mute_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing mute: {e}")
        return False
        
def get_guilds():
    """Get a list of all guilds from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get unique guilds from timeouts, bans, and mutes
        cursor.execute('''
        SELECT DISTINCT guild_id, guild_name FROM (
            SELECT guild_id, guild_name FROM timeouts
            UNION
            SELECT guild_id, guild_name FROM bans
            UNION
            SELECT guild_id, guild_name FROM mutes
        )
        ORDER BY guild_name
        ''')
        
        guilds = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return guilds
    except Exception as e:
        print(f"Error getting guilds: {e}")
        return []

def log_ban(user_id, username, guild_id, guild_name, reason=None):
    """Log a ban action to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create the bans table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            guild_id TEXT NOT NULL,
            guild_name TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        conn.commit()
        
        # Get current time in ISO format
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        
        # Insert the ban record
        cursor.execute('''
        INSERT INTO bans (user_id, username, guild_id, guild_name, reason, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, guild_id, guild_name, reason, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error logging ban: {e}")
        return False

def remove_timeout(timeout_id):
    """Remove a timeout from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete the timeout record
        cursor.execute('DELETE FROM timeouts WHERE id = ?', (timeout_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing timeout: {e}")
        return False

def remove_timeout_by_user_id(user_id):
    """Remove a timeout from the database by user ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete the timeout record
        cursor.execute('DELETE FROM timeouts WHERE user_id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing timeout by user ID: {e}")
        return False

def remove_ban(ban_id):
    """Remove a ban from the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete the ban record
        cursor.execute('DELETE FROM bans WHERE id = ?', (ban_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing ban: {e}")
        return False
        
def remove_ban_by_user_id(user_id):
    """Remove a ban from the database by user ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete the ban record
        cursor.execute('DELETE FROM bans WHERE user_id = ?', (user_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error removing ban by user ID: {e}")
        return False

# The database will be initialized when needed, not automatically on import