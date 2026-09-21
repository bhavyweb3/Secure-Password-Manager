import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime
import os
import base64
import secrets
import string
import random
import time
import hashlib
import threading
from typing import Optional

# Security imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

class SecurityManager:
    def __init__(self):
        self.session_start_time = None
        self.last_activity_time = None
        self.session_timeout = 300  # 5 minutes
        self.auto_lock_timer = None
        
    def start_session(self):
        """Start a new security session"""
        self.session_start_time = time.time()
        self.last_activity_time = time.time()
        self.start_auto_lock_timer()
    
    def record_activity(self):
        """Record user activity to prevent auto-lock"""
        self.last_activity_time = time.time()
    
    def start_auto_lock_timer(self):
        """Start timer for auto-lock functionality"""
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
        
        self.auto_lock_timer = threading.Timer(self.session_timeout, self.auto_lock)
        self.auto_lock_timer.daemon = True
        self.auto_lock_timer.start()
    
    def auto_lock(self):
        """Auto-lock the application"""
        if hasattr(self, 'callback') and self.callback:
            self.callback()
    
    def set_auto_lock_callback(self, callback):
        """Set callback function for auto-lock"""
        self.callback = callback
    
    def get_session_duration(self):
        """Get current session duration"""
        if self.session_start_time:
            return int(time.time() - self.session_start_time)
        return 0
    
    def get_inactivity_time(self):
        """Get time since last activity"""
        if self.last_activity_time:
            return int(time.time() - self.last_activity_time)
        return 0

class BreachMonitor:
    @staticmethod
    def check_password_breach(password: str) -> dict:
        """Check if password appears in known breaches (simulated)"""
        # In a real implementation, this would check against HIBP API
        # For demo purposes, we'll simulate common breached passwords
        
        common_breaches = [
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "qwerty", "abc123", "password1", "123123"
        ]
        
        if password in common_breaches:
            return {
                'breached': True,
                'severity': 'high',
                'message': 'This password appears in known data breaches!',
                'recommendation': 'Change this password immediately.'
            }
        
        # Simulate checking password hash against breached passwords
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        
        # Check against simulated breach database (first 5 chars of hash)
        breached_prefixes = ['5BAA6', '7C4A8', 'A9993']  # Simulated breached hash prefixes
        
        if any(password_hash.startswith(prefix) for prefix in breached_prefixes):
            return {
                'breached': True,
                'severity': 'medium',
                'message': 'Similar passwords have been breached.',
                'recommendation': 'Consider using a different password.'
            }
        
        return {
            'breached': False,
            'severity': 'none',
            'message': 'No known breaches found for this password.',
            'recommendation': 'This password appears secure.'
        }

class AdvancedPasswordGenerator:
    @staticmethod
    def generate_password(length: int = 16, use_uppercase: bool = True, 
                         use_lowercase: bool = True, use_numbers: bool = True, 
                         use_symbols: bool = True) -> str:
        """Generate a cryptographically secure random password"""
        characters = ""
        
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            raise ValueError("At least one character type must be selected")
        
        # Ensure password has at least one of each selected character type
        password = []
        if use_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_numbers:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill the rest with cryptographically secure random characters
        remaining_length = length - len(password)
        if remaining_length > 0:
            password.extend(secrets.choice(characters) for _ in range(remaining_length))
        
        # Shuffle the password using cryptographically secure random
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def check_password_strength(password: str) -> dict:
        """Advanced password strength analysis"""
        score = 0
        feedback = []
        requirements = {
            'length': False,
            'lowercase': False,
            'uppercase': False,
            'numbers': False,
            'symbols': False,
            'unique_chars': False
        }
        
        # Length check
        if len(password) >= 16:
            score += 3
            requirements['length'] = True
            feedback.append("✓ Excellent length (16+ characters)")
        elif len(password) >= 12:
            score += 2
            requirements['length'] = True
            feedback.append("✓ Good length (12+ characters)")
        elif len(password) >= 8:
            score += 1
            requirements['length'] = True
            feedback.append("✓ Minimum length (8+ characters)")
        else:
            feedback.append("✗ Too short (min 8 characters)")
        
        # Character variety checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if has_lower:
            score += 1
            requirements['lowercase'] = True
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("✗ Add lowercase letters")
        
        if has_upper:
            score += 1
            requirements['uppercase'] = True
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("✗ Add uppercase letters")
        
        if has_digit:
            score += 1
            requirements['numbers'] = True
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ Add numbers")
        
        if has_symbol:
            score += 2  # Extra points for symbols
            requirements['symbols'] = True
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Add special characters")
        
        # Entropy and uniqueness
        unique_chars = len(set(password))
        char_variety = unique_chars / len(password)
        
        if char_variety > 0.8:
            score += 2
            requirements['unique_chars'] = True
            feedback.append("✓ Excellent character variety")
        elif char_variety > 0.6:
            score += 1
            requirements['unique_chars'] = True
            feedback.append("✓ Good character variety")
        else:
            feedback.append("✗ Low character variety (repeating characters)")
        
        # Common patterns check
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("✗ Contains common patterns")
        
        # Sequential characters check
        sequential_chars = any(
            ord(password[i]) + 1 == ord(password[i+1]) == ord(password[i+2]) - 1
            for i in range(len(password) - 2)
        )
        if sequential_chars:
            score -= 1
            feedback.append("✗ Contains sequential characters")
        
        # Score mapping
        if score >= 8:
            level = "Very Strong"
            color = "darkgreen"
        elif score >= 6:
            level = "Strong"
            color = "green"
        elif score >= 4:
            level = "Good"
            color = "orange"
        elif score >= 2:
            level = "Weak"
            color = "red"
        else:
            level = "Very Weak"
            color = "darkred"
        
        # Requirements met calculation
        met_requirements = sum(requirements.values())
        total_requirements = len(requirements)
        
        return {
            'score': score,
            'level': level,
            'color': color,
            'feedback': feedback,
            'requirements_met': f"{met_requirements}/{total_requirements}",
            'all_requirements_met': met_requirements == total_requirements
        }

class MasterPasswordValidator:
    @staticmethod
    def validate_master_password(password: str) -> dict:
        """Validate master password strength"""
        issues = []
        score = 0
        
        if len(password) < 12:
            issues.append("Must be at least 12 characters long")
        else:
            score += 1
        
        if not any(c.islower() for c in password):
            issues.append("Must contain lowercase letters")
        else:
            score += 1
        
        if not any(c.isupper() for c in password):
            issues.append("Must contain uppercase letters")
        else:
            score += 1
        
        if not any(c.isdigit() for c in password):
            issues.append("Must contain numbers")
        else:
            score += 1
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Must contain special characters")
        else:
            score += 1
        
        # Check for common passwords
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if any(common in password.lower() for common in common_passwords):
            issues.append("Avoid common passwords")
            score -= 1
        
        if score == 5:
            return {"valid": True, "score": score, "issues": [], "strength": "Excellent"}
        elif score >= 3:
            return {"valid": True, "score": score, "issues": issues, "strength": "Good"}
        else:
            return {"valid": False, "score": score, "issues": issues, "strength": "Weak"}

class EncryptionManager:
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt_password(self, plaintext_password: str, master_password: str) -> dict:
        """Encrypt a password using AES-256-GCM"""
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        
        key = self.derive_key(master_password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_password.encode('utf-8')) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    def decrypt_password(self, encrypted_data: dict, master_password: str) -> str:
        """Decrypt a password using AES-256-GCM"""
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            salt = base64.b64decode(encrypted_data['salt'])
            iv = base64.b64decode(encrypted_data['iv'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            key = self.derive_key(master_password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except InvalidTag:
            raise ValueError("Authentication failed! Data may have been tampered with.")
        except Exception as e:
            raise ValueError("Decryption failed. Wrong master password or corrupted data.")
"""
Password database management with SQLite
Handles storage and retrieval of encrypted passwords using SQLite database
"""



class PasswordDatabase:
    """Manages the password database with SQLite storage"""
    
    def __init__(self, db_file="passwords_secure.db"):
        self.db_file = db_file
        self.connection = None
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            self.connection = sqlite3.connect(self.db_file, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row  # Enable dictionary-like access
            
            cursor = self.connection.cursor()
            
            # Create passwords table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version TEXT DEFAULT '2.0',
                    encryption TEXT DEFAULT 'AES-256-GCM',
                    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_passwords INTEGER DEFAULT 0
                )
            ''')
            
            # Initialize metadata if not exists
            cursor.execute('''
                INSERT OR IGNORE INTO metadata (id, version, encryption, created, total_passwords)
                VALUES (1, '2.0', 'AES-256-GCM', CURRENT_TIMESTAMP, 0)
            ''')
            
            self.connection.commit()
            print(f"✅ Database initialized: {self.db_file}")
            
        except sqlite3.Error as e:
            print(f"❌ Database initialization error: {e}")
            raise
    
    def _update_metadata(self):
        """Update metadata with current statistics"""
        try:
            cursor = self.connection.cursor()
            
            # Count total passwords
            cursor.execute('SELECT COUNT(*) as count FROM passwords')
            total_passwords = cursor.fetchone()['count']
            
            # Update metadata
            cursor.execute('''
                UPDATE metadata 
                SET total_passwords = ?, last_modified = CURRENT_TIMESTAMP
                WHERE id = 1
            ''', (total_passwords,))
            
            self.connection.commit()
            
        except sqlite3.Error as e:
            print(f"❌ Metadata update error: {e}")
    
    def store_password(self, service, username, encrypted_data):
        """Store encrypted password for a service"""
        if not service or not username:
            raise ValueError("Service and username are required")
        
        try:
            cursor = self.connection.cursor()
            
            # Insert or replace password entry
            cursor.execute('''
                INSERT OR REPLACE INTO passwords 
                (service, username, ciphertext, salt, iv, tag, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                service,
                username,
                encrypted_data['ciphertext'],
                encrypted_data['salt'],
                encrypted_data['iv'],
                encrypted_data['tag']
            ))
            
            self.connection.commit()
            self._update_metadata()
            
            print(f"✅ Password stored for service: {service}")
            
        except sqlite3.Error as e:
            print(f"❌ Database error storing password: {e}")
            raise Exception(f"Failed to store password: {str(e)}")
    
    def get_password(self, service):
        """Retrieve encrypted password for a service"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                SELECT service, username, ciphertext, salt, iv, tag, created, last_modified
                FROM passwords WHERE service = ?
            ''', (service,))
            
            row = cursor.fetchone()
            
            if row:
                return {
                    'service': row['service'],
                    'username': row['username'],
                    'encrypted_data': {
                        'ciphertext': row['ciphertext'],
                        'salt': row['salt'],
                        'iv': row['iv'],
                        'tag': row['tag']
                    },
                    'created': row['created'],
                    'last_modified': row['last_modified']
                }
            return None
            
        except sqlite3.Error as e:
            print(f"❌ Database error retrieving password: {e}")
            return None
    
    def get_all_services(self):
        """Get list of all stored services"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('SELECT service FROM passwords ORDER BY service')
            rows = cursor.fetchall()
            
            return [row['service'] for row in rows]
            
        except sqlite3.Error as e:
            print(f"❌ Database error retrieving services: {e}")
            return []
    
    def delete_password(self, service):
        """Delete password for a service"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('DELETE FROM passwords WHERE service = ?', (service,))
            deleted = cursor.rowcount > 0
            
            if deleted:
                self.connection.commit()
                self._update_metadata()
                print(f"✅ Password deleted for service: {service}")
            else:
                print(f"⚠️ No password found for service: {service}")
            
            return deleted
            
        except sqlite3.Error as e:
            print(f"❌ Database error deleting password: {e}")
            return False
    
    def search_passwords(self, search_term):
        """Search passwords by service name"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                SELECT service, username FROM passwords 
                WHERE service LIKE ? OR username LIKE ?
                ORDER BY service
            ''', (f'%{search_term}%', f'%{search_term}%'))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except sqlite3.Error as e:
            print(f"❌ Database search error: {e}")
            return []
    
    def get_database_info(self):
        """Get database metadata and statistics"""
        try:
            cursor = self.connection.cursor()
            
            # Get metadata
            cursor.execute('SELECT * FROM metadata WHERE id = 1')
            metadata = cursor.fetchone()
            
            # Get additional stats
            cursor.execute('SELECT COUNT(*) as total FROM passwords')
            total_passwords = cursor.fetchone()['total']
            
            cursor.execute('SELECT MAX(last_modified) as last_backup FROM passwords')
            last_backup = cursor.fetchone()['last_backup']
            
            return {
                'total_passwords': total_passwords,
                'version': metadata['version'] if metadata else '2.0',
                'encryption': metadata['encryption'] if metadata else 'AES-256-GCM',
                'created': metadata['created'] if metadata else None,
                'last_modified': metadata['last_modified'] if metadata else None,
                'last_backup': last_backup,
                'database_file': self.db_file
            }
            
        except sqlite3.Error as e:
            print(f"❌ Database info error: {e}")
            return {
                'total_passwords': 0,
                'version': '2.0',
                'encryption': 'AES-256-GCM',
                'database_file': self.db_file
            }
    
    def export_to_json(self, export_file="passwords_export.json"):
        """Export database to JSON file (for backup/migration)"""
        try:
            cursor = self.connection.cursor()
            
            # Get all passwords
            cursor.execute('''
                SELECT service, username, ciphertext, salt, iv, tag, created, last_modified
                FROM passwords ORDER BY service
            ''')
            passwords = cursor.fetchall()
            
            # Get metadata
            cursor.execute('SELECT * FROM metadata WHERE id = 1')
            metadata = cursor.fetchone()
            
            export_data = {
                'passwords': {},
                'metadata': dict(metadata) if metadata else {
                    'version': '2.0',
                    'encryption': 'AES-256-GCM',
                    'created': datetime.now().isoformat(),
                    'total_passwords': len(passwords)
                }
            }
            
            # Convert passwords to dictionary format
            for row in passwords:
                export_data['passwords'][row['service']] = {
                    'username': row['username'],
                    'encrypted_data': {
                        'ciphertext': row['ciphertext'],
                        'salt': row['salt'],
                        'iv': row['iv'],
                        'tag': row['tag']
                    },
                    'created': row['created'],
                    'last_modified': row['last_modified']
                }
            
            import json
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False, default=str)
            
            print(f"✅ Database exported to: {export_file}")
            return True
            
        except Exception as e:
            print(f"❌ Export error: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __del__(self):
        """Destructor to ensure connection is closed"""
        self.close()

class SecurePasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager Pro")
        self.root.geometry("900x700")
        
        # Security components
        self.security_manager = SecurityManager()
        self.security_manager.set_auto_lock_callback(self.auto_lock)
        self.breach_monitor = BreachMonitor()
        self.password_analyzer = AdvancedPasswordGenerator()
        self.master_validator = MasterPasswordValidator()
        self.encryption_manager = EncryptionManager()
        self.database = PasswordDatabase()
        
        self.master_password = None
        self.setup_gui()
        
        # Bind activity monitoring
        self.bind_activity_monitoring()
    
    def bind_activity_monitoring(self):
        """Bind events to monitor user activity"""
        events = ['<KeyPress>', '<ButtonPress>', '<Motion>']
        for event in events:
            self.root.bind(event, self.record_activity)
    
    def record_activity(self, event=None):
        """Record user activity for session management"""
        if hasattr(self, 'security_manager'):
            self.security_manager.record_activity()
    
    def auto_lock(self):
        """Auto-lock the application"""
        if self.master_password:
            self.master_password = None
            self.toggle_interface(False)
            messagebox.showwarning("Auto-Lock", 
                                "Application locked due to inactivity.\n\n"
                                "Please enter your master password to continue.")
    
    def setup_gui(self):
        """Setup the enhanced GUI interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header with security status
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky=(tk.W, tk.E))
        
        title_label = ttk.Label(header_frame, text="Secure Password Manager Pro", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        self.security_status = ttk.Label(header_frame, text="🔓 Locked", 
                                       font=('Arial', 10), foreground='red')
        self.security_status.grid(row=0, column=1, sticky=tk.E)
        
        # Session info
        self.session_label = ttk.Label(header_frame, text="", font=('Arial', 9))
        self.session_label.grid(row=1, column=1, sticky=tk.E)
        
        # Master password frame
        password_frame = ttk.LabelFrame(main_frame, text="Master Password Security", padding="10")
        password_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(password_frame, text="Master Password:").grid(row=0, column=0, sticky=tk.W)
        self.master_pw_entry = ttk.Entry(password_frame, show="*", width=30)
        self.master_pw_entry.grid(row=0, column=1, padx=(10, 5))
        self.master_pw_entry.bind('<KeyRelease>', self.validate_master_password_strength)
        
        self.master_strength_label = ttk.Label(password_frame, text="", font=('Arial', 9))
        self.master_strength_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Button(password_frame, text="Unlock Vault", 
                  command=self.verify_master_password).grid(row=0, column=2, padx=5)
        
        ttk.Button(password_frame, text="Lock Vault", 
                  command=self.lock_vault).grid(row=0, column=3, padx=5)
        
        # Password entry frame
        self.entry_frame = ttk.LabelFrame(main_frame, text="Password Management", padding="10")
        self.entry_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(self.entry_frame, text="Service:").grid(row=0, column=0, sticky=tk.W)
        self.service_entry = ttk.Entry(self.entry_frame, width=30)
        self.service_entry.grid(row=0, column=1, padx=(10, 5), pady=5)
        
        ttk.Label(self.entry_frame, text="Username:").grid(row=1, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(self.entry_frame, width=30)
        self.username_entry.grid(row=1, column=1, padx=(10, 5), pady=5)
        
        ttk.Label(self.entry_frame, text="Password:").grid(row=2, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(self.entry_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=(10, 5), pady=5)
        self.password_entry.bind('<KeyRelease>', self.analyze_password_strength)
        
        # Password strength display
        self.strength_frame = ttk.Frame(self.entry_frame)
        self.strength_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        self.strength_label = ttk.Label(self.strength_frame, text="", font=('Arial', 9))
        self.strength_label.grid(row=0, column=0, sticky=tk.W)
        
        # Password controls
        gen_frame = ttk.Frame(self.entry_frame)
        gen_frame.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(gen_frame, text="Generate Secure Password", 
                  command=self.generate_password_dialog).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(gen_frame, text="Show/Hide", 
                  command=self.toggle_password_visibility).grid(row=0, column=1, padx=5)
        ttk.Button(gen_frame, text="Check Breaches", 
                  command=self.check_password_breaches).grid(row=0, column=2, padx=5)
        
        ttk.Button(self.entry_frame, text="🔒 Store Password Securely", 
                  command=self.store_password).grid(row=5, column=1, sticky=tk.W, pady=10)
        
        # Password list frame
        list_frame = ttk.LabelFrame(main_frame, text="Stored Passwords", padding="10")
        list_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Treeview
        columns = ('Service', 'Username')
        self.password_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        self.password_tree.heading('Service', text='Service')
        self.password_tree.heading('Username', text='Username')
        self.password_tree.column('Service', width=300)
        self.password_tree.column('Username', width=300)
        self.password_tree.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        scrollbar.grid(row=0, column=3, sticky=(tk.N, tk.S))
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        # Operations buttons
        button_frame = ttk.Frame(list_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        ttk.Button(button_frame, text="🔍 Retrieve Password", 
                  command=self.retrieve_password).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="📊 Analyze Strength", 
                  command=self.analyze_stored_password).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="🌐 Check Breaches", 
                  command=self.check_stored_breaches).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="🗑️ Delete Password", 
                  command=self.delete_password).grid(row=0, column=3, padx=5)
        ttk.Button(button_frame, text="🔄 Refresh", 
                  command=self.refresh_password_list).grid(row=0, column=4, padx=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        header_frame.columnconfigure(1, weight=1)
        
        # Initially locked
        self.toggle_interface(False)
        self.update_session_display()
    
    def update_session_display(self):
        """Update session information display"""
        if self.master_password and hasattr(self, 'security_manager'):
            session_time = self.security_manager.get_session_duration()
            inactivity_time = self.security_manager.get_inactivity_time()
            
            session_text = f"Session: {session_time}s | Inactive: {inactivity_time}s"
            self.session_label.config(text=session_text)
        
        # Update every second
        self.root.after(1000, self.update_session_display)
    
    def validate_master_password_strength(self, event=None):
        """Validate master password strength in real-time"""
        password = self.master_pw_entry.get()
        if len(password) > 0:
            result = self.master_validator.validate_master_password(password)
            
            if result['valid']:
                self.master_strength_label.config(
                    text=f"Strength: {result['strength']} ({result['score']}/5)",
                    foreground='green'
                )
            else:
                self.master_strength_label.config(
                    text=f"Strength: {result['strength']} - {', '.join(result['issues'])}",
                    foreground='red'
                )
        else:
            self.master_strength_label.config(text="")
    
    def analyze_password_strength(self, event=None):
        """Analyze password strength in real-time"""
        password = self.password_entry.get()
        if len(password) > 0:
            analysis = self.password_analyzer.check_password_strength(password)
            self.strength_label.config(
                text=f"Strength: {analysis['level']} ({analysis['score']}/10) - {analysis['requirements_met']} requirements met",
                foreground=analysis['color']
            )
        else:
            self.strength_label.config(text="")
    
    def check_password_breaches(self):
        """Check current password for breaches"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to check")
            return
        
        result = self.breach_monitor.check_password_breach(password)
        
        if result['breached']:
            messagebox.showwarning(
                "Password Breach Alert!",
                f"{result['message']}\n\n{result['recommendation']}\n\nSeverity: {result['severity'].upper()}"
            )
        else:
            messagebox.showinfo(
                "No Breaches Found",
                f"{result['message']}\n\n{result['recommendation']}"
            )
    
    def generate_password_dialog(self):
        """Enhanced password generator dialog with real-time strength analysis"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Secure Password Generator")
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Password length
        ttk.Label(dialog, text="Password Length:", font=('Arial', 10)).grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        length_var = tk.IntVar(value=16)
        length_scale = ttk.Scale(dialog, from_=8, to=32, variable=length_var, orient=tk.HORIZONTAL, length=200)
        length_scale.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        length_value = ttk.Label(dialog, textvariable=length_var, font=('Arial', 10, 'bold'))
        length_value.grid(row=0, column=2, padx=5, pady=10)
        
        # Character types
        ttk.Label(dialog, text="Character Types:", font=('Arial', 10, 'bold')).grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=10, pady=5)
        
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        numbers_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(dialog, text="Uppercase Letters (A-Z)", variable=uppercase_var, 
                       command=lambda: self.validate_generator_settings(uppercase_var, lowercase_var, numbers_var, symbols_var)).grid(row=2, column=0, columnspan=3, sticky=tk.W, padx=20)
        ttk.Checkbutton(dialog, text="Lowercase Letters (a-z)", variable=lowercase_var,
                       command=lambda: self.validate_generator_settings(uppercase_var, lowercase_var, numbers_var, symbols_var)).grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=20)
        ttk.Checkbutton(dialog, text="Numbers (0-9)", variable=numbers_var,
                       command=lambda: self.validate_generator_settings(uppercase_var, lowercase_var, numbers_var, symbols_var)).grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=20)
        ttk.Checkbutton(dialog, text="Special Characters (!@#$%^&* etc.)", variable=symbols_var,
                       command=lambda: self.validate_generator_settings(uppercase_var, lowercase_var, numbers_var, symbols_var)).grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=20)
        
        # Generated password display
        ttk.Label(dialog, text="Generated Password:", font=('Arial', 10, 'bold')).grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, textvariable=password_var, width=35, font=('Courier', 12), state='readonly')
        password_entry.grid(row=6, column=1, columnspan=2, padx=10, pady=10, sticky=tk.W)
        
        # Strength indicator
        strength_label = ttk.Label(dialog, text="Strength: Not generated", font=('Arial', 9))
        strength_label.grid(row=7, column=0, columnspan=3, padx=10, pady=5, sticky=tk.W)
        
        # Requirements met
        requirements_label = ttk.Label(dialog, text="Requirements: -", font=('Arial', 9))
        requirements_label.grid(row=8, column=0, columnspan=3, padx=10, pady=2, sticky=tk.W)
        
        def generate_password():
            """Generate password and update display"""
            try:
                # Validate at least one character type is selected
                if not any([uppercase_var.get(), lowercase_var.get(), numbers_var.get(), symbols_var.get()]):
                    messagebox.showerror("Error", "Please select at least one character type")
                    return
                
                password = self.password_analyzer.generate_password(
                    length=length_var.get(),
                    use_uppercase=uppercase_var.get(),
                    use_lowercase=lowercase_var.get(),
                    use_numbers=numbers_var.get(),
                    use_symbols=symbols_var.get()
                )
                password_var.set(password)
                
                # Analyze strength
                analysis = self.password_analyzer.check_password_strength(password)
                strength_label.config(
                    text=f"Strength: {analysis['level']} (Score: {analysis['score']}/10)",
                    foreground=analysis['color']
                )
                requirements_label.config(
                    text=f"Requirements: {analysis['requirements_met']} met"
                )
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
        
        def validate_and_generate():
            """Validate settings and generate password"""
            if not any([uppercase_var.get(), lowercase_var.get(), numbers_var.get(), symbols_var.get()]):
                messagebox.showerror("Error", "Please select at least one character type")
                return
            generate_password()
        
        def use_password():
            """Use the generated password in the main form"""
            if password_var.get():
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, password_var.get())
                
                # Trigger strength analysis
                self.analyze_password_strength()
                
                dialog.destroy()
        
        def copy_password():
            """Copy password to clipboard"""
            if password_var.get():
                dialog.clipboard_clear()
                dialog.clipboard_append(password_var.get())
                dialog.after(30000, lambda: dialog.clipboard_clear())  # Clear after 30 seconds
                messagebox.showinfo("Copied", "Password copied to clipboard!\n\nAuto-clearing in 30 seconds for security.")
        
        # Buttons frame
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=9, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Generate Password", 
                  command=validate_and_generate).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Use This Password", 
                  command=use_password).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=copy_password).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="Close", 
                  command=dialog.destroy).grid(row=0, column=3, padx=5)
        
        # Generate initial password
        generate_password()
    
    def validate_generator_settings(self, uppercase_var, lowercase_var, numbers_var, symbols_var):
        """Validate that at least one character type is selected"""
        if not any([uppercase_var.get(), lowercase_var.get(), numbers_var.get(), symbols_var.get()]):
            # This will be handled when generating, but we can show a warning
            pass
    
    def verify_master_password(self):
        """Verify master password with enhanced security"""
        master_pw = self.master_pw_entry.get()
        if not master_pw:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        # Validate master password strength
        validation = self.master_validator.validate_master_password(master_pw)
        if not validation['valid']:
            if not messagebox.askyesno(
                "Weak Master Password",
                f"Your master password is {validation['strength']}.\n\n"
                f"Issues: {', '.join(validation['issues'])}\n\n"
                "Do you want to continue anyway?"
            ):
                return
        
        self.master_password = master_pw
        self.security_manager.start_session()
        self.toggle_interface(True)
        
        messagebox.showinfo(
            "Vault Unlocked",
            f"Secure password manager unlocked!\n\n"
            f"Security Features Active:\n"
            f"• AES-256-GCM Encryption\n"
            f"• Auto-lock after 5 minutes\n"
            f"• Session timeout monitoring\n"
            f"• Breach monitoring\n"
            f"• Advanced password analysis"
        )
        
        self.master_pw_entry.delete(0, tk.END)
        self.master_pw_entry.config(state='disabled')
    
    def lock_vault(self):
        """Manually lock the vault"""
        self.master_password = None
        self.toggle_interface(False)
        self.master_pw_entry.config(state='normal')
        messagebox.showinfo("Vault Locked", "Password vault has been locked.")
    
    def toggle_interface(self, enabled: bool):
        """Enable or disable the interface"""
        state = 'normal' if enabled else 'disabled'
        for widget in self.entry_frame.winfo_children():
            try:
                widget.configure(state=state)
            except:
                pass
        
        if enabled:
            self.refresh_password_list()
            self.security_status.config(text="🔒 Unlocked - Secure", foreground='green')
        else:
            self.security_status.config(text="🔓 Locked", foreground='red')
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        current_show = self.password_entry.cget('show')
        self.password_entry.config(show='' if current_show == '*' else '*')
    
    def store_password(self):
        """Store password with enhanced security"""
        if not self.master_password:
            messagebox.showerror("Error", "Vault is locked")
            return
        
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not service or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        # Analyze password strength
        analysis = self.password_analyzer.check_password_strength(password)
        if not analysis['all_requirements_met']:
            if not messagebox.askyesno(
                "Weak Password Detected",
                f"Password strength: {analysis['level']}\n\n"
                f"Recommendations:\n" + "\n".join(analysis['feedback'][:3]) + "\n\n"
                "Do you want to store this password anyway?"
            ):
                return
        
        try:
            encrypted_data = self.encryption_manager.encrypt_password(password, self.master_password)
            self.database.store_password(service, username, encrypted_data)
            
            messagebox.showinfo(
                "Success",
                f"Password for {service} stored securely!\n\n"
                f"Security Level: {analysis['level']}\n"
                f"Requirements Met: {analysis['requirements_met']}"
            )
            
            self.service_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.refresh_password_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to store password: {str(e)}")
    
    def refresh_password_list(self):
        """Refresh password list"""
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        services = self.database.get_all_services()
        for service in services:
            password_data = self.database.get_password(service)
            if password_data:
                self.password_tree.insert('', tk.END, values=(service, password_data['username']))
    
    def retrieve_password(self):
        """Retrieve password with security enhancements"""
        if not self.master_password:
            messagebox.showerror("Error", "Vault is locked")
            return
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a service")
            return
        
        item = selection[0]
        service = self.password_tree.item(item, 'values')[0]
        
        try:
            stored_data = self.database.get_password(service)
            if stored_data:
                decrypted_password = self.encryption_manager.decrypt_password(
                    stored_data['encrypted_data'], self.master_password
                )
                
                # Show secure dialog
                self.show_secure_password_dialog(service, stored_data['username'], decrypted_password)
            else:
                messagebox.showerror("Error", "Password not found")
                
        except ValueError as e:
            messagebox.showerror("Security Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")
    
    def show_secure_password_dialog(self, service: str, username: str, password: str):
        """Show password in a secure dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"🔐 {service} - Secure View")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Security analysis
        analysis = self.password_analyzer.check_password_strength(password)
        breach_check = self.breach_monitor.check_password_breach(password)
        
        ttk.Label(dialog, text=f"Service: {service}", font=('Arial', 12, 'bold')).pack(pady=10)
        ttk.Label(dialog, text=f"Username: {username}", font=('Arial', 10)).pack(pady=5)
        
        # Password strength
        strength_frame = ttk.Frame(dialog)
        strength_frame.pack(pady=5)
        ttk.Label(strength_frame, text=f"Strength: ", font=('Arial', 10)).pack(side=tk.LEFT)
        ttk.Label(strength_frame, text=analysis['level'], 
                 foreground=analysis['color'], font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        # Breach status
        breach_frame = ttk.Frame(dialog)
        breach_frame.pack(pady=5)
        if breach_check['breached']:
            ttk.Label(breach_frame, text="🚨 BREACHED", 
                     foreground='red', font=('Arial', 10, 'bold')).pack()
            ttk.Label(breach_frame, text=breach_check['message'], 
                     font=('Arial', 9)).pack()
        else:
            ttk.Label(breach_frame, text="✅ No breaches found", 
                     foreground='green', font=('Arial', 10)).pack()
        
        # Password display
        password_frame = ttk.Frame(dialog)
        password_frame.pack(pady=15)
        
        ttk.Label(password_frame, text="Password:", font=('Arial', 10)).grid(row=0, column=0, padx=5)
        password_entry = ttk.Entry(password_frame, show="*", width=25, font=('Courier', 10))
        password_entry.insert(0, password)
        password_entry.grid(row=0, column=1, padx=5)
        
        def toggle_show():
            current_show = password_entry.cget('show')
            password_entry.config(show='' if current_show == '*' else '*')
        
        ttk.Button(password_frame, text="👁️ Show/Hide", command=toggle_show).grid(row=0, column=2, padx=5)
        
        def secure_copy():
            dialog.clipboard_clear()
            dialog.clipboard_append(password)
            dialog.after(30000, lambda: dialog.clipboard_clear())  # Clear after 30 seconds
            messagebox.showinfo("Copied", "Password copied to clipboard!\n\nAuto-clearing in 30 seconds.")
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="📋 Copy Securely", command=secure_copy).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).grid(row=0, column=1, padx=5)
    
    def analyze_stored_password(self):
        """Analyze strength of stored password"""
        if not self.master_password:
            messagebox.showerror("Error", "Vault is locked")
            return
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a service")
            return
        
        item = selection[0]
        service = self.password_tree.item(item, 'values')[0]
        
        try:
            stored_data = self.database.get_password(service)
            if stored_data:
                password = self.encryption_manager.decrypt_password(
                    stored_data['encrypted_data'], self.master_password
                )
                
                analysis = self.password_analyzer.check_password_strength(password)
                
                # Show analysis results
                dialog = tk.Toplevel(self.root)
                dialog.title(f"Password Analysis - {service}")
                dialog.geometry("400x300")
                
                ttk.Label(dialog, text=f"Analysis for: {service}", 
                         font=('Arial', 12, 'bold')).pack(pady=10)
                ttk.Label(dialog, text=f"Strength: {analysis['level']} ({analysis['score']}/10)",
                         foreground=analysis['color'], font=('Arial', 11)).pack(pady=5)
                ttk.Label(dialog, text=f"Requirements: {analysis['requirements_met']} met").pack(pady=5)
                
                # Feedback list
                feedback_frame = ttk.Frame(dialog)
                feedback_frame.pack(pady=10, fill=tk.BOTH, expand=True)
                
                scrollbar = ttk.Scrollbar(feedback_frame)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                
                feedback_text = tk.Text(feedback_frame, height=8, yscrollcommand=scrollbar.set)
                feedback_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar.config(command=feedback_text.yview)
                
                for item in analysis['feedback']:
                    feedback_text.insert(tk.END, f"• {item}\n")
                feedback_text.config(state=tk.DISABLED)
                
            else:
                messagebox.showerror("Error", "Password not found")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze password: {str(e)}")
    
    def check_stored_breaches(self):
        """Check stored password for breaches"""
        if not self.master_password:
            messagebox.showerror("Error", "Vault is locked")
            return
        
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a service")
            return
        
        item = selection[0]
        service = self.password_tree.item(item, 'values')[0]
        
        try:
            stored_data = self.database.get_password(service)
            if stored_data:
                password = self.encryption_manager.decrypt_password(
                    stored_data['encrypted_data'], self.master_password
                )
                
                result = self.breach_monitor.check_password_breach(password)
                
                if result['breached']:
                    messagebox.showwarning(
                        "Password Breach Alert!",
                        f"Service: {service}\n\n"
                        f"{result['message']}\n\n"
                        f"{result['recommendation']}\n\n"
                        f"Severity: {result['severity'].upper()}"
                    )
                else:
                    messagebox.showinfo(
                        "No Breaches Found",
                        f"Service: {service}\n\n"
                        f"{result['message']}\n\n"
                        f"{result['recommendation']}"
                    )
            else:
                messagebox.showerror("Error", "Password not found")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check breaches: {str(e)}")
    
    def delete_password(self):
        """Delete selected password"""
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showerror("Error", "Please select a service to delete")
            return
        
        item = selection[0]
        service = self.password_tree.item(item, 'values')[0]
        
        if messagebox.askyesno("Confirm Deletion", 
                             f"Permanently delete password for:\n\n{service}?\n\nThis cannot be undone!"):
            if self.database.delete_password(service):
                messagebox.showinfo("Deleted", f"Password for {service} has been deleted.")
                self.refresh_password_list()
            else:
                messagebox.showerror("Error", "Failed to delete password")
def main():
    root = tk.Tk()
    app = SecurePasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()