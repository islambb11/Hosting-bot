#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
💀 Telegram Bot Hosting System v3.0 - Professional Edition
🔥 Enhanced & Legendary Version - By وحش الإنترنت الأسود 👿
📅 Updated: 2024
🛡️ Security Level: Maximum
⚡ Performance: Optimized
🌟 Features: Legendary
"""

import os
import sys
import json
import time
import psutil
import sqlite3
import logging
import asyncio
import hashlib
import secrets
import subprocess
import threading
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import telebot
from telebot import types
import requests
from cryptography.fernet import Fernet
import schedule
import validators
from filelock import FileLock

# ═══════════════════════════════════════════════════════════════
# 🔧 CONFIGURATION & CONSTANTS
# ═══════════════════════════════════════════════════════════════

# أمان - إعدادات حساسة
TOKEN = "7661560318:AAEJoFqAyM8e8gxj4DUb77sbnGXfiQcxQeo"
OWNER_ID = 6991944640
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# إعدادات النظام
MAX_BOTS_PER_USER = 10
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
SUPPORTED_EXTENSIONS = ['.py', '.php', '.js', '.rb']
BACKUP_INTERVAL = 3600  # كل ساعة
LOG_RETENTION_DAYS = 30

# مسارات النظام
BASE_DIR = Path(__file__).parent
USER_BOTS_DIR = BASE_DIR / "user_bots"
BACKUPS_DIR = BASE_DIR / "backups"
LOGS_DIR = BASE_DIR / "logs"
DATABASE_PATH = BASE_DIR / "bot_hosting.db"

# إنشاء المجلدات المطلوبة
for directory in [USER_BOTS_DIR, BACKUPS_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# 🔐 SECURITY & ENCRYPTION
# ═══════════════════════════════════════════════════════════════

class SecurityManager:
    """مدير الأمان المتقدم"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = {}
        self.suspicious_activities = []
        
    def encrypt_data(self, data: str) -> str:
        """تشفير البيانات الحساسة"""
        return cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """فك تشفير البيانات"""
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def generate_secure_token(self) -> str:
        """توليد رمز أمان عشوائي"""
        return secrets.token_urlsafe(32)
    
    def hash_password(self, password: str) -> str:
        """تشفير كلمة المرور"""
        salt = secrets.token_hex(16)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() + ':' + salt
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """التحقق من كلمة المرور"""
        password_hash, salt = hashed.split(':')
        return password_hash == hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    
    def rate_limit_check(self, user_id: int, limit: int = 10, window: int = 60) -> bool:
        """فحص معدل الطلبات"""
        now = time.time()
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []
        
        # تنظيف الطلبات القديمة
        self.rate_limits[user_id] = [req_time for req_time in self.rate_limits[user_id] if now - req_time < window]
        
        if len(self.rate_limits[user_id]) >= limit:
            return False
        
        self.rate_limits[user_id].append(now)
        return True

# ═══════════════════════════════════════════════════════════════
# 📊 DATABASE MANAGEMENT
# ═══════════════════════════════════════════════════════════════

@dataclass
class BotInfo:
    """معلومات البوت"""
    id: str
    user_id: int
    filename: str
    path: str
    token: str
    language: str
    status: str
    created_at: datetime
    last_activity: datetime
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    uptime: int = 0

class DatabaseManager:
    """مدير قاعدة البيانات المتقدم"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """إنشاء جداول قاعدة البيانات"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    telegram_id INTEGER UNIQUE NOT NULL,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    is_premium BOOLEAN DEFAULT FALSE,
                    join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_bots INTEGER DEFAULT 0,
                    max_bots INTEGER DEFAULT 10,
                    is_banned BOOLEAN DEFAULT FALSE
                );
                
                CREATE TABLE IF NOT EXISTS bots (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    token TEXT NOT NULL,
                    language TEXT NOT NULL,
                    status TEXT DEFAULT 'stopped',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cpu_usage REAL DEFAULT 0.0,
                    memory_usage REAL DEFAULT 0.0,
                    uptime INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (telegram_id)
                );
                
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    bot_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT
                );
                
                CREATE TABLE IF NOT EXISTS system_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_users INTEGER,
                    active_bots INTEGER,
                    cpu_usage REAL,
                    memory_usage REAL,
                    disk_usage REAL,
                    network_in REAL,
                    network_out REAL
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id);
                CREATE INDEX IF NOT EXISTS idx_bots_user_id ON bots(user_id);
                CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
            """)
    
    def add_user(self, telegram_id: int, username: str = None, first_name: str = None, last_name: str = None):
        """إضافة مستخدم جديد"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO users (telegram_id, username, first_name, last_name)
                VALUES (?, ?, ?, ?)
            """, (telegram_id, username, first_name, last_name))
    
    def add_bot(self, bot_info: BotInfo):
        """إضافة بوت جديد"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO bots (id, user_id, filename, file_path, token, language, status, created_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (bot_info.id, bot_info.user_id, bot_info.filename, bot_info.path, 
                 bot_info.token, bot_info.language, bot_info.status, 
                 bot_info.created_at, bot_info.last_activity))
    
    def get_user_bots(self, user_id: int) -> List[BotInfo]:
        """استرجاع بوتات المستخدم"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM bots WHERE user_id = ?", (user_id,))
            return [BotInfo(**dict(row)) for row in cursor.fetchall()]
    
    def update_bot_status(self, bot_id: str, status: str):
        """تحديث حالة البوت"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE bots SET status = ?, last_activity = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (status, bot_id))
    
    def log_action(self, user_id: int, bot_id: str, action: str, details: str = None):
        """تسجيل العمليات"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO logs (user_id, bot_id, action, details)
                VALUES (?, ?, ?, ?)
            """, (user_id, bot_id, action, details))

# ═══════════════════════════════════════════════════════════════
# 📈 PERFORMANCE MONITORING
# ═══════════════════════════════════════════════════════════════

class PerformanceMonitor:
    """مراقب الأداء المتقدم"""
    
    def __init__(self):
        self.process_monitors = {}
        self.system_stats = {}
        
    def get_system_stats(self) -> Dict:
        """إحصائيات النظام"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters(),
            'boot_time': psutil.boot_time(),
            'process_count': len(psutil.pids())
        }
    
    def monitor_bot_process(self, bot_id: str, pid: int):
        """مراقبة عملية البوت"""
        try:
            process = psutil.Process(pid)
            self.process_monitors[bot_id] = {
                'process': process,
                'start_time': time.time(),
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'status': 'running'
            }
        except psutil.NoSuchProcess:
            pass
    
    def get_bot_stats(self, bot_id: str) -> Dict:
        """إحصائيات البوت"""
        if bot_id not in self.process_monitors:
            return {'status': 'not_found'}
        
        try:
            process = self.process_monitors[bot_id]['process']
            return {
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'memory_info': process.memory_info(),
                'status': process.status(),
                'create_time': process.create_time(),
                'uptime': time.time() - self.process_monitors[bot_id]['start_time']
            }
        except psutil.NoSuchProcess:
            return {'status': 'terminated'}

# ═══════════════════════════════════════════════════════════════
# 🔄 BACKUP SYSTEM
# ═══════════════════════════════════════════════════════════════

class BackupManager:
    """مدير النسخ الاحتياطي"""
    
    def __init__(self, backup_dir: Path):
        self.backup_dir = backup_dir
        
    def create_backup(self) -> str:
        """إنشاء نسخة احتياطية"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}"
        backup_path = self.backup_dir / backup_name
        
        # نسخ قاعدة البيانات
        subprocess.run([
            'cp', str(DATABASE_PATH), 
            str(backup_path / "database.db")
        ])
        
        # نسخ ملفات البوتات
        subprocess.run([
            'cp', '-r', str(USER_BOTS_DIR), 
            str(backup_path / "user_bots")
        ])
        
        # ضغط النسخة الاحتياطية
        subprocess.run([
            'tar', '-czf', f"{backup_path}.tar.gz", 
            '-C', str(self.backup_dir), backup_name
        ])
        
        # حذف المجلد المؤقت
        subprocess.run(['rm', '-rf', str(backup_path)])
        
        return f"{backup_name}.tar.gz"
    
    def cleanup_old_backups(self, keep_days: int = 7):
        """تنظيف النسخ الاحتياطية القديمة"""
        cutoff_date = datetime.now() - timedelta(days=keep_days)
        
        for backup_file in self.backup_dir.glob("backup_*.tar.gz"):
            if backup_file.stat().st_mtime < cutoff_date.timestamp():
                backup_file.unlink()

# ═══════════════════════════════════════════════════════════════
# 🤖 ENHANCED BOT MANAGER
# ═══════════════════════════════════════════════════════════════

class EnhancedBotManager:
    """مدير البوتات المحسن"""
    
    def __init__(self):
        self.running_processes = {}
        self.file_locks = {}
        
    def extract_token_from_file(self, file_path: Path) -> Optional[str]:
        """استخراج التوكن من الملف مع دعم أشكال متعددة"""
        patterns = [
            r'[\d]{8,10}:[\w-]{30,}',  # التوكن العادي
            r'bot_token\s*=\s*["\']([^"\']+)["\']',  # bot_token = "..."
            r'TOKEN\s*=\s*["\']([^"\']+)["\']',  # TOKEN = "..."
            r'token\s*:\s*["\']([^"\']+)["\']',  # token: "..."
        ]
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    return matches[0] if isinstance(matches[0], str) else matches[0][0]
                    
        except Exception as e:
            logger.error(f"خطأ في قراءة الملف {file_path}: {e}")
            
        return None
    
    def validate_bot_file(self, file_path: Path) -> Tuple[bool, str]:
        """التحقق من صحة ملف البوت"""
        try:
            # فحص الامتداد
            if file_path.suffix not in SUPPORTED_EXTENSIONS:
                return False, f"امتداد غير مدعوم: {file_path.suffix}"
            
            # فحص حجم الملف
            if file_path.stat().st_size > MAX_FILE_SIZE:
                return False, f"حجم الملف كبير جداً: {file_path.stat().st_size} bytes"
            
            # فحص وجود التوكن
            token = self.extract_token_from_file(file_path)
            if not token:
                return False, "لم يتم العثور على توكن صحيح في الملف"
            
            # التحقق من صحة التوكن
            if not self.validate_token(token):
                return False, "التوكن غير صحيح أو منتهي الصلاحية"
            
            return True, "الملف صحيح"
            
        except Exception as e:
            return False, f"خطأ في فحص الملف: {str(e)}"
    
    def validate_token(self, token: str) -> bool:
        """التحقق من صحة التوكن"""
        try:
            # فحص تنسيق التوكن
            if not re.match(r'^\d{8,10}:[A-Za-z0-9_-]{35}$', token):
                return False
            
            # فحص التوكن مع Telegram API
            response = requests.get(
                f"https://api.telegram.org/bot{token}/getMe",
                timeout=5
            )
            return response.status_code == 200
            
        except:
            return False
    
    def run_bot(self, file_path: Path, language: str) -> Optional[int]:
        """تشغيل البوت وإرجاع PID"""
        try:
            # اختيار المفسر المناسب
            interpreters = {
                '.py': 'python3',
                '.php': 'php',
                '.js': 'node',
                '.rb': 'ruby'
            }
            
            interpreter = interpreters.get(file_path.suffix, 'python3')
            
            # تشغيل البوت
            process = subprocess.Popen(
                [interpreter, str(file_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=file_path.parent
            )
            
            self.running_processes[str(file_path)] = process
            return process.pid
            
        except Exception as e:
            logger.error(f"خطأ في تشغيل البوت {file_path}: {e}")
            return None
    
    def stop_bot(self, file_path: Path) -> bool:
        """إيقاف البوت"""
        try:
            file_str = str(file_path)
            
            if file_str in self.running_processes:
                process = self.running_processes[file_str]
                process.terminate()
                
                # انتظار الإغلاق الطبيعي
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                
                del self.running_processes[file_str]
                return True
            else:
                # محاولة إيقاف بواسطة اسم الملف
                subprocess.run([
                    'pkill', '-f', file_path.name
                ], stderr=subprocess.DEVNULL)
                return True
                
        except Exception as e:
            logger.error(f"خطأ في إيقاف البوت {file_path}: {e}")
            return False

# ═══════════════════════════════════════════════════════════════
# 📝 LOGGING SYSTEM
# ═══════════════════════════════════════════════════════════════

def setup_logging():
    """إعداد نظام السجلات المتقدم"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # إعداد السجل الرئيسي
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(LOGS_DIR / 'bot_hosting.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # سجل الأمان
    security_logger = logging.getLogger('security')
    security_handler = logging.FileHandler(LOGS_DIR / 'security.log', encoding='utf-8')
    security_handler.setFormatter(logging.Formatter(log_format))
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    # سجل الأداء
    performance_logger = logging.getLogger('performance')
    performance_handler = logging.FileHandler(LOGS_DIR / 'performance.log', encoding='utf-8')
    performance_handler.setFormatter(logging.Formatter(log_format))
    performance_logger.addHandler(performance_handler)
    performance_logger.setLevel(logging.INFO)
    
    return logging.getLogger(__name__)

logger = setup_logging()

# ═══════════════════════════════════════════════════════════════
# 🚀 MAIN BOT CLASS
# ═══════════════════════════════════════════════════════════════

class ProfessionalTelegramBotHost:
    """نظام استضافة البوتات الاحترافي"""
    
    def __init__(self):
        self.bot = telebot.TeleBot(TOKEN)
        self.security = SecurityManager()
        self.database = DatabaseManager(DATABASE_PATH)
        self.performance = PerformanceMonitor()
        self.backup_manager = BackupManager(BACKUPS_DIR)
        self.bot_manager = EnhancedBotManager()
        
        self.user_sessions = {}
        self.admin_commands = {}
        
        self.setup_handlers()
        self.start_background_tasks()
    
    def setup_handlers(self):
        """إعداد معالجات الرسائل"""
        
        @self.bot.message_handler(commands=['start'])
        def start_command(message):
            self.handle_start(message)
        
        @self.bot.message_handler(commands=['help'])
        def help_command(message):
            self.handle_help(message)
        
        @self.bot.message_handler(commands=['stats'])
        def stats_command(message):
            self.handle_stats(message)
        
        @self.bot.message_handler(commands=['admin'])
        def admin_command(message):
            self.handle_admin(message)
        
        @self.bot.message_handler(content_types=['document'])
        def handle_document(message):
            self.handle_file_upload(message)
        
        @self.bot.callback_query_handler(func=lambda call: True)
        def callback_query(call):
            self.handle_callback(call)
    
    def handle_start(self, message):
        """معالج أمر البداية المحسن"""
        user = message.from_user
        
        # إضافة المستخدم إلى قاعدة البيانات
        self.database.add_user(
            user.id, user.username, 
            user.first_name, user.last_name
        )
        
        # فحص معدل الطلبات
        if not self.security.rate_limit_check(user.id):
            self.bot.send_message(
                message.chat.id, 
                "⚠️ تم تجاوز معدل الطلبات المسموح. يرجى المحاولة لاحقاً."
            )
            return
        
        # إنشاء القائمة الرئيسية
        markup = types.InlineKeyboardMarkup(row_width=2)
        
        buttons = [
            types.InlineKeyboardButton("🤖 بوتاتي", callback_data="my_bots"),
            types.InlineKeyboardButton("📊 الإحصائيات", callback_data="user_stats"),
            types.InlineKeyboardButton("⚙️ الإعدادات", callback_data="settings"),
            types.InlineKeyboardButton("❓ المساعدة", callback_data="help"),
        ]
        
        if user.id == OWNER_ID:
            buttons.extend([
                types.InlineKeyboardButton("👨‍💻 لوحة الإدارة", callback_data="admin_panel"),
                types.InlineKeyboardButton("🔧 إدارة النظام", callback_data="system_admin")
            ])
        
        markup.add(*buttons)
        
        welcome_text = f"""
🌟 مرحباً بك في نظام استضافة البوتات الاحترافي v3.0 🌟

👋 أهلاً {user.first_name}!

🚀 الميزات المتاحة:
• استضافة بوتات Python, PHP, JavaScript, Ruby
• مراقبة الأداء في الوقت الفعلي
• نظام أمان متقدم
• نسخ احتياطية تلقائية
• واجهة إدارة احترافية

💡 للبدء: قم برفع ملف البوت الخاص بك
📋 الحد الأقصى: {MAX_BOTS_PER_USER} بوت لكل مستخدم
📏 حجم الملف الأقصى: {MAX_FILE_SIZE // (1024*1024)} ميجابايت

🔐 نظام آمن 100% | ⚡ أداء فائق | 🛡️ حماية شاملة
        """
        
        self.bot.send_message(
            message.chat.id, welcome_text,
            parse_mode='HTML', reply_markup=markup
        )
        
        # تسجيل العملية
        self.database.log_action(user.id, None, "start_command", "User started the bot")
        logger.info(f"User {user.id} ({user.username}) started the bot")

    def handle_file_upload(self, message):
        """معالج رفع الملفات المحسن"""
        user = message.from_user
        
        # فحص معدل الطلبات
        if not self.security.rate_limit_check(user.id, limit=5, window=300):
            self.bot.send_message(
                message.chat.id,
                "⚠️ تجاوزت معدل رفع الملفات المسموح. يرجى الانتظار 5 دقائق."
            )
            return
        
        # فحص صحة الملف
        file_info = self.bot.get_file(message.document.file_id)
        file_extension = Path(message.document.file_name).suffix.lower()
        
        if file_extension not in SUPPORTED_EXTENSIONS:
            supported = ', '.join(SUPPORTED_EXTENSIONS)
            self.bot.send_message(
                message.chat.id,
                f"❌ امتداد الملف غير مدعوم.\n🔧 الامتدادات المدعومة: {supported}"
            )
            return
        
        if message.document.file_size > MAX_FILE_SIZE:
            self.bot.send_message(
                message.chat.id,
                f"❌ حجم الملف كبير جداً.\n📏 الحد الأقصى: {MAX_FILE_SIZE // (1024*1024)} ميجابايت"
            )
            return
        
        # فحص عدد البوتات
        user_bots = self.database.get_user_bots(user.id)
        if len(user_bots) >= MAX_BOTS_PER_USER:
            self.bot.send_message(
                message.chat.id,
                f"❌ وصلت للحد الأقصى من البوتات ({MAX_BOTS_PER_USER}).\n🗑️ احذف بعض البوتات أولاً."
            )
            return
        
        # رسالة تحميل
        loading_msg = self.bot.send_message(
            message.chat.id,
            "⏰ جاري تحميل وفحص الملف..."
        )
        
        try:
            # تحميل الملف
            downloaded_file = self.bot.download_file(file_info.file_path)
            
            # إنشاء اسم فريد للملف
            timestamp = int(time.time())
            bot_id = f"{user.id}_{timestamp}"
            filename = f"{bot_id}_{message.document.file_name}"
            file_path = USER_BOTS_DIR / filename
            
            # حفظ الملف
            with open(file_path, 'wb') as f:
                f.write(downloaded_file)
            
            # فحص الملف
            is_valid, validation_message = self.bot_manager.validate_bot_file(file_path)
            
            if not is_valid:
                file_path.unlink()  # حذف الملف الخاطئ
                self.bot.edit_message_text(
                    f"❌ خطأ في الملف:\n{validation_message}",
                    message.chat.id, loading_msg.message_id
                )
                return
            
            # استخراج التوكن
            token = self.bot_manager.extract_token_from_file(file_path)
            
            # تشغيل البوت
            pid = self.bot_manager.run_bot(file_path, file_extension[1:])
            
            if not pid:
                file_path.unlink()
                self.bot.edit_message_text(
                    "❌ فشل في تشغيل البوت. يرجى التحقق من الكود.",
                    message.chat.id, loading_msg.message_id
                )
                return
            
            # إضافة البوت لقاعدة البيانات
            bot_info = BotInfo(
                id=bot_id,
                user_id=user.id,
                filename=message.document.file_name,
                path=str(file_path),
                token=self.security.encrypt_data(token),
                language=file_extension[1:],
                status='running',
                created_at=datetime.now(),
                last_activity=datetime.now()
            )
            
            self.database.add_bot(bot_info)
            
            # بدء مراقبة الأداء
            self.performance.monitor_bot_process(bot_id, pid)
            
            # رسالة النجاح
            success_text = f"""
✅ تم تشغيل البوت بنجاح!

🤖 اسم الملف: {message.document.file_name}
🆔 معرف البوت: {bot_id}
💻 اللغة: {file_extension[1:].upper()}
🔐 التوكن: {token[:20]}...
📊 معرف العملية: {pid}
⏰ وقت التشغيل: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🎯 البوت يعمل الآن!
            """
            
            # أزرار الإدارة
            markup = types.InlineKeyboardMarkup()
            markup.row(
                types.InlineKeyboardButton("📊 الإحصائيات", callback_data=f"bot_stats_{bot_id}"),
                types.InlineKeyboardButton("⚙️ الإعدادات", callback_data=f"bot_settings_{bot_id}")
            )
            markup.row(
                types.InlineKeyboardButton("🔄 إعادة تشغيل", callback_data=f"restart_{bot_id}"),
                types.InlineKeyboardButton("⏹️ إيقاف", callback_data=f"stop_{bot_id}")
            )
            
            self.bot.edit_message_text(
                success_text, message.chat.id, loading_msg.message_id,
                parse_mode='HTML', reply_markup=markup
            )
            
            # إشعار المطور
            if user.id != OWNER_ID:
                self.bot.send_message(
                    OWNER_ID,
                    f"🚀 بوت جديد تم تشغيله:\n"
                    f"👤 المستخدم: {user.first_name} (@{user.username})\n"
                    f"🆔 معرف المستخدم: {user.id}\n"
                    f"📁 الملف: {message.document.file_name}\n"
                    f"🤖 معرف البوت: {bot_id}",
                    parse_mode='HTML'
                )
            
            # تسجيل العملية
            self.database.log_action(user.id, bot_id, "bot_uploaded", f"File: {message.document.file_name}")
            logger.info(f"User {user.id} uploaded and started bot {bot_id}")
            
        except Exception as e:
            logger.error(f"Error uploading file for user {user.id}: {e}")
            self.bot.edit_message_text(
                f"❌ خطأ في تحميل الملف:\n{str(e)}",
                message.chat.id, loading_msg.message_id
            )

    def start_background_tasks(self):
        """بدء المهام الخلفية"""
        
        def backup_scheduler():
            """جدولة النسخ الاحتياطية"""
            schedule.every().hour.do(self.create_system_backup)
            schedule.every().day.at("02:00").do(self.cleanup_old_data)
            schedule.every(10).minutes.do(self.update_system_stats)
            
            while True:
                schedule.run_pending()
                time.sleep(60)
        
        # تشغيل الجدولة في خيط منفصل
        threading.Thread(target=backup_scheduler, daemon=True).start()
        
        logger.info("Background tasks started successfully")
    
    def create_system_backup(self):
        """إنشاء نسخة احتياطية للنظام"""
        try:
            backup_name = self.backup_manager.create_backup()
            logger.info(f"System backup created: {backup_name}")
            
            # إشعار المطور
            self.bot.send_message(
                OWNER_ID,
                f"💾 تم إنشاء نسخة احتياطية:\n📁 {backup_name}",
                parse_mode='HTML'
            )
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
    
    def cleanup_old_data(self):
        """تنظيف البيانات القديمة"""
        try:
            # تنظيف النسخ الاحتياطية القديمة
            self.backup_manager.cleanup_old_backups()
            
            # تنظيف السجلات القديمة
            cutoff_date = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
            with sqlite3.connect(DATABASE_PATH) as conn:
                conn.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date,))
            
            logger.info("Old data cleanup completed")
            
        except Exception as e:
            logger.error(f"Data cleanup failed: {e}")
    
    def update_system_stats(self):
        """تحديث إحصائيات النظام"""
        try:
            stats = self.performance.get_system_stats()
            
            # حفظ الإحصائيات في قاعدة البيانات
            with sqlite3.connect(DATABASE_PATH) as conn:
                conn.execute("""
                    INSERT INTO system_stats 
                    (total_users, active_bots, cpu_usage, memory_usage, disk_usage) 
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    len(self.database.get_all_users()),
                    len(self.bot_manager.running_processes),
                    stats['cpu_percent'],
                    stats['memory_percent'],
                    stats['disk_percent']
                ))
            
        except Exception as e:
            logger.error(f"Stats update failed: {e}")
    
    def run(self):
        """تشغيل النظام"""
        logger.info("🚀 Starting Professional Telegram Bot Hosting System v3.0")
        logger.info(f"📊 System initialized with {len(SUPPORTED_EXTENSIONS)} supported languages")
        
        try:
            self.bot.infinity_polling(timeout=10, long_polling_timeout=5)
        except Exception as e:
            logger.critical(f"Bot polling failed: {e}")
            raise

# ═══════════════════════════════════════════════════════════════
# 🎯 MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        # إنشاء وتشغيل النظام
        hosting_system = ProfessionalTelegramBotHost()
        hosting_system.run()
        
    except KeyboardInterrupt:
        logger.info("System shutdown by user")
    except Exception as e:
        logger.critical(f"System startup failed: {e}")
        sys.exit(1)