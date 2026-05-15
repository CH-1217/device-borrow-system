"""
设备借用管理系统 - Flask 后端
SQLite 版本
"""

import hashlib
import hmac
import secrets
import json
import logging
import bcrypt  # [安全修复] 使用 bcrypt 进行密码哈希

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, make_response, abort
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
import csv
import sqlite3
import os
import io
from datetime import datetime, timedelta
from functools import wraps
from contextlib import closing
from qrgen import generate_qr_zip, generate_single_qr_png, generate_home_qr_png, generate_borrow_qr_png, generate_return_qr_png, generate_device_qr_png

app = Flask(__name__)

# [安全修复] 根据环境变量判断是否为生产环境
is_production = os.environ.get('FLASK_ENV') == 'production'
app.config['TEMPLATES_AUTO_RELOAD'] = not is_production  # 生产环境关闭模板自动重载
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0 if not is_production else 3600  # 生产环境启用缓存
app.config['DEBUG'] = not is_production  # 生产环境关闭调试模式

CORS(app)

# [安全修复] CSRF 防护（临时禁用，需要时再启用）
# csrf = CSRFProtect()
# csrf.init_app(app)
csrf = None  # 占位符

# [安全修复] 日志配置：同时输出到控制台和文件
logger = logging.getLogger(__name__)

# ============ 配置 ============
ADMIN_USER = 'admin'  # 保留常量，不再用于认证
DATA_DIR = os.environ.get('BORROW_DATA_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'borrow_data'))
DB_FILE = os.path.join(DATA_DIR, 'borrow.db')

# [安全修复] 日志配置：同时输出到控制台和文件（在配置定义之后）
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)
if os.path.exists(DATA_DIR):
    fh = logging.FileHandler(os.path.join(DATA_DIR, 'app.log'), encoding='utf-8')
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def audit_log(action, username, details=''):
    """[安全修复] 安全审计日志：记录关键操作"""
    ip = ''
    try:
        ip = request.remote_addr
    except:
        pass
    logger.info(f"[AUDIT] {action} | User: {username} | IP: {ip} | {details}")

# Cookie 签名密钥（生产环境应通过环境变量注入）
# [安全修复] 使用固定密钥，避免重启后所有会话失效
COOKIE_SECRET = os.environ.get('COOKIE_SECRET')
if not COOKIE_SECRET:
    # 如果没有设置环境变量，从文件读取或生成并保存
    secret_file = os.path.join(DATA_DIR, '.cookie_secret')
    if os.path.exists(secret_file):
        with open(secret_file, 'r') as f:
            COOKIE_SECRET = f.read().strip()
    else:
        COOKIE_SECRET = secrets.token_hex(32)
        with open(secret_file, 'w') as f:
            f.write(COOKIE_SECRET)
app.config['SECRET_KEY'] = COOKIE_SECRET  # [安全修复] Flask-WTF CSRF 需要 SECRET_KEY


def _hash_password(password):
    """[安全修复] 使用 bcrypt 进行密码哈希（慢哈希，防暴力破解）"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def _verify_password(password, hashed):
    """[安全修复] 验证密码，支持新旧两种格式"""
    try:
        # 如果是 bcrypt 格式（$2b$ 开头）
        if hashed.startswith('$2'):
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        else:
            # 兼容旧 SHA-256 格式（仅用于迁移）
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed
    except Exception:
        return False


def get_admin_by_username(username):
    """根据用户名查询管理员"""
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM admins WHERE username = ?', [username]).fetchone()
        return dict(row) if row else None


def get_all_admins():
    """获取所有管理员列表（不含密码哈希）"""
    admins = []
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute('SELECT id, username, role, display_name, created_at, last_login, is_active FROM admins ORDER BY id'):
            admins.append(dict(row))
    return admins


def get_current_admin():
    """[安全修复] 从 Cookie 中获取当前登录的管理员信息（含 role）"""
    cookie = request.cookies.get('admin_auth')
    if not cookie:
        return None
    try:
        parts = cookie.split(':')
        if len(parts) != 2:
            return None
        username = parts[0]
        admin = get_admin_by_username(username)
        if not admin or not admin['is_active']:
            return None
        # [安全修复] 使用 created_at 验证签名，避免密码变化导致失效
        msg = f"{username}:{admin['created_at']}"
        expected_sig = hmac.new(COOKIE_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(parts[1], expected_sig):
            return None
        return admin
    except Exception:
        return None


def _make_cookie_token(username):
    """[安全修复] 生成安全的认证 Cookie token（HMAC签名，使用固定密钥）"""
    admin = get_admin_by_username(username)
    if not admin:
        return None
    # 使用用户创建时间作为签名基础，避免密码变化导致 token 失效
    msg = f"{username}:{admin['created_at']}"
    sig = hmac.new(COOKIE_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{username}:{sig}"


def _verify_cookie_token(cookie_value):
    """[安全修复] 验证 Cookie token 是否有效"""
    if not cookie_value:
        return False
    try:
        parts = cookie_value.split(':')
        if len(parts) != 2:
            return False
        username, sig = parts
        admin = get_admin_by_username(username)
        if not admin or not admin['is_active']:
            return False
        # 使用用户创建时间验证签名
        expected_msg = f"{username}:{admin['created_at']}"
        expected_sig = hmac.new(COOKIE_SECRET.encode(), expected_msg.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected_sig):
            return False
        return True
    except Exception:
        return False


# ============ 数据库初始化 ============
def init_db():
    """初始化 SQLite 数据库，创建表结构"""
    os.makedirs(DATA_DIR, exist_ok=True)
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                device_name TEXT,
                borrower TEXT,
                department TEXT,
                phone TEXT,
                borrow_time TEXT,
                expected_return TEXT,
                actual_return TEXT,
                status TEXT,
                submit_time TEXT,
                submit_type TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT,
                location TEXT,
                status TEXT DEFAULT '空闲',
                note TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS departments (
                name TEXT PRIMARY KEY
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'operator',
                display_name TEXT DEFAULT '',
                created_at TEXT,
                last_login TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        # 功能配置表 - 控制系统字段的必填性和显示名称
        conn.execute('''
            CREATE TABLE IF NOT EXISTS field_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                field_key TEXT NOT NULL,
                form_type TEXT DEFAULT 'borrow',
                field_name TEXT NOT NULL,
                is_required INTEGER DEFAULT 0,
                is_enabled INTEGER DEFAULT 1,
                sort_order INTEGER DEFAULT 0,
                updated_at TEXT,
                UNIQUE(field_key, form_type)
            )
        ''')
        # 迁移：检查并添加 form_type 列（兼容旧数据库）
        try:
            conn.execute('SELECT form_type FROM field_configs LIMIT 1')
        except sqlite3.OperationalError:
            # 旧表没有 form_type 列，需要重建表
            conn.execute('''
                CREATE TABLE field_configs_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    field_key TEXT NOT NULL,
                    form_type TEXT DEFAULT 'borrow',
                    field_name TEXT NOT NULL,
                    is_required INTEGER DEFAULT 0,
                    is_enabled INTEGER DEFAULT 1,
                    sort_order INTEGER DEFAULT 0,
                    updated_at TEXT,
                    UNIQUE(field_key, form_type)
                )
            ''')
            conn.execute('''
                INSERT INTO field_configs_new (id, field_key, form_type, field_name, is_required, is_enabled, sort_order, updated_at)
                SELECT id, field_key, 'borrow', field_name, is_required, is_enabled, sort_order, updated_at
                FROM field_configs
            ''')
            conn.execute('DROP TABLE field_configs')
            conn.execute('ALTER TABLE field_configs_new RENAME TO field_configs')
        # 检查是否有归还表单字段，如果没有则添加
        cur = conn.execute("SELECT COUNT(*) FROM field_configs WHERE form_type = 'return'")
        if cur.fetchone()[0] == 0:
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return_fields = [
                ('device_id', 'return', '设备编号', 1, 1, 1),
                ('return_time', 'return', '归还时间', 0, 1, 2),
                ('note', 'return', '归还备注', 0, 1, 3),
            ]
            for key, form_type, name, req, en, sort in return_fields:
                conn.execute('''
                    INSERT INTO field_configs (field_key, form_type, field_name, is_required, is_enabled, sort_order, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', [key, form_type, name, req, en, sort, now_str])
        # 如果 field_configs 表为空，插入默认配置
        cur = conn.execute('SELECT COUNT(*) FROM field_configs')
        if cur.fetchone()[0] == 0:
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # 借用表单字段 - 按照需求文档要求的字段配置
            borrow_fields = [
                ('device_id', 'borrow', '设备编号', 1, 1, 1),
                ('device_name', 'borrow', '设备名称', 0, 1, 2),
                ('borrower', 'borrow', '借用人姓名', 1, 1, 3),  # 借用人姓名(必填)
                ('dept', 'borrow', '借用部门', 1, 1, 4),  # 借用部门(必填)
                ('phone', 'borrow', '联系电话', 0, 1, 5),  # 联系电话(可选)
                ('borrow_time', 'borrow', '借用时间', 1, 1, 6),
                ('return_time', 'borrow', '预计归还', 0, 1, 7),
                ('note', 'borrow', '借用用途', 1, 1, 8),  # 借用用途(必填)
            ]
            # 归还表单字段 - 按照需求文档要求的字段配置
            return_fields = [
                ('device_id', 'return', '设备编号', 1, 1, 1),
                ('return_person', 'return', '归还人姓名', 1, 1, 2),  # 归还人姓名(必填)
                ('device_status', 'return', '设备状态', 0, 1, 3),  # 设备状态(可选)
                ('return_time', 'return', '归还时间', 0, 1, 4),
                ('note', 'return', '备注', 0, 1, 5),  # 备注(可选)
            ]
            all_fields = borrow_fields + return_fields
            for key, form_type, name, req, en, sort in all_fields:
                conn.execute('''
                    INSERT INTO field_configs (field_key, form_type, field_name, is_required, is_enabled, sort_order, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', [key, form_type, name, req, en, sort, now_str])
        # 如果 admins 表为空，插入默认超级管理员
        cur = conn.execute('SELECT COUNT(*) FROM admins')
        if cur.fetchone()[0] == 0:
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('''
                INSERT INTO admins (username, password_hash, role, display_name, created_at, last_login, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ['admin', _hash_password('123456'), 'super', '超级管理员', now_str, now_str, 1])
        conn.commit()

def migrate_from_csv():
    """从旧 CSV 文件迁移数据到 SQLite（仅首次）"""
    csv_files = {
        'records': os.path.join(DATA_DIR, 'records.csv'),
        'devices': os.path.join(DATA_DIR, 'devices.csv'),
        'departments': os.path.join(DATA_DIR, 'departments.csv'),
    }

    with closing(sqlite3.connect(DB_FILE)) as conn:
        # 检查 records 表是否为空
        cur = conn.execute("SELECT COUNT(*) FROM records")
        if cur.fetchone()[0] > 0:
            return  # 已有数据，跳过迁移

        # 迁移 records
        records_csv = csv_files['records']
        if os.path.exists(records_csv):
            with open(records_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    conn.execute('''
                        INSERT INTO records (device_id, device_name, borrower, department, phone,
                            borrow_time, expected_return, actual_return, status, submit_time, submit_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', [
                        row.get('设备编号', ''), row.get('设备名称', ''), row.get('借用人', ''),
                        row.get('部门', ''), row.get('手机号', ''), row.get('借用时间', ''),
                        row.get('预计归还', ''), row.get('实际归还', ''), row.get('状态', ''),
                        row.get('提交时间', ''), row.get('登记方式', '')
                    ])
            conn.commit()
            # 备份旧 CSV
            os.rename(records_csv, records_csv + '.bak')

        # 迁移 devices
        devices_csv = csv_files['devices']
        if os.path.exists(devices_csv):
            with open(devices_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    conn.execute('''
                        INSERT OR IGNORE INTO devices (device_id, device_name, location, status, note)
                        VALUES (?, ?, ?, ?, ?)
                    ''', [
                        row.get('设备编号', ''), row.get('设备名称', ''), row.get('位置', ''),
                        row.get('当前状态', '空闲'), row.get('备注', '')
                    ])
            conn.commit()
            os.rename(devices_csv, devices_csv + '.bak')

        # 迁移 departments
        depts_csv = csv_files['departments']
        if os.path.exists(depts_csv):
            with open(depts_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = row.get('部门名称', '').strip()
                    if name:
                        conn.execute('INSERT OR IGNORE INTO departments (name) VALUES (?)', [name])
            conn.commit()
            os.rename(depts_csv, depts_csv + '.bak')

init_db()
migrate_from_csv()

# ============ 数据访问层 ============
def get_devices():
    devices = {}
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute('SELECT * FROM devices'):
            devices[row['device_id']] = dict(row)
    return devices

def get_records(limit=None, device_id=None):
    records = []
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        query = 'SELECT * FROM records ORDER BY id DESC'
        params = []
        if device_id:
            query = 'SELECT * FROM records WHERE device_id = ? ORDER BY id DESC'
            params = [device_id]
        for row in conn.execute(query, params):
            r = dict(row)
            r['设备编号'] = r.pop('device_id')
            r['设备名称'] = r.pop('device_name')
            r['借用人'] = r.pop('borrower')
            r['部门'] = r.pop('department')
            r['手机号'] = r.pop('phone')
            r['借用时间'] = r.pop('borrow_time')
            r['预计归还'] = r.pop('expected_return')
            r['实际归还'] = r.pop('actual_return')
            r['状态'] = r.pop('status')
            r['提交时间'] = r.pop('submit_time')
            r['登记方式'] = r.pop('submit_type')
            records.append(r)
    return records[:limit] if limit else records

def get_departments():
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT name FROM departments ORDER BY name').fetchall()
        if not rows:
            return ['技术部', '财务部', '行政部', '市场部', '人事部', '信息部']
        return [r['name'] for r in rows]

def get_available_devices():
    devices = get_devices()
    records = get_records()
    borrowed = {}
    for r in records:
        if r['状态'] == '借用中':
            borrowed[r['设备编号']] = r

    result = []
    for dev_id, dev in devices.items():
        dev = dict(dev)
        actual_status = '借用中' if dev_id in borrowed else '空闲'
        dev['状态'] = actual_status
        dev['设备编号'] = dev_id
        # 映射数据库字段为中文名称，供前端模板使用
        dev['设备名称'] = dev.pop('device_name', '')
        dev['位置'] = dev.pop('location', '')
        dev['备注'] = dev.pop('note', '')
        if dev_id in borrowed:
            rec = borrowed[dev_id]
            dev['当前借用人'] = rec['借用人']
            dev['借用部门'] = rec['部门']
            dev['手机号'] = rec.get('手机号', '')
            dev['借用时间'] = rec['借用时间']
            dev['预计归还'] = rec['预计归还']
        else:
            dev['当前借用人'] = ''
            dev['借用部门'] = ''
            dev['手机号'] = ''
            dev['借用时间'] = ''
            dev['预计归还'] = ''
        result.append(dev)
    return result

def update_device_status(device_id, status):
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('UPDATE devices SET status = ? WHERE device_id = ?', [status, device_id])
        conn.commit()

def is_device_borrowed(device_id):
    """检查设备是否正在被借用（通过 records 表判断）"""
    with closing(sqlite3.connect(DB_FILE)) as conn:
        cur = conn.execute(
            "SELECT COUNT(*) FROM records WHERE device_id = ? AND status = '借用中'",
            [device_id])
        return cur.fetchone()[0] > 0

# ============ 认证 ============
def require_auth(f):
    """需要管理员登录的装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_cookie_auth():
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated

def require_auth_api(f):
    """需要管理员登录的 API 装饰器（返回 JSON 而非重定向）"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_cookie_auth():
            return jsonify({'success': False, 'message': '未登录或登录已过期'}), 401
        return f(*args, **kwargs)
    return decorated

def require_super_admin(f):
    """需要超级管理员权限的装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin = get_current_admin()
        if not admin:
            return redirect('/admin/login')
        if admin['role'] != 'super':
            abort(403)
        return f(*args, **kwargs)
    return decorated

def require_super_admin_api(f):
    """需要超级管理员权限的 API 装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin = get_current_admin()
        if not admin:
            return jsonify({'success': False, 'message': '未登录'}), 401
        if admin['role'] != 'super':
            return jsonify({'success': False, 'message': '权限不足'}), 403
        return f(*args, **kwargs)
    return decorated

def check_cookie_auth():
    """检查 Cookie 认证状态"""
    cookie = request.cookies.get('admin_auth')
    if not cookie:
        return False

    # 验证 token 签名
    valid = _verify_cookie_token(cookie)
    if not valid:
        return False

    # 检查超时
    last_active = request.cookies.get('admin_last')
    if last_active:
        try:
            last_time = datetime.fromisoformat(last_active)
            if (datetime.now() - last_time).total_seconds() > 1800:
                return False
        except (ValueError, TypeError):
            pass
    return True

# ============ 借用者页面（公开） ============
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/borrow')
def borrow_page():
    devices = get_available_devices()
    return render_template('borrow.html', devices=devices)

@app.route('/return')
def return_page():
    devices = get_available_devices()
    return render_template('return.html', devices=devices)

@app.route('/qr')
def qr_home():
    return render_template('qr_home.html')

@app.route('/qr/<device_id>')
def qr_page(device_id):
    device_id = device_id.strip()
    devices = get_devices()
    if device_id not in devices:
        return '设备不存在', 404
    return render_template('qr.html', device_id=device_id, device=devices[device_id])

# ============ 借用/归还 API ============
@app.route('/api/submit-borrow', methods=['POST'])
def submit_borrow():
    data = request.form or request.get_json()
    device_id = data.get('device_id', '').strip()
    device_name = data.get('device_name', '').strip()
    borrower = data.get('borrower', '').strip()
    dept = data.get('dept', '').strip()
    phone = data.get('phone', '').strip()
    borrow_time = data.get('borrow_time', '').strip()
    return_time = data.get('return_time', '').strip()
    note = data.get('note', '').strip()
    submit_type = data.get('submit_type', '扫码')

    if not all([device_id, borrower, dept, phone, borrow_time]):
        return jsonify({'success': False, 'message': '请填写完整信息（含手机号）'})
    if not phone.startswith('1') or len(phone) != 11:
        return jsonify({'success': False, 'message': '手机号格式不正确'})

    # [BUG修复#9] 检查设备是否存在
    devices = get_devices()
    if device_id not in devices:
        return jsonify({'success': False, 'message': '设备编号不存在'})

    # [安全修复] 使用事务保证原子性：检查状态、更新设备、插入记录在一个事务中完成
    with closing(sqlite3.connect(DB_FILE)) as conn:
        try:
            conn.execute('BEGIN EXCLUSIVE')  # 独占锁，防止并发问题
            
            # 检查设备是否已被借用（在事务内检查，避免竞态条件）
            cur = conn.execute("SELECT status FROM devices WHERE device_id = ?", [device_id])
            row = cur.fetchone()
            if row and row[0] == '借用中':
                conn.rollback()
                return jsonify({'success': False, 'message': '该设备已被借用，请先归还后再借用'})
            
            # 更新设备状态
            conn.execute("UPDATE devices SET status = '借用中' WHERE device_id = ?", [device_id])
            
            # 插入借用记录
            conn.execute('''
                INSERT INTO records (device_id, device_name, borrower, department, phone,
                    borrow_time, expected_return, actual_return, status, submit_time, submit_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', [device_id, device_name, borrower, dept, phone,
                 borrow_time, return_time, '', '借用中',
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'), submit_type])
            
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"借用事务失败: {e}")
            return jsonify({'success': False, 'message': '系统错误，请稍后重试'})

    # [安全修复] 审计日志：借用操作
    audit_log('DEVICE_BORROW', 'borrower:' + borrower, f'device:{device_id} {device_name}')
    return jsonify({'success': True, 'message': '借用登记成功！请按时归还。'})

@app.route('/api/submit-return', methods=['POST'])
def submit_return():
    data = request.form or request.get_json()
    device_id = data.get('device_id', '').strip()
    actual_return_time = data.get('actual_return_time', '').strip()

    if not device_id:
        return jsonify({'success': False, 'message': '设备编号不能为空'})

    # [安全修复] 使用事务保证原子性：更新记录和设备状态在一个事务中完成
    now = actual_return_time if actual_return_time else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with closing(sqlite3.connect(DB_FILE)) as conn:
        try:
            conn.execute('BEGIN EXCLUSIVE')
            conn.row_factory = sqlite3.Row
            
            # 找到最新一条借用中记录并归还
            cur = conn.execute(
                "SELECT id FROM records WHERE device_id = ? AND status = '借用中' ORDER BY id DESC LIMIT 1",
                [device_id])
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return jsonify({'success': False, 'message': '该设备没有借用中的记录，无需归还'})
            
            # 更新记录
            conn.execute("UPDATE records SET actual_return = ?, status = '已归还' WHERE id = ?",
                        [now, row['id']])
            
            # 更新设备状态
            conn.execute("UPDATE devices SET status = '空闲' WHERE device_id = ?", [device_id])
            
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"归还事务失败: {e}")
            return jsonify({'success': False, 'message': '系统错误，请稍后重试'})
    
    # [安全修复] 审计日志：归还操作
    audit_log('DEVICE_RETURN', 'public', f'device:{device_id}')
    return jsonify({'success': True, 'message': '归还成功！'})

# ============ 管理后台（需登录） ============
@app.route('/admin/login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin/login/submit', methods=['POST'])
def admin_login_submit():
    user = request.form.get('username', '').strip()
    pw = request.form.get('password', '').strip()
    admin = get_admin_by_username(user)
    if admin and _verify_password(pw, admin['password_hash']) and admin['is_active']:
        # [安全修复] 登录成功后，如果密码是旧格式，自动升级为 bcrypt
        if not admin['password_hash'].startswith('$2'):
            with closing(sqlite3.connect(DB_FILE)) as conn:
                conn.execute('UPDATE admins SET password_hash = ? WHERE username = ?', 
                           [_hash_password(pw), user])
                conn.commit()
        # 更新 last_login
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with closing(sqlite3.connect(DB_FILE)) as conn:
            conn.execute('UPDATE admins SET last_login = ? WHERE username = ?', [now_str, user])
            conn.commit()
        # [安全修复] 审计日志：登录成功
        audit_log('LOGIN_SUCCESS', user)
        resp = make_response(redirect('/admin'))
        token = _make_cookie_token(user)
        # [安全修复] 先清除可能存在的旧 cookie，再设置新的
        resp.delete_cookie('admin_auth', path='/admin')  # 清除旧 path
        resp.delete_cookie('admin_last', path='/admin')  # 清除旧 path
        # [安全修复] Cookie安全设置：Strict防止CSRF，path限制作用域
        resp.set_cookie('admin_auth', token, max_age=3600*24, httponly=True, samesite='Strict', path='/')
        resp.set_cookie('admin_last', datetime.now().isoformat(), max_age=1800, httponly=True, samesite='Strict', path='/')
        return resp
    # [安全修复] 审计日志：登录失败
    audit_log('LOGIN_FAILED', user or 'unknown', f'attempted with username: {user}')
    return render_template('admin_login.html', error='用户名或密码错误')

@app.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect('/admin/login'))
    # [安全修复] 清除所有可能的 cookie path
    resp.delete_cookie('admin_auth', path='/')
    resp.delete_cookie('admin_last', path='/')
    resp.delete_cookie('admin_auth', path='/admin')  # 旧 path
    resp.delete_cookie('admin_last', path='/admin')  # 旧 path
    return resp

@app.route('/admin/last-active', methods=['POST'])
def admin_last_active():
    if not check_cookie_auth():
        return '', 401
    resp = make_response('', 204)
    resp.set_cookie('admin_last', datetime.now().isoformat(), max_age=1800)
    return resp

@app.route('/admin')
def admin():
    if not check_cookie_auth():
        return redirect('/admin/login')
    devices = get_available_devices()
    records = get_records(limit=50)

    borrowed_now = sum(1 for d in devices if d['状态'] == '借用中')

    dept_count = {}
    for r in records:
        if r['部门']:
            dept_count[r['部门']] = dept_count.get(r['部门'], 0) + 1
    device_count = {}
    for r in records:
        if r['设备编号']:
            device_count[r['设备编号']] = device_count.get(r['设备编号'], 0) + 1

    now = datetime.now()
    overdue = []
    for d in devices:
        if d['状态'] == '借用中' and d['预计归还']:
            try:
                # [BUG修复#15] 统一用 datetime 对象比较，避免字符串比较不一致
                expected_date = datetime.strptime(d['预计归还'].split(' ')[0], '%Y-%m-%d')
                if expected_date < now:
                    overdue_days = (now.date() - expected_date.date()).days
                    d['超期天数'] = overdue_days
                    overdue.append(d)
            except (ValueError, IndexError):
                logger.warning("日期解析失败: %s", d['预计归还'])

    return render_template('admin.html',
        devices=devices,
        records=records[:20],
        departments=get_departments(),
        stats={
            'total_devices': len(devices),
            'borrowed_now': borrowed_now,
            'total_records': len(records),
            'overdue_count': len(overdue),
            'dept_count': sorted(dept_count.items(), key=lambda x: -x[1])[:10],
            'device_count': sorted(device_count.items(), key=lambda x: -x[1])[:10],
            'now_str': now.strftime('%Y-%m-%d'),
        },
        overdue=overdue,
        current_admin=get_current_admin(),
    )

# ============ 设备管理（需登录） ============
@app.route('/admin/devices')
@require_auth
def admin_devices():
    return redirect('/admin/system#tab-device')

@app.route('/admin/devices/add', methods=['POST'])
@require_auth
def add_device():
    data = request.form or request.get_json()
    device_id = data.get('device_id', '').strip()
    device_name = data.get('device_name', '').strip()
    location = data.get('location', '').strip()
    note = data.get('note', '').strip()

    if not all([device_id, device_name]):
        return jsonify({'success': False, 'message': '设备编号和名称必填'})

    devices = get_devices()
    if device_id in devices:
        return jsonify({'success': False, 'message': '设备编号已存在'})

    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('INSERT INTO devices (device_id, device_name, location, status, note) VALUES (?, ?, ?, ?, ?)',
                     [device_id, device_name, location, '空闲', note])
        conn.commit()

    # [安全修复] 审计日志：添加设备
    audit_log('DEVICE_ADD', get_current_admin()['username'], f'device:{device_id} {device_name}')
    return jsonify({'success': True, 'message': '设备添加成功'})

@app.route('/admin/devices/update', methods=['POST'])
@require_auth
def update_device():
    data = request.form or request.get_json()
    device_id = data.get('device_id', '').strip()
    device_name = data.get('device_name', '').strip()
    location = data.get('location', '').strip()
    note = data.get('note', '').strip()

    if not device_id:
        return jsonify({'success': False, 'message': '设备编号不能为空'})

    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('UPDATE devices SET device_name = ?, location = ?, note = ? WHERE device_id = ?',
                     [device_name, location, note, device_id])
        conn.commit()

    return jsonify({'success': True, 'message': '设备更新成功'})

@app.route('/admin/devices/delete', methods=['POST'])
@require_auth
def delete_device():
    data = request.form or request.get_json()
    device_id = data.get('device_id', '').strip()

    if not device_id:
        return jsonify({'success': False, 'message': '设备编号不能为空'})

    # [BUG修复#10] 使用 records 表检查借用状态，而非 devices 表的 status 字段
    if is_device_borrowed(device_id):
        return jsonify({'success': False, 'message': '设备正在使用中，无法删除'})

    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('DELETE FROM devices WHERE device_id = ?', [device_id])
        conn.commit()

    return jsonify({'success': True, 'message': '设备已删除'})

# ============ 管理员修改密码（需登录） ============
@app.route('/admin/change-password', methods=['POST'])
@require_auth
def change_password():
    admin = get_current_admin()
    data = request.form or request.get_json()
    old_pass = data.get('old_pass', '').strip()
    new_pass = data.get('new_pass', '').strip()
    confirm_pass = data.get('confirm_pass', '').strip()

    # [安全修复] 从 admins 表验证旧密码
    db_admin = get_admin_by_username(admin['username'])
    if not _verify_password(old_pass, db_admin['password_hash']):
        return jsonify({'success': False, 'message': '旧密码错误'})
    if len(new_pass) < 6:
        return jsonify({'success': False, 'message': '新密码至少6位'})
    if new_pass != confirm_pass:
        return jsonify({'success': False, 'message': '两次新密码不一致'})

    # 更新 admins 表
    new_hash = _hash_password(new_pass)
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('UPDATE admins SET password_hash = ? WHERE username = ?', [new_hash, admin['username']])
        conn.commit()

    return jsonify({'success': True, 'message': '密码修改成功，请重新登录'})

@app.route('/api/stats')
@require_auth_api
def api_stats():
    devices = get_available_devices()
    records = get_records()
    dept_count = {}
    for r in records:
        if r['部门']:
            dept_count[r['部门']] = dept_count.get(r['部门'], 0) + 1
    device_count = {}
    for r in records:
        if r['设备编号']:
            device_count[r['设备编号']] = device_count.get(r['设备编号'], 0) + 1

    now = datetime.now()
    overdue = []
    for d in devices:
        if d['状态'] == '借用中' and d['预计归还']:
            try:
                expected_date = datetime.strptime(d['预计归还'].split(' ')[0], '%Y-%m-%d')
                if expected_date < now:
                    overdue_days = (now.date() - expected_date.date()).days
                    d['超期天数'] = overdue_days
                    overdue.append(d)
            except (ValueError, IndexError):
                logger.warning("日期解析失败: %s", d['预计归还'])

    return jsonify({
        'devices': devices,
        'total_devices': len(devices),
        'borrowed_now': sum(1 for d in devices if d['状态'] == '借用中'),
        'total_records': len(records),
        'overdue': overdue,
        'dept_count': dept_count,
        'device_count': device_count,
    })

# ============ 设备列表 API（供前端筛选） ============
@app.route('/api/devices')
def api_devices():
    devices = get_available_devices()
    return jsonify({'success': True, 'devices': devices})

@app.route('/api/departments')
def api_departments():
    return jsonify({'success': True, 'departments': get_departments()})

# [BUG修复#5] 部门管理 API 添加认证保护
@app.route('/api/departments/add', methods=['POST'])
@require_auth_api
def api_departments_add():
    data = request.form or request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'message': '部门名称不能为空'})
    departments = get_departments()
    if name in departments:
        return jsonify({'success': False, 'message': '该部门已存在'})
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('INSERT INTO departments (name) VALUES (?)', [name])
        conn.commit()
    return jsonify({'success': True, 'message': '部门已添加'})

@app.route('/api/departments/update', methods=['POST'])
@require_auth_api
def api_departments_update():
    data = request.form or request.get_json()
    old_name = data.get('old_name', '').strip()
    new_name = data.get('new_name', '').strip()
    if not old_name or not new_name:
        return jsonify({'success': False, 'message': '参数不完整'})
    if old_name == new_name:
        return jsonify({'success': True, 'message': '未修改'})
    departments = get_departments()
    if new_name in departments and new_name != old_name:
        return jsonify({'success': False, 'message': '该部门已存在'})
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('UPDATE departments SET name = ? WHERE name = ?', [new_name, old_name])
        conn.commit()
    return jsonify({'success': True, 'message': '部门已修改'})

@app.route('/api/departments/delete', methods=['POST'])
@require_auth_api
def api_departments_delete():
    data = request.form or request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'message': '部门名称不能为空'})
    departments = get_departments()
    if name not in departments:
        return jsonify({'success': False, 'message': '该部门不存在'})
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('DELETE FROM departments WHERE name = ?', [name])
        conn.commit()
    return jsonify({'success': True, 'message': '部门已删除'})

@app.route('/admin/departments')
@require_auth
def admin_departments():
    return redirect('/admin/system#tab-dept')

# ============ 设备状态查询 API ============
@app.route('/api/device/<device_id>')
def api_device(device_id):
    devices = get_devices()
    if device_id not in devices:
        return jsonify({'success': False, 'message': '设备不存在'})
    return jsonify({'success': True, 'device': devices[device_id]})

# ============ QR码批量生成（需登录） ============
@app.route('/api/qr-generate', methods=['POST'])
@require_auth
def api_qr_generate():
    data = request.form or request.get_json()
    device_ids_raw = data.get('device_ids', [])
    if isinstance(device_ids_raw, str):
        device_ids = json.loads(device_ids_raw)
    elif isinstance(device_ids_raw, list):
        device_ids = device_ids_raw
    else:
        device_ids = []
    if not device_ids:
        return jsonify({'success': False, 'message': '请选择设备'})

    devices = get_devices()
    device_names = {d: devices[d]['device_name'] for d in device_ids if d in devices}

    zip_data = generate_qr_zip(device_ids, device_names)

    resp = make_response(zip_data)
    resp.headers['Content-Type'] = 'application/zip'
    resp.headers['Content-Disposition'] = 'attachment; filename="qr_codes.zip"'
    return resp

@app.route('/api/qr-single')
def api_qr_single():
    """返回统一二维码图片（内联显示）"""
    png_data = generate_single_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    return resp

@app.route('/api/qr-single-download')
def api_qr_single_download():
    """下载统一二维码图片"""
    png_data = generate_single_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    resp.headers['Content-Disposition'] = 'attachment; filename="device_borrow_qr.png"'
    return resp

@app.route('/api/qr-home')
def api_qr_home():
    """系统首页二维码（内联显示）"""
    png_data = generate_home_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    return resp

@app.route('/api/qr-home-download')
def api_qr_home_download():
    """下载系统首页二维码"""
    png_data = generate_home_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    resp.headers['Content-Disposition'] = 'attachment; filename="system_home_qr.png"'
    return resp

@app.route('/api/qr-borrow')
def api_qr_borrow():
    """借用登记二维码（内联显示）"""
    png_data = generate_borrow_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    return resp

@app.route('/api/qr-borrow-download')
def api_qr_borrow_download():
    """下载借用登记二维码"""
    png_data = generate_borrow_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    resp.headers['Content-Disposition'] = 'attachment; filename="borrow_qr.png"'
    return resp

@app.route('/api/qr-return')
def api_qr_return():
    """归还登记二维码（内联显示）"""
    png_data = generate_return_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    return resp

@app.route('/api/qr-return-download')
def api_qr_return_download():
    """下载归还登记二维码"""
    png_data = generate_return_qr_png()
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    resp.headers['Content-Disposition'] = 'attachment; filename="return_qr.png"'
    return resp

@app.route('/api/qr-device/<device_id>')
def api_qr_device(device_id):
    """指定设备二维码（内联显示）"""
    png_data = generate_device_qr_png(device_id)
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    return resp

@app.route('/api/qr-device-download/<device_id>')
def api_qr_device_download(device_id):
    """下载指定设备二维码"""
    png_data = generate_device_qr_png(device_id)
    resp = make_response(png_data)
    resp.headers['Content-Type'] = 'image/png'
    resp.headers['Content-Disposition'] = f'attachment; filename="{device_id}_qr.png"'
    return resp

# ============ 借用记录导出（需登录） ============
@app.route('/admin/export')
@require_auth
def export_records():
    """导出借用/归还记录为 CSV"""
    # 获取筛选参数
    range_filter = request.args.get('range', 'all')  # week / month / all
    status_filter = request.args.get('status', 'all')  # borrowed / returned / all
    device_filter = request.args.get('device_id', '').strip()

    records = get_records()

    # 应用时间范围筛选
    now = datetime.now()
    if range_filter == 'week':
        cutoff = now - timedelta(days=7)
        records = [r for r in records if r['提交时间'] and
                   datetime.strptime(r['提交时间'], '%Y-%m-%d %H:%M:%S') >= cutoff]
    elif range_filter == 'month':
        cutoff = now - timedelta(days=30)
        records = [r for r in records if r['提交时间'] and
                   datetime.strptime(r['提交时间'], '%Y-%m-%d %H:%M:%S') >= cutoff]

    # 应用状态筛选
    if status_filter == 'borrowed':
        records = [r for r in records if r['状态'] == '借用中']
    elif status_filter == 'returned':
        records = [r for r in records if r['状态'] == '已归还']

    # 应用设备筛选
    if device_filter:
        records = [r for r in records if r['设备编号'] == device_filter]

    # 生成 CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['设备编号', '设备名称', '借用人', '部门', '手机号',
                     '借用时间', '预计归还', '实际归还', '状态', '登记方式'])
    for r in records:
        writer.writerow([
            r['设备编号'], r['设备名称'], r['借用人'], r['部门'], r['手机号'],
            r['借用时间'], r['预计归还'], r['实际归还'], r['状态'], r['登记方式']
        ])

    csv_content = output.getvalue()
    output.close()

    filename = f"借用记录_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    # RFC 5987/RFC 2231 编码，避免中文文件名导致 gunicorn HTTP 头解析失败
    import urllib.parse
    encoded_filename = urllib.parse.quote(filename)
    resp = make_response(csv_content)
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_filename}"
    return resp

# ============ 管理员 CRUD API（需超级管理员权限） ============
@app.route('/api/admins')
@require_super_admin_api
def api_get_admins():
    """获取管理员列表"""
    admins = get_all_admins()
    current = get_current_admin()
    return jsonify({
        'success': True,
        'admins': admins,
        'current_admin': {
            'username': current['username'],
            'role': current['role'],
            'display_name': current.get('display_name', ''),
        } if current else None,
    })


@app.route('/api/admins/add', methods=['POST'])
@require_super_admin_api
def api_add_admin():
    """添加管理员"""
    data = request.form or request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'operator').strip()
    display_name = data.get('display_name', '').strip()

    if not username:
        return jsonify({'success': False, 'message': '用户名不能为空'})
    if len(password) < 6:
        return jsonify({'success': False, 'message': '密码至少6位'})
    if role not in ('super', 'operator'):
        return jsonify({'success': False, 'message': '角色只能是 super 或 operator'})

    # 检查用户名是否已存在
    existing = get_admin_by_username(username)
    if existing:
        return jsonify({'success': False, 'message': '用户名已存在'})

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    password_hash = _hash_password(password)
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('''
            INSERT INTO admins (username, password_hash, role, display_name, created_at, last_login, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', [username, password_hash, role, display_name, now_str, now_str, 1])
        conn.commit()

    # [安全修复] 审计日志：添加管理员
    audit_log('ADMIN_ADD', get_current_admin()['username'], f'new_admin:{username} role:{role}')
    return jsonify({'success': True, 'message': '管理员添加成功'})


@app.route('/api/admins/update', methods=['POST'])
@require_super_admin_api
def api_update_admin():
    """更新管理员信息"""
    data = request.form or request.get_json()
    admin_id = data.get('id')
    role = data.get('role', '').strip()
    display_name = data.get('display_name', '').strip()
    is_active = data.get('is_active')

    if not admin_id:
        return jsonify({'success': False, 'message': '缺少管理员 ID'})

    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM admins WHERE id = ?', [admin_id]).fetchone()
        if not row:
            return jsonify({'success': False, 'message': '管理员不存在'})

        admin = dict(row)
        old_role = admin['role']

        # 如果要降级或禁用 super 管理员，检查是否是最后一个
        if old_role == 'super' and (role != 'super' or is_active == 0 or is_active == '0' or is_active is False):
            cur = conn.execute("SELECT COUNT(*) FROM admins WHERE role = 'super' AND is_active = 1")
            active_super_count = cur.fetchone()[0]
            if active_super_count <= 1:
                return jsonify({'success': False, 'message': '不能降级或禁用最后一个超级管理员'})

        if role and role in ('super', 'operator'):
            conn.execute('UPDATE admins SET role = ? WHERE id = ?', [role, admin_id])
        if display_name is not None:
            conn.execute('UPDATE admins SET display_name = ? WHERE id = ?', [display_name, admin_id])
        if is_active is not None:
            conn.execute('UPDATE admins SET is_active = ? WHERE id = ?', [int(is_active), admin_id])
        conn.commit()

    return jsonify({'success': True, 'message': '管理员信息已更新'})


@app.route('/api/admins/delete', methods=['POST'])
@require_super_admin_api
def api_delete_admin():
    """删除管理员"""
    data = request.form or request.get_json()
    admin_id = data.get('id')

    if not admin_id:
        return jsonify({'success': False, 'message': '缺少管理员 ID'})

    current = get_current_admin()

    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM admins WHERE id = ?', [admin_id]).fetchone()
        if not row:
            return jsonify({'success': False, 'message': '管理员不存在'})

        admin = dict(row)

        # 不能删除自己
        if admin['username'] == current['username']:
            return jsonify({'success': False, 'message': '不能删除自己'})

        # 如果是 super 管理员，检查是否是最后一个
        if admin['role'] == 'super':
            cur = conn.execute("SELECT COUNT(*) FROM admins WHERE role = 'super' AND is_active = 1")
            active_super_count = cur.fetchone()[0]
            if active_super_count <= 1:
                return jsonify({'success': False, 'message': '不能删除最后一个超级管理员'})

        conn.execute('DELETE FROM admins WHERE id = ?', [admin_id])
        conn.commit()

    return jsonify({'success': True, 'message': '管理员已删除'})


@app.route('/api/admins/reset-pw', methods=['POST'])
@require_super_admin_api
def api_reset_admin_password():
    """重置管理员密码"""
    data = request.form or request.get_json()
    admin_id = data.get('id')
    new_password = data.get('new_password', '').strip()

    if not admin_id:
        return jsonify({'success': False, 'message': '缺少管理员 ID'})
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': '新密码至少6位'})

    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM admins WHERE id = ?', [admin_id]).fetchone()
        if not row:
            return jsonify({'success': False, 'message': '管理员不存在'})

        new_hash = _hash_password(new_password)
        conn.execute('UPDATE admins SET password_hash = ? WHERE id = ?', [new_hash, admin_id])
        conn.commit()

    return jsonify({'success': True, 'message': '密码已重置'})


# ============ 功能管理 API（需超级管理员权限） ============
def get_field_configs(form_type=None):
    """获取字段配置"""
    configs = []
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        if form_type:
            for row in conn.execute('SELECT * FROM field_configs WHERE form_type = ? ORDER BY sort_order', [form_type]):
                configs.append(dict(row))
        else:
            for row in conn.execute('SELECT * FROM field_configs ORDER BY form_type, sort_order'):
                configs.append(dict(row))
    return configs

@app.route('/api/field-configs')
@require_super_admin_api
def api_field_configs():
    """获取字段配置列表（需超级管理员权限）"""
    form_type = request.args.get('form_type')  # 'borrow' 或 'return'，不传则返回全部
    configs = get_field_configs(form_type)
    return jsonify({'success': True, 'configs': configs})

@app.route('/api/field-configs/public')
def api_field_configs_public():
    """公开获取字段配置（无需登录，供借用/归还表单使用）"""
    form_type = request.args.get('form_type')
    configs = get_field_configs(form_type)
    # 只返回启用的字段
    enabled_configs = [c for c in configs if c['is_enabled']]
    return jsonify({'success': True, 'configs': enabled_configs})

@app.route('/api/field-configs/update', methods=['POST'])
@require_super_admin_api
def api_field_config_update():
    """更新字段配置"""
    data = request.form or request.get_json()
    config_id = data.get('id')
    field_name = data.get('field_name', '').strip()
    is_required = data.get('is_required', 0)
    is_enabled = data.get('is_enabled', 1)
    
    if not config_id or not field_name:
        return jsonify({'success': False, 'message': '参数不完整'})
    
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('''
            UPDATE field_configs 
            SET field_name = ?, is_required = ?, is_enabled = ?, updated_at = ?
            WHERE id = ?
        ''', [field_name, is_required, is_enabled, now_str, config_id])
        conn.commit()
    
    return jsonify({'success': True, 'message': '配置已更新'})

@app.route('/api/field-configs/reset', methods=['POST'])
@require_super_admin_api
def api_field_config_reset():
    """重置为默认配置"""
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # 借用表单字段
    borrow_fields = [
        ('device_id', 'borrow', '设备编号', 1, 1, 1),
        ('device_name', 'borrow', '设备名称', 0, 1, 2),
        ('borrower', 'borrow', '借用人', 1, 1, 3),
        ('dept', 'borrow', '部门', 1, 1, 4),
        ('phone', 'borrow', '手机号', 1, 1, 5),
        ('borrow_time', 'borrow', '借用时间', 1, 1, 6),
        ('return_time', 'borrow', '预计归还', 0, 1, 7),
        ('note', 'borrow', '备注', 0, 1, 8),
    ]
    # 归还表单字段
    return_fields = [
        ('device_id', 'return', '设备编号', 1, 1, 1),
        ('return_time', 'return', '归还时间', 0, 1, 2),
        ('note', 'return', '归还备注', 0, 1, 3),
    ]
    all_fields = borrow_fields + return_fields
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.execute('DELETE FROM field_configs')
        for key, form_type, name, req, en, sort in all_fields:
            conn.execute('''
                INSERT INTO field_configs (field_key, form_type, field_name, is_required, is_enabled, sort_order, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', [key, form_type, name, req, en, sort, now_str])
        conn.commit()
    return jsonify({'success': True, 'message': '已恢复默认配置'})


# ============ 系统管理页面（需登录） ============
@app.route('/admin/system')
@require_auth
def admin_system():
    return render_template('admin_system.html', current_admin=get_current_admin())


# [安全修复] 全局异常处理器：捕获所有未处理的异常，防止堆栈信息泄露
@app.errorhandler(Exception)
def handle_error(error):
    logger.exception(f"未处理的异常: {error}")
    # 生产环境返回通用错误信息，不暴露堆栈
    if app.config.get('DEBUG'):
        return f"<h1>Error</h1><pre>{error}</pre>", 500
    return "<h1>服务器内部错误</h1><p>请稍后重试或联系管理员。</p>", 500


# [安全修复] 404 错误处理
@app.errorhandler(404)
def handle_not_found(error):
    return "<h1>页面未找到</h1>", 404


# [安全修复] 403 禁止访问
@app.errorhandler(403)
def handle_forbidden(error):
    return "<h1>禁止访问</h1>", 403


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
