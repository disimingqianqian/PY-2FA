import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import hmac
import hashlib
import base64
import struct
import time
import urllib.parse
import cv2
import numpy as np
from PIL import ImageGrab
import os
import json
import sqlite3
import ctypes
import re
import sys
import logging
import socket
import threading
import queue

# ================= 强制修正 Windows 高 DPI 缩放问题 =================
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# ================= 控制台日志配置 (仅检测到控制台时输出) =================
def setup_console():
    if sys.platform == "win32":
        if ctypes.windll.kernel32.GetConsoleWindow() == 0:
            return
        try:
            if sys.stdout is None:
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
            if sys.stderr is None:
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        except Exception:
            pass

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logging.info("系统日志已启动，控制台输出绑定成功。")

# ================= 配置与数据库路径 =================
APP_NAME = "Mini2FAGuard"
APP_DATA_DIR = os.getenv('APPDATA') or os.path.expanduser('~')
CONFIG_DIR = os.path.join(APP_DATA_DIR, APP_NAME)
DB_FILE = os.path.join(CONFIG_DIR, "data.db")
OLD_JSON_FILE = os.path.join(CONFIG_DIR, "config.json")

AUTO_LOCK_SECONDS = 300
BACKUP_MAGIC = b"MINI2FA1"
MAX_DIGITS = 15

# ================= 单实例锁 =================
_SINGLE_INSTANCE_MUTEX = None

def acquire_single_instance():
    """成功获得锁返回 True；已有实例则尝试唤起旧窗口并返回 False"""
    global _SINGLE_INSTANCE_MUTEX
    try:
        kernel32 = ctypes.windll.kernel32
        _SINGLE_INSTANCE_MUTEX = kernel32.CreateMutexW(None, False, "Mini2FAGuard_SingleInstance")
        ERROR_ALREADY_EXISTS = 183
        if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            hwnd = ctypes.windll.user32.FindWindowW(None, "py 2FA")
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 9)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
            return False
        return True
    except Exception:
        return True

# ================= 数据库操作层 =================
def init_db():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, secret TEXT NOT NULL)')
    cursor.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
    cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', ('anti_screenshot', '1'))

    if os.path.exists(OLD_JSON_FILE):
        try:
            with open(OLD_JSON_FILE, 'r', encoding='utf-8') as f:
                old_accounts = json.load(f)
                for acc in old_accounts:
                    cursor.execute('INSERT INTO accounts (name, secret) VALUES (?, ?)', (acc['name'], acc['secret']))
            os.rename(OLD_JSON_FILE, OLD_JSON_FILE + ".bak")
            logging.info("检测到旧版 JSON 配置文件，已成功迁移至 SQLite 数据库。")
        except Exception as e:
            logging.error(f"旧数据迁移失败: {e}")

    conn.commit()
    conn.close()
    logging.info("数据库初始化完成。")

def get_setting(key, default=""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key, value):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, str(value)))
    conn.commit()
    conn.close()

def migrate_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(accounts)")
        cols = {row[1] for row in cursor.fetchall()}
        new_cols = [
            ("algorithm", "TEXT DEFAULT 'SHA1'"),
            ("digits", "INTEGER DEFAULT 6"),
            ("period", "INTEGER DEFAULT 30"),
            ("issuer", "TEXT DEFAULT ''"),
            ("otpauth_url", "TEXT DEFAULT ''"),
        ]
        for col, ddl in new_cols:
            if col not in cols:
                cursor.execute(f"ALTER TABLE accounts ADD COLUMN {col} {ddl}")
                logging.info(f"数据库升级：accounts 表新增字段 {col}")
        conn.commit()
    except Exception as e:
        logging.error(f"数据库升级失败: {e}")
    finally:
        conn.close()

def load_accounts_from_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM accounts ORDER BY id')
    rows = cursor.fetchall()
    conn.close()

    accounts = []
    for r in rows:
        d = dict(r)
        d["name"] = d.get("name") or "未命名账户"
        d["secret"] = (d.get("secret") or "").strip()
        alg = str(d.get("algorithm") or "SHA1").upper().replace("-", "")
        d["algorithm"] = alg if alg in ("SHA1", "SHA256", "SHA512", "MD5") else "SHA1"
        try:
            d["digits"] = int(d.get("digits") or 6)
        except (TypeError, ValueError):
            d["digits"] = 6
        if not (1 <= d["digits"] <= MAX_DIGITS):
            d["digits"] = 6
        try:
            d["period"] = int(d.get("period") or 30)
        except (TypeError, ValueError):
            d["period"] = 30
        if d["period"] <= 0:
            d["period"] = 30
        d["issuer"] = d.get("issuer") or ""
        d["otpauth_url"] = d.get("otpauth_url") or ""
        accounts.append(d)
    return accounts

def find_account_by_secret(secret):
    norm = normalize_secret(secret)
    if not norm:
        return None
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, secret FROM accounts')
    rows = cursor.fetchall()
    conn.close()
    for acc_id, name, sec in rows:
        if normalize_secret(sec) == norm:
            return acc_id, name
    return None

def add_account_to_db(name, secret, algorithm="SHA1", digits=6, period=30, issuer="", otpauth_url=""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO accounts (name, secret, algorithm, digits, period, issuer, otpauth_url) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (name, secret, str(algorithm).upper(), int(digits), int(period), issuer or "", otpauth_url or "")
    )
    conn.commit()
    conn.close()

def update_account_in_db(acc_id, name, secret, algorithm="SHA1", digits=6, period=30, issuer="", otpauth_url=""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE accounts SET name=?, secret=?, algorithm=?, digits=?, period=?, issuer=?, otpauth_url=? WHERE id=?',
        (name, secret, str(algorithm).upper(), int(digits), int(period),
         issuer or "", otpauth_url or "", acc_id)
    )
    conn.commit()
    conn.close()

def delete_account_from_db(acc_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM accounts WHERE id = ?', (acc_id,))
    conn.commit()
    conn.close()

# ================= 备份加解密 =================
def _derive_keys(password, salt):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200000, dklen=64)
    return dk[:32], dk[32:]

def _xor_stream(data, key):
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out[:len(data)]))

def encrypt_backup(data, password):
    salt = os.urandom(16)
    enc_key, mac_key = _derive_keys(password, salt)
    ct = _xor_stream(data, enc_key)
    mac = hmac.new(mac_key, salt + ct, hashlib.sha256).digest()
    return BACKUP_MAGIC + salt + mac + ct

def decrypt_backup(blob, password):
    if not blob.startswith(BACKUP_MAGIC):
        raise ValueError("不是有效的备份文件")
    salt = blob[len(BACKUP_MAGIC):len(BACKUP_MAGIC) + 16]
    mac = blob[len(BACKUP_MAGIC) + 16:len(BACKUP_MAGIC) + 48]
    ct = blob[len(BACKUP_MAGIC) + 48:]
    enc_key, mac_key = _derive_keys(password, salt)
    expect = hmac.new(mac_key, salt + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise ValueError("密码错误或文件已损坏")
    return _xor_stream(ct, enc_key)

# ================= 防截屏工具函数 =================
def apply_anti_screenshot(window, enable):
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000011 if enable else 0x00000000)
    except Exception as e:
        logging.error(f"防截屏设置失败: {e}")

# ================= NTP 时间同步 =================
_NTP_SERVERS = [
    "ntp.tencent.com",
    "ntp1.tencent.com",
    "ntp2.tencent.com",
    "ntp3.tencent.com",
    "ntp4.tencent.com",
    "ntp5.tencent.com",
    "ntp.aliyun.com",
    "pool.ntp.org",
]
_NTP_DELTA = 2208988800

_ntp_offset = 0.0
_ntp_ok = False
_ntp_lock = threading.Lock()

def _query_ntp(server, timeout=3):
    packet = b'\x1b' + 47 * b'\0'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t1 = time.time()
        sock.sendto(packet, (server, 123))
        data, _ = sock.recvfrom(1024)
        t4 = time.time()
        if len(data) < 48:
            return None
        unpacked = struct.unpack('!12I', data)
        t2 = unpacked[8] + float(unpacked[9]) / 2 ** 32 - _NTP_DELTA
        t3 = unpacked[10] + float(unpacked[11]) / 2 ** 32 - _NTP_DELTA
        return ((t2 - t1) + (t3 - t4)) / 2.0
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

def sync_ntp():
    global _ntp_offset, _ntp_ok
    for server in _NTP_SERVERS:
        off = _query_ntp(server)
        if off is not None:
            with _ntp_lock:
                _ntp_offset = off
                _ntp_ok = True
            logging.info(f"NTP 时间同步成功 ({server})，偏移 {off:+.3f} 秒")
            return True
    with _ntp_lock:
        _ntp_ok = False
    logging.warning("NTP 时间同步失败，已回退到系统时间")
    return False

def get_current_time():
    with _ntp_lock:
        off = _ntp_offset
        ok = _ntp_ok
    return time.time() + off if ok else time.time()

def start_ntp_sync():
    def worker():
        sync_ntp()
        while True:
            time.sleep(600)
            sync_ntp()
    threading.Thread(target=worker, daemon=True).start()

# ==================================================================
# 二维码 / TOTP 多算法支持
# ==================================================================

_ALGO_MAP = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "MD5": hashlib.md5,
}

def normalize_secret(secret):
    return re.sub(r'\s+', '', (secret or "")).upper().rstrip("=")

def parse_otpauth_full(raw_text):
    info = {
        "name": "手动添加", "secret": "", "algorithm": "SHA1",
        "digits": 6, "period": 30, "issuer": "", "url": ""
    }
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return info

    if not raw_text.lower().startswith("otpauth://"):
        info["secret"] = normalize_secret(raw_text)
        return info

    try:
        parsed = urllib.parse.urlparse(raw_text)
        params = urllib.parse.parse_qs(parsed.query)

        info["url"] = raw_text
        info["secret"] = normalize_secret(params.get("secret", [""])[0])

        alg = params.get("algorithm", ["SHA1"])[0].upper().replace("-", "")
        info["algorithm"] = alg if alg in _ALGO_MAP else "SHA1"

        try:
            digits = int(params.get("digits", ["6"])[0])
        except (TypeError, ValueError):
            digits = 6
        info["digits"] = digits if 1 <= digits <= MAX_DIGITS else 6

        try:
            period = int(params.get("period", ["30"])[0])
        except (TypeError, ValueError):
            period = 30
        info["period"] = period if period > 0 else 30

        issuer = params.get("issuer", [""])[0].strip()
        label = urllib.parse.unquote(parsed.path.lstrip("/"))
        if "/" in label:
            label = label.split("/", 1)[1]
        if ":" in label:
            iss_from_label, _, acc_name = label.partition(":")
            if not issuer:
                issuer = iss_from_label.strip()
            label = acc_name.strip()
        info["issuer"] = issuer
        info["name"] = label.strip() or (issuer or "未命名账户")
    except Exception as e:
        logging.error(f"解析 otpauth 链接失败: {e}")

    return info

def build_otpauth_url(name, secret, issuer="", algorithm="SHA1", digits=6, period=30):
    label = f"{issuer}:{name}" if issuer and not str(name).startswith(f"{issuer}:") else str(name)
    label = urllib.parse.quote(label, safe="")

    params = {"secret": normalize_secret(secret)}
    alg = str(algorithm).upper()
    if alg != "SHA1":
        params["algorithm"] = alg
    if int(digits) != 6:
        params["digits"] = int(digits)
    if int(period) != 30:
        params["period"] = int(period)
    if issuer:
        params["issuer"] = issuer

    return "otpauth://totp/" + label + "?" + urllib.parse.urlencode(params)

def generate_totp_ex(secret, algorithm="SHA1", digits=6, period=30):
    """支持 SHA1/SHA256/SHA512/MD5，位数 1~15（>10 位用 8 字节扩展）"""
    digestmod = _ALGO_MAP.get(str(algorithm).upper().replace("-", ""), hashlib.sha1)

    try:
        digits = int(digits)
    except (TypeError, ValueError):
        digits = 6
    if not (1 <= digits <= MAX_DIGITS):
        digits = 6

    try:
        period = int(period)
    except (TypeError, ValueError):
        period = 30
    if period <= 0:
        period = 30

    norm = normalize_secret(secret)
    key = base64.b32decode(norm + "=" * ((8 - len(norm) % 8) % 8))
    counter = int(get_current_time() // period)
    counter_bytes = struct.pack(">Q", counter)
    hmac_digest = hmac.new(key, counter_bytes, digestmod).digest()
    dlen = len(hmac_digest)

    if digits <= 10:
        offset = hmac_digest[-1] & 0x0F
        if offset > dlen - 4:
            offset = offset % (dlen - 3)
        binary_code = struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF
    else:
        offset = hmac_digest[-1] % (dlen - 7)
        binary_code = struct.unpack(">Q", hmac_digest[offset:offset + 8])[0] & 0x7FFFFFFFFFFFFFFF

    otp = binary_code % (10 ** digits)
    return f"{otp:0{digits}d}"

def decode_qr_codes(img_bgr):
    results = []
    detector = cv2.QRCodeDetector()
    try:
        ok, decoded_info, _, _ = detector.detectAndDecodeMulti(img_bgr)
        if ok and decoded_info:
            results = [d for d in decoded_info if d]
    except Exception:
        results = []
    if not results:
        try:
            data, _, _ = detector.detectAndDecode(img_bgr)
            if data:
                results = [data]
        except Exception:
            pass
    return results

def save_qr_image(parent, img, title):
    safe = re.sub(r'[\\/:*?"<>|]', "_", str(title)) or "qrcode"
    path = filedialog.asksaveasfilename(
        parent=parent, title="保存二维码",
        initialfile=f"{safe}_2fa.png",
        defaultextension=".png",
        filetypes=[("PNG 图片", "*.png"), ("JPEG 图片", "*.jpg")])
    if not path:
        return
    try:
        img.save(path)
        messagebox.showinfo("保存成功", f"二维码已保存到:\n{path}", parent=parent)
        logging.info(f"二维码已保存: {path}")
    except Exception as e:
        messagebox.showerror("保存失败", f"保存图片时出错:\n{e}", parent=parent)

def show_qr_window(parent, text, title="账户"):
    try:
        import qrcode
        from PIL import Image, ImageTk
    except ImportError:
        messagebox.showerror(
            "缺少依赖",
            "生成二维码需要 qrcode 库。\n\n请运行以下命令安装：\n    pip install qrcode[pil]")
        return

    try:
        img = qrcode.make(text).convert("RGB")
    except Exception as e:
        messagebox.showerror("生成失败", f"生成二维码时出错:\n{e}")
        return

    win = tk.Toplevel(parent)
    win.title(f"二维码 - {title}")
    win.resizable(False, False)
    win.transient(parent)

    photo = ImageTk.PhotoImage(img)
    lbl = tk.Label(win, image=photo, bg="white")
    lbl.image = photo
    lbl.pack(padx=20, pady=(20, 8))

    tk.Label(win, text=text, wraplength=320, fg="gray",
             font=("Consolas", 8), justify=tk.LEFT).pack(padx=20)

    btns = tk.Frame(win)
    btns.pack(pady=12)
    tk.Button(btns, text="💾 保存为图片", width=12,
              command=lambda: save_qr_image(win, img, title)).pack(side=tk.LEFT, padx=5)
    tk.Button(btns, text="关闭", width=8, command=win.destroy).pack(side=tk.LEFT, padx=5)

    win.update_idletasks()
    px = parent.winfo_rootx() + (parent.winfo_width() - win.winfo_width()) // 2
    py = parent.winfo_rooty() + (parent.winfo_height() - win.winfo_height()) // 2
    win.geometry(f"+{max(px, 0)}+{max(py, 0)}")

# ================= 首次启动：设置密码 Frame =================
class SetupPasswordFrame(tk.Frame):
    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.on_success = on_success
        self.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(self, text="首次使用 - 设置主密码", font=("Arial", 12, "bold")).pack(pady=10)
        tk.Label(self, text="要求：至少8位，包含大写字母、小写字母和数字").pack(pady=5)

        frame1 = tk.Frame(self)
        frame1.pack(pady=5)
        tk.Label(frame1, text="新密码:").pack(side=tk.LEFT)
        self.pwd_entry = tk.Entry(frame1, show="*", width=20)
        self.pwd_entry.pack(side=tk.LEFT, padx=5)

        frame2 = tk.Frame(self)
        frame2.pack(pady=5)
        tk.Label(frame2, text="确认密码:").pack(side=tk.LEFT)
        self.pwd_confirm = tk.Entry(frame2, show="*", width=20)
        self.pwd_confirm.pack(side=tk.LEFT, padx=5)

        self.error_label = tk.Label(self, text="", fg="red")
        self.error_label.pack(pady=5)
        tk.Button(self, text="确认并进入", command=self.save_password, width=15).pack(pady=10)

    def save_password(self):
        pwd = self.pwd_entry.get()
        confirm = self.pwd_confirm.get()
        if not pwd or not confirm:
            self.error_label.config(text="密码不能为空！")
            return
        if pwd != confirm:
            self.error_label.config(text="两次输入的密码不一致！")
            return
        if len(pwd) < 8 or not re.search(r'[a-z]', pwd) or not re.search(r'[A-Z]', pwd) or not re.search(r'[0-9]', pwd):
            self.error_label.config(text="密码必须包含大小写字母和数字，且长度不少于8位！")
            return

        set_setting('master_password_hash', hashlib.sha256(pwd.encode()).hexdigest())
        logging.info("主密码设置成功。")
        self.destroy()
        self.on_success()

# ================= 后续启动：解锁 Frame =================
class UnlockFrame(tk.Frame):
    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.on_success = on_success
        self.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(self, text="请输入主密码解锁", font=("Arial", 12, "bold")).pack(pady=20)
        frame = tk.Frame(self)
        frame.pack(pady=5)
        tk.Label(frame, text="密码:").pack(side=tk.LEFT)
        self.pwd_entry = tk.Entry(frame, show="*", width=20)
        self.pwd_entry.pack(side=tk.LEFT, padx=5)
        self.pwd_entry.bind("<Return>", lambda e: self.unlock())
        self.pwd_entry.focus_set()

        self.error_label = tk.Label(self, text="", fg="red")
        self.error_label.pack(pady=5)
        tk.Button(self, text="解锁", command=self.unlock, width=10).pack(pady=10)

    def unlock(self):
        pwd = self.pwd_entry.get()
        stored_hash = get_setting('master_password_hash', '')
        if hashlib.sha256(pwd.encode()).hexdigest() == stored_hash:
            logging.info("主密码验证成功，用户已登录。")
            self.destroy()
            self.on_success()
        else:
            logging.warning("主密码验证失败，尝试登录被拒绝。")
            self.error_label.config(text="密码错误，请重试！")
            self.pwd_entry.delete(0, tk.END)

# ================= 系统设置窗口 =================
class SettingsWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("系统设置")
        self.geometry("400x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.anti_screenshot_var = tk.IntVar(value=int(get_setting('anti_screenshot', '1')))
        tk.Checkbutton(self, text="开启防截屏保护 (WDA_EXCLUDEFROMCAPTURE)",
                       variable=self.anti_screenshot_var, command=self.toggle_anti_screenshot).pack(pady=15)

        frame_pwd = tk.LabelFrame(self, text="修改主密码", padx=10, pady=10)
        frame_pwd.pack(pady=10, fill=tk.X, padx=20)

        tk.Label(frame_pwd, text="旧密码:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.old_pwd_entry = tk.Entry(frame_pwd, show="*", width=20)
        self.old_pwd_entry.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(frame_pwd, text="新密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.new_pwd_entry = tk.Entry(frame_pwd, show="*", width=20)
        self.new_pwd_entry.grid(row=1, column=1, pady=5, padx=5)

        tk.Label(frame_pwd, text="确认新密码:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.confirm_pwd_entry = tk.Entry(frame_pwd, show="*", width=20)
        self.confirm_pwd_entry.grid(row=2, column=1, pady=5, padx=5)

        tk.Label(frame_pwd, text="(新密码需8位以上，包含大小写和数字)", fg="gray", font=("Arial", 8)).grid(row=3, column=0, columnspan=2, pady=5)

        tk.Button(frame_pwd, text="确认修改", command=self.change_password).grid(row=4, column=0, columnspan=2, pady=10)

        tk.Label(self, text=f"无操作自动锁定：{AUTO_LOCK_SECONDS // 60} 分钟",
                 fg="gray", font=("Arial", 9)).pack(pady=5)

        tk.Button(self, text="关闭", command=self.destroy, width=10).pack(pady=10)

    def toggle_anti_screenshot(self):
        val = self.anti_screenshot_var.get()
        set_setting('anti_screenshot', val)
        apply_anti_screenshot(self.master, val)
        logging.info(f"防截屏保护状态已切换为: {'开启' if val else '关闭'}")

    def change_password(self):
        old_pwd = self.old_pwd_entry.get().strip()
        new_pwd = self.new_pwd_entry.get().strip()
        confirm_pwd = self.confirm_pwd_entry.get().strip()

        if not old_pwd:
            messagebox.showwarning("提示", "请输入旧密码！")
            return

        stored_hash = get_setting('master_password_hash', '')
        if hashlib.sha256(old_pwd.encode()).hexdigest() != stored_hash:
            logging.warning("用户尝试修改密码，但旧密码验证失败。")
            messagebox.showerror("错误", "旧密码错误，无法修改！")
            return

        if len(new_pwd) < 8 or not re.search(r'[a-z]', new_pwd) or not re.search(r'[A-Z]', new_pwd) or not re.search(r'[0-9]', new_pwd):
            messagebox.showwarning("提示", "新密码必须包含大小写字母和数字，且长度不少于8位！")
            return

        if new_pwd != confirm_pwd:
            messagebox.showwarning("提示", "两次输入的新密码不一致！")
            return

        new_hash = hashlib.sha256(new_pwd.encode()).hexdigest()
        set_setting('master_password_hash', new_hash)

        self.old_pwd_entry.delete(0, tk.END)
        self.new_pwd_entry.delete(0, tk.END)
        self.confirm_pwd_entry.delete(0, tk.END)

        logging.info("主密码修改成功 (旧密码已验证)。")
        messagebox.showinfo("成功", "主密码已修改！请牢记，忘记密码将无法查看密钥。")

# ================= 添加方式选择窗口 =================
class AddChoiceDialog(tk.Toplevel):
    def __init__(self, parent, on_manual, on_clipboard, on_file, on_screenshot):
        super().__init__(parent)
        self.title("添加账户")
        self.geometry("320x340")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="请选择添加方式", font=("Arial", 12, "bold")).pack(pady=(20, 15))

        tk.Button(self, text="✍️  手动填写", width=24, height=2,
                  command=lambda: [self.destroy(), on_manual()]).pack(pady=5)
        tk.Button(self, text="📋  从剪贴板二维码", width=24, height=2,
                  command=lambda: [self.destroy(), on_clipboard()]).pack(pady=5)
        tk.Button(self, text="📁  从图片文件", width=24, height=2,
                  command=lambda: [self.destroy(), on_file()]).pack(pady=5)
        tk.Button(self, text="📷  截屏扫码", width=24, height=2,
                  command=lambda: [self.destroy(), on_screenshot()]).pack(pady=5)

        self.update_idletasks()
        px = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{max(px, 0)}+{max(py, 0)}")

# ================= 备份/迁移选择窗口 =================
class BackupChoiceDialog(tk.Toplevel):
    def __init__(self, parent, on_export, on_import):
        super().__init__(parent)
        self.title("备份 / 迁移")
        self.geometry("320x220")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="请选择操作", font=("Arial", 12, "bold")).pack(pady=(20, 15))

        tk.Button(self, text="📤  导出加密备份", width=24, height=2,
                  command=lambda: [self.destroy(), on_export()]).pack(pady=5)
        tk.Button(self, text="📥  导入加密备份", width=24, height=2,
                  command=lambda: [self.destroy(), on_import()]).pack(pady=5)

        self.update_idletasks()
        px = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{max(px, 0)}+{max(py, 0)}")

# ================= 手动添加账户窗口 =================
class AddAccountWindow(tk.Toplevel):
    def __init__(self, parent, on_saved):
        super().__init__(parent)
        self.on_saved = on_saved
        self.title("手动添加账户")
        self.geometry("440x380")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frm = tk.Frame(self, padx=20, pady=15)
        frm.pack(fill=tk.BOTH, expand=True)

        row = 0
        tk.Label(frm, text="账户名称:").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.name_var = tk.StringVar()
        tk.Entry(frm, textvariable=self.name_var, width=28).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="发行方:").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.issuer_var = tk.StringVar()
        tk.Entry(frm, textvariable=self.issuer_var, width=28).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="密钥 (Base32):").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.secret_var = tk.StringVar()
        tk.Entry(frm, textvariable=self.secret_var, width=28).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="算法:").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.algorithm_var = tk.StringVar(value="SHA1")
        ttk.Combobox(frm, textvariable=self.algorithm_var,
                     values=["SHA1", "SHA256", "SHA512", "MD5"],
                     state="readonly", width=25).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text=f"位数 (1~{MAX_DIGITS}):").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.digits_var = tk.StringVar(value="6")
        ttk.Combobox(frm, textvariable=self.digits_var,
                     values=[str(i) for i in range(1, MAX_DIGITS + 1)],
                     state="readonly", width=25).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="周期 (秒):").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.period_var = tk.StringVar(value="30")
        tk.Entry(frm, textvariable=self.period_var, width=28).grid(row=row, column=1, pady=6, padx=6)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="添加", width=10, command=self.save).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="取消", width=10, command=self.destroy).pack(side=tk.LEFT, padx=8)

    def save(self):
        name = self.name_var.get().strip()
        secret = normalize_secret(self.secret_var.get())
        issuer = self.issuer_var.get().strip()
        algorithm = self.algorithm_var.get().strip().upper()

        try:
            digits = int(self.digits_var.get())
            period = int(self.period_var.get())
        except ValueError:
            messagebox.showwarning("提示", "位数和周期必须是数字！", parent=self)
            return

        if not name:
            messagebox.showwarning("提示", "账户名称不能为空！", parent=self)
            return
        if not secret:
            messagebox.showwarning("提示", "密钥不能为空！", parent=self)
            return
        if not (1 <= digits <= MAX_DIGITS):
            messagebox.showwarning("提示", f"位数必须在 1 到 {MAX_DIGITS} 之间！", parent=self)
            return
        if period <= 0:
            messagebox.showwarning("提示", "周期必须大于 0！", parent=self)
            return

        try:
            base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
        except Exception:
            messagebox.showerror("错误", "密钥不是有效的 Base32 格式！", parent=self)
            return

        dup = find_account_by_secret(secret)
        if dup:
            messagebox.showerror(
                "无法导入",
                f"已存在此账户！\n\n重复的密钥属于账户「{dup[1]}」。",
                parent=self)
            return

        url = build_otpauth_url(name, secret, issuer, algorithm, digits, period)
        add_account_to_db(name, secret, algorithm, digits, period, issuer, url)
        logging.info(f"手动添加账户: {name} (发行方={issuer or '-'}, 算法={algorithm}, "
                     f"位数={digits}, 周期={period}s)")
        messagebox.showinfo("成功", "账户已添加！", parent=self)
        self.destroy()
        self.on_saved()

# ================= 账户编辑窗口 =================
class EditAccountWindow(tk.Toplevel):
    def __init__(self, parent, account, on_saved):
        super().__init__(parent)
        self.account = account
        self.on_saved = on_saved
        self.title(f"编辑账户 - {account['name']}")
        self.geometry("440x400")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        frm = tk.Frame(self, padx=20, pady=15)
        frm.pack(fill=tk.BOTH, expand=True)

        row = 0
        tk.Label(frm, text="账户名称:").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.name_var = tk.StringVar(value=account.get("name", ""))
        tk.Entry(frm, textvariable=self.name_var, width=28).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="发行方:").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.issuer_var = tk.StringVar(value=account.get("issuer", ""))
        tk.Entry(frm, textvariable=self.issuer_var, width=28).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="密钥 (Base32):").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.secret_var = tk.StringVar(value=account.get("secret", ""))
        self.secret_entry = tk.Entry(frm, textvariable=self.secret_var, width=28, show="*")
        self.secret_entry.grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Button(frm, text="👁 显示密钥（需密码）", width=22,
                  command=self._reveal_secret).grid(row=row, column=1, sticky=tk.W, padx=6)
        row += 1

        tk.Label(frm, text="算法:").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.algorithm_var = tk.StringVar(value=account.get("algorithm", "SHA1"))
        ttk.Combobox(frm, textvariable=self.algorithm_var,
                     values=["SHA1", "SHA256", "SHA512", "MD5"],
                     state="readonly", width=25).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text=f"位数 (1~{MAX_DIGITS}):").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.digits_var = tk.StringVar(value=str(account.get("digits", 6)))
        ttk.Combobox(frm, textvariable=self.digits_var,
                     values=[str(i) for i in range(1, MAX_DIGITS + 1)],
                     state="readonly", width=25).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="周期 (秒):").grid(row=row, column=0, sticky=tk.W, pady=6)
        self.period_var = tk.StringVar(value=str(account.get("period", 30)))
        tk.Entry(frm, textvariable=self.period_var, width=28).grid(row=row, column=1, pady=6, padx=6)
        row += 1

        tk.Label(frm, text="(改密钥会改变所有验证码，请谨慎操作)", fg="gray",
                 font=("Arial", 8)).grid(row=row, column=0, columnspan=2, pady=6)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="保存", width=10, command=self.save).pack(side=tk.LEFT, padx=8)
        tk.Button(btn_frame, text="取消", width=10, command=self.destroy).pack(side=tk.LEFT, padx=8)

    def _reveal_secret(self):
        pwd = simpledialog.askstring("安全验证", "请输入主密码以查看密钥:",
                                     show='*', parent=self)
        if pwd is None:
            return
        stored_hash = get_setting('master_password_hash', '')
        if hashlib.sha256(pwd.encode()).hexdigest() != stored_hash:
            logging.warning("编辑窗口查看密钥，密码验证失败。")
            messagebox.showerror("验证失败", "主密码错误！", parent=self)
            return
        self.secret_entry.config(show="")
        self.after(3000, lambda: self.secret_entry.config(show="*"))

    def save(self):
        name = self.name_var.get().strip()
        secret = normalize_secret(self.secret_var.get())
        issuer = self.issuer_var.get().strip()
        algorithm = self.algorithm_var.get().strip().upper()

        try:
            digits = int(self.digits_var.get())
            period = int(self.period_var.get())
        except ValueError:
            messagebox.showwarning("提示", "位数和周期必须是数字！", parent=self)
            return

        if not name:
            messagebox.showwarning("提示", "账户名称不能为空！", parent=self)
            return
        if not secret:
            messagebox.showwarning("提示", "密钥不能为空！", parent=self)
            return
        if not (1 <= digits <= MAX_DIGITS):
            messagebox.showwarning("提示", f"位数必须在 1 到 {MAX_DIGITS} 之间！", parent=self)
            return
        if period <= 0:
            messagebox.showwarning("提示", "周期必须大于 0！", parent=self)
            return

        try:
            base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
        except Exception:
            messagebox.showerror("错误", "密钥不是有效的 Base32 格式！", parent=self)
            return

        dup = find_account_by_secret(secret)
        if dup and dup[0] != self.account["id"]:
            messagebox.showerror(
                "密钥重复",
                f"该密钥已被账户「{dup[1]}」使用，不能重复保存。",
                parent=self)
            return

        url = build_otpauth_url(name, secret, issuer, algorithm, digits, period)
        update_account_in_db(self.account["id"], name, secret, algorithm, digits, period, issuer, url)
        logging.info(f"账户已更新: {name} (算法={algorithm}, 位数={digits}, 周期={period}s)")
        messagebox.showinfo("成功", "账户信息已保存！", parent=self)
        self.destroy()
        self.on_saved()

# ================= 截屏窗口 =================
class ScreenshotWindow(tk.Toplevel):
    def __init__(self, parent, callback):
        super().__init__(parent)
        self.callback = callback
        self.start_x = None
        self.start_y = None
        self.rect = None

        self.attributes('-fullscreen', True)
        self.attributes('-alpha', 0.3)
        self.configure(bg='black')
        self.attributes('-topmost', True)
        self.config(cursor="cross")

        self.canvas = tk.Canvas(self, bg='black', highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<ButtonPress-1>", self.on_press)
        self.canvas.bind("<B1-Motion>", self.on_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_release)
        self.bind("<Escape>", lambda e: self.destroy())

    def on_press(self, event):
        self.start_x = event.x_root
        self.start_y = event.y_root

    def on_drag(self, event):
        cur_x, cur_y = event.x_root, event.y_root
        if self.rect:
            self.canvas.delete(self.rect)
        self.rect = self.canvas.create_rectangle(
            self.start_x - self.winfo_rootx(), self.start_y - self.winfo_rooty(),
            cur_x - self.winfo_rootx(), cur_y - self.winfo_rooty(),
            outline='red', width=2)

    def on_release(self, event):
        end_x, end_y = event.x_root, event.y_root
        self.destroy()
        x1, x2 = min(self.start_x, end_x), max(self.start_x, end_x)
        y1, y2 = min(self.start_y, end_y), max(self.start_y, end_y)
        if x2 - x1 > 10 and y2 - y1 > 10:
            try:
                img = ImageGrab.grab(bbox=(x1, y1, x2, y2))
                self.callback(img)
            except Exception as e:
                logging.error(f"截图失败: {e}")
                messagebox.showerror("截图失败", f"无法截取屏幕: {e}")

# ================= 主界面 Frame =================
class Mini2FAGuard(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.root = parent
        self.pack(fill=tk.BOTH, expand=True)

        self.accounts = load_accounts_from_db()
        self.anti_screenshot_enabled = int(get_setting('anti_screenshot', '1'))

        self._last_activity = time.time()
        self._activity_bindings = []
        self._lock_after_id = None
        self._bind_activity()
        self._schedule_lock_check()

        frame_top = tk.Frame(self)
        frame_top.pack(pady=(10, 6), fill=tk.X, padx=10)

        tk.Button(frame_top, text="➕ 添加账户", width=14, height=1,
                  bg="#d0f0c0", command=self.open_add_dialog).pack(side=tk.LEFT, padx=2)
        tk.Button(frame_top, text="🔳 生成二维码", command=self.generate_qr_for_selected, bg="#fff3e0").pack(side=tk.LEFT, padx=2)
        tk.Button(frame_top, text="💾 备份/迁移", command=self.open_backup_dialog, bg="#e8eaf6").pack(side=tk.LEFT, padx=2)
        tk.Button(frame_top, text="⚙️ 系统设置", command=self.open_settings, bg="#f0f0f0").pack(side=tk.LEFT, padx=2)

        self.tree = ttk.Treeview(self, columns=("issuer", "name", "code", "time"), show="headings", height=10)
        self.tree.heading("issuer", text="发行方")
        self.tree.heading("name", text="账户")
        self.tree.heading("code", text="当前验证码")
        self.tree.heading("time", text="剩余秒数")
        self.tree.column("issuer", width=100, anchor="w")
        self.tree.column("name", width=130, anchor="w")
        self.tree.column("code", width=190, anchor="center")
        self.tree.column("time", width=80, anchor="center")
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)

        self.tree.bind("<Double-Button-1>", self.copy_code)
        self.tree.bind("<Button-3>", self.show_context_menu)

        tk.Button(self, text="删除选中账户", command=self.delete_account).pack(pady=5)

        self.refresh_treeview()
        self.root.after(100, lambda: apply_anti_screenshot(self.root, self.anti_screenshot_enabled))
        self.update_codes()
        logging.info("主界面加载完毕，验证码刷新线程已启动。")

    def _bind_activity(self):
        for seq in ("<Any-KeyPress>", "<Any-Button>", "<Motion>"):
            try:
                self.root.bind_all(seq, self._on_activity, add="+")
                self._activity_bindings.append(seq)
            except Exception:
                pass

    def _on_activity(self, event=None):
        self._last_activity = time.time()

    def _schedule_lock_check(self):
        elapsed = time.time() - self._last_activity
        if elapsed >= AUTO_LOCK_SECONDS:
            self._do_lock()
            return
        self._lock_after_id = self.root.after(5000, self._schedule_lock_check)

    def _do_lock(self):
        logging.info("检测到无操作超时，程序已自动锁定。")
        try:
            if self._lock_after_id:
                self.root.after_cancel(self._lock_after_id)
        except Exception:
            pass
        for w in list(self.root.winfo_children()):
            if isinstance(w, tk.Toplevel):
                try:
                    w.destroy()
                except Exception:
                    pass
        self.destroy()
        UnlockFrame(self.root, on_success=lambda: start_main_app(self.root))

    def open_backup_dialog(self):
        BackupChoiceDialog(self.root, on_export=self.do_export, on_import=self.do_import)

    def do_export(self):
        pwd = simpledialog.askstring("导出备份", "请设置备份密码（用于加密备份文件）:",
                                     show='*', parent=self.root)
        if not pwd:
            return
        if len(pwd) < 6:
            messagebox.showwarning("提示", "备份密码建议至少 6 位，请重新输入。", parent=self.root)
            return
        confirm = simpledialog.askstring("导出备份", "请再次输入备份密码:",
                                         show='*', parent=self.root)
        if confirm != pwd:
            messagebox.showwarning("提示", "两次输入的密码不一致。", parent=self.root)
            return

        ts = time.strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self.root, title="保存加密备份",
            initialfile=f"2FA_backup_{ts}.m2fa",
            defaultextension=".m2fa",
            filetypes=[("2FA 加密备份", "*.m2fa"), ("所有文件", "*.*")])
        if not path:
            return

        try:
            with open(DB_FILE, 'rb') as f:
                data = f.read()
            blob = encrypt_backup(data, pwd)
            with open(path, 'wb') as f:
                f.write(blob)
            logging.info(f"加密备份已导出: {path}")
            messagebox.showinfo("导出成功",
                                f"备份已导出到:\n{path}\n\n请牢记备份密码，遗失将无法恢复。",
                                parent=self.root)
        except Exception as e:
            logging.error(f"导出备份失败: {e}")
            messagebox.showerror("导出失败", f"导出备份时出错:\n{e}", parent=self.root)

    def do_import(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="选择加密备份文件",
            filetypes=[("2FA 加密备份", "*.m2fa"), ("所有文件", "*.*")])
        if not path:
            return

        pwd = simpledialog.askstring("导入备份", "请输入备份密码:", show='*', parent=self.root)
        if not pwd:
            return

        try:
            with open(path, 'rb') as f:
                blob = f.read()
            data = decrypt_backup(blob, pwd)
        except Exception as e:
            logging.error(f"解密备份失败: {e}")
            messagebox.showerror("导入失败", f"无法解密备份文件：\n{e}", parent=self.root)
            return

        if not data.startswith(b"SQLite format 3"):
            messagebox.showerror("导入失败", "解密成功，但内容不是有效的数据库文件。", parent=self.root)
            return

        if not messagebox.askyesno("确认导入",
                                   "导入后当前数据库将被备份文件中内容覆盖。\n"
                                   "原数据会另存为 data.db.bak。\n\n确定继续吗？",
                                   parent=self.root):
            return

        try:
            if os.path.exists(DB_FILE):
                bak = DB_FILE + ".bak"
                if os.path.exists(bak):
                    os.remove(bak)
                os.rename(DB_FILE, bak)
            with open(DB_FILE, 'wb') as f:
                f.write(data)
            migrate_db()
            self.refresh_treeview()
            logging.info(f"备份导入成功: {path}")
            messagebox.showinfo("导入成功",
                                "备份已成功导入，账户列表已刷新。\n"
                                "原数据库已保存为 data.db.bak。",
                                parent=self.root)
        except Exception as e:
            logging.error(f"导入备份失败: {e}")
            messagebox.showerror("导入失败", f"写入数据库时出错:\n{e}", parent=self.root)

    def open_settings(self):
        SettingsWindow(self.root)

    def open_add_dialog(self):
        AddChoiceDialog(
            self.root,
            on_manual=self.add_manual,
            on_clipboard=self.add_from_clipboard,
            on_file=self.add_from_file,
            on_screenshot=self.start_screenshot,
        )

    def add_manual(self):
        AddAccountWindow(self.root, on_saved=self.refresh_treeview)

    def add_from_clipboard(self):
        try:
            clip = ImageGrab.grabclipboard()
        except Exception as e:
            messagebox.showerror("剪贴板读取失败", f"无法访问剪贴板:\n{e}", parent=self.root)
            return

        if clip is None:
            messagebox.showwarning("剪贴板为空", "剪贴板中没有图片。\n请先把二维码截图/复制到剪贴板。", parent=self.root)
            return

        if isinstance(clip, list):
            found = False
            for path in clip:
                if not os.path.isfile(path):
                    continue
                ext = os.path.splitext(path)[1].lower()
                if ext not in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"):
                    continue
                found = True
                try:
                    buf = np.fromfile(path, dtype=np.uint8)
                    img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
                except Exception:
                    continue
                if img is not None:
                    self._import_from_image(img)
            if not found:
                messagebox.showwarning("未找到图片", "剪贴板里没有可识别的图片文件。", parent=self.root)
            return

        try:
            img_np = np.array(clip)
            if img_np.ndim == 2:
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_GRAY2BGR)
            else:
                img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        except Exception as e:
            messagebox.showerror("处理失败", f"无法处理剪贴板图片:\n{e}", parent=self.root)
            return

        self._import_from_image(img_bgr)

    def add_from_file(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="选择二维码图片",
            filetypes=[("图片文件", "*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff"),
                       ("所有文件", "*.*")])
        if not path:
            return

        try:
            buf = np.fromfile(path, dtype=np.uint8)
            img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
        except Exception as e:
            messagebox.showerror("读取失败", f"无法读取图片文件:\n{e}", parent=self.root)
            return

        if img is None:
            messagebox.showerror("读取失败", "无法解析该图片，请确认文件格式是否正确。", parent=self.root)
            return

        self._import_from_image(img)

    def _import_from_image(self, img_bgr):
        raw_results = decode_qr_codes(img_bgr)
        if not raw_results:
            messagebox.showwarning("识别失败", "未能从图片中识别到二维码。", parent=self.root)
            return

        urls = [u for u in raw_results if u.strip().lower().startswith("otpauth://")]
        if not urls:
            preview = "\n".join(raw_results[:3])
            messagebox.showwarning("格式不符",
                                   f"识别到二维码，但内容不是 2FA 链接：\n\n{preview}",
                                   parent=self.root)
            return

        added = 0
        skipped = 0
        dup_names = []
        for u in urls:
            info = parse_otpauth_full(u)
            if not info["secret"]:
                continue
            try:
                base64.b32decode(info["secret"] + "=" * ((8 - len(info["secret"]) % 8) % 8))
            except Exception:
                continue

            dup = find_account_by_secret(info["secret"])
            if dup:
                skipped += 1
                dup_names.append(f"{info['name']}（已存在于「{dup[1]}」）")
                logging.warning(f"跳过重复账户: {info['name']} (已有: {dup[1]})")
                continue

            url = info["url"] or build_otpauth_url(
                info["name"], info["secret"], info["issuer"],
                info["algorithm"], info["digits"], info["period"])
            add_account_to_db(info["name"], info["secret"], info["algorithm"],
                              info["digits"], info["period"], info["issuer"], url)
            added += 1
            logging.info(f"从二维码导入账户: {info['name']} "
                         f"(发行方={info['issuer'] or '-'}, 算法={info['algorithm']}, "
                         f"位数={info['digits']}, 周期={info['period']}s)")

        self.refresh_treeview()

        if added and not skipped:
            messagebox.showinfo("导入成功", f"已成功导入 {added} 个账户。", parent=self.root)
        elif added and skipped:
            msg = f"成功导入 {added} 个账户，跳过 {skipped} 个重复账户。"
            if dup_names:
                msg += "\n\n被跳过的重复项：\n" + "\n".join(dup_names[:5])
                if len(dup_names) > 5:
                    msg += f"\n...还有 {len(dup_names) - 5} 个"
            messagebox.showinfo("导入完成", msg, parent=self.root)
        elif skipped and not added:
            msg = "无法导入，已存在此账户！"
            if dup_names:
                msg += "\n\n重复项：\n" + "\n".join(dup_names[:5])
            messagebox.showwarning("无法导入", msg, parent=self.root)
        else:
            messagebox.showwarning("导入失败", "识别到链接，但密钥无效，未能导入。", parent=self.root)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="编辑账户", command=self.edit_account)
            menu.add_command(label="查看密钥 (需密码)", command=self.view_secret)
            menu.add_command(label="生成二维码", command=self.generate_qr_for_selected)
            menu.post(event.x_root, event.y_root)

    def edit_account(self):
        selected = self.tree.selection()
        if not selected:
            return
        acc_id = int(selected[0])
        account = next((acc for acc in self.accounts if acc["id"] == acc_id), None)
        if not account:
            return
        EditAccountWindow(self.root, account, on_saved=self.refresh_treeview)

    def view_secret(self):
        selected = self.tree.selection()
        if not selected: return
        acc_id = int(selected[0])
        account = next((acc for acc in self.accounts if acc["id"] == acc_id), None)
        if not account: return

        pwd = simpledialog.askstring("安全验证", "请输入主密码以查看密钥:", show='*', parent=self.root)
        if pwd is None: return

        stored_hash = get_setting('master_password_hash', '')
        if hashlib.sha256(pwd.encode()).hexdigest() == stored_hash:
            logging.info(f"用户查看密钥: {account['name']} (已验证密码)")
            messagebox.showinfo(
                "密钥信息",
                f"账户: {account['name']}\n"
                f"发行方: {account.get('issuer') or '-'}\n"
                f"算法: {account.get('algorithm', 'SHA1')}  |  "
                f"位数: {account.get('digits', 6)}  |  "
                f"周期: {account.get('period', 30)}s\n\n"
                f"密钥 (Secret):\n{account['secret']}",
                parent=self.root)
        else:
            logging.warning(f"用户尝试查看密钥: {account['name']} 密码验证失败。")
            messagebox.showerror("验证失败", "主密码错误！", parent=self.root)

    def refresh_treeview(self):
        self.accounts = load_accounts_from_db()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for account in self.accounts:
            issuer_disp = account.get("issuer") or "-"
            self.tree.insert("", "end",
                             values=(issuer_disp, account["name"], "------", "0s"),
                             iid=str(account["id"]))

    def start_screenshot(self):
        self.root.withdraw()
        self.root.after(200, self.open_screenshot_window)

    def open_screenshot_window(self):
        ScreenshotWindow(self.root, self.process_screenshot)

    def process_screenshot(self, pil_image):
        self.root.deiconify()
        img_np = np.array(pil_image)
        img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        self._import_from_image(img_bgr)

    def delete_account(self):
        selected = self.tree.selection()
        if not selected: return
        for item in selected:
            acc_id = int(item)
            account = next((acc for acc in self.accounts if acc["id"] == acc_id), None)
            if account:
                logging.info(f"删除账户: {account['name']}")
            delete_account_from_db(acc_id)
        self.refresh_treeview()

    def copy_code(self, event):
        selected = self.tree.selection()
        if not selected: return
        item_values = self.tree.item(selected[0], "values")
        code = item_values[2]
        if code and code not in ["------", "错误"]:
            self.root.clipboard_clear()
            self.root.clipboard_append(code)
            logging.info(f"用户复制了验证码 (账户: {item_values[1]})")
            self.root.title(f"py 2FA - 已复制: {code}")
            self.root.after(2000, lambda: self.root.title("py 2FA"))

    def generate_totp(self, secret):
        key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
        counter = int(get_current_time() // 30)
        counter_bytes = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0F
        binary_code = struct.unpack(">I", hmac_digest[offset:offset+4])[0] & 0x7FFFFFFF
        otp = binary_code % 1000000
        return f"{otp:06d}"

    def update_codes(self):
        now = get_current_time()
        for item in self.tree.get_children():
            acc_id = int(item)
            account = next((acc for acc in self.accounts if acc["id"] == acc_id), None)
            if not account:
                continue

            period = int(account.get("period") or 30)
            digits = int(account.get("digits") or 6)
            algorithm = account.get("algorithm", "SHA1")
            remaining = period - int(now % period)
            issuer_disp = account.get("issuer") or "-"

            try:
                code = generate_totp_ex(account["secret"], algorithm, digits, period)
            except Exception as e:
                logging.error(f"生成验证码失败 ({account['name']}): {e}")
                code = "错误"

            self.tree.item(item, values=(issuer_disp, account["name"], code, f"{remaining}s"))

        self.root.after(1000, self.update_codes)

    def generate_qr_for_selected(self):
        target = None
        selected = self.tree.selection()
        if selected:
            acc_id = int(selected[0])
            target = next((acc for acc in self.accounts if acc["id"] == acc_id), None)

        if target is not None:
            url = target.get("otpauth_url") or build_otpauth_url(
                target["name"], target["secret"], target.get("issuer", ""),
                target.get("algorithm", "SHA1"), target.get("digits", 6), target.get("period", 30))
            show_qr_window(self.root, url, target["name"])
            logging.info(f"生成二维码: {target['name']}")
            return

        messagebox.showinfo("提示", "请先在列表中选中一个账户，\n然后点击「🔳 生成二维码」。")

# ================= 托盘 & 主入口 =================
_tray_icon = None
_tray_queue = queue.Queue()


def _make_tray_image():
    from PIL import Image, ImageDraw
    img = Image.new('RGB', (64, 64), (26, 35, 50))
    d = ImageDraw.Draw(img)
    d.ellipse((4, 4, 60, 60), fill=(70, 170, 100))
    d.ellipse((10, 10, 54, 54), fill=(26, 35, 50))
    d.text((22, 26), "2F", fill=(220, 240, 220))
    return img


def start_tray(root):
    global _tray_icon
    try:
        import pystray
    except ImportError:
        logging.warning("未安装 pystray，托盘功能不可用（pip install pystray）")
        return None

    def on_show(icon, item):
        _tray_queue.put("show")

    def on_quit(icon, item):
        _tray_queue.put("quit")

    menu = pystray.Menu(
        pystray.MenuItem("显示主界面", on_show, default=True),
        pystray.MenuItem("退出", on_quit),
    )

    try:
        icon = pystray.Icon("Mini2FAGuard", _make_tray_image(), "py 2FA", menu)
    except Exception as e:
        logging.error(f"创建托盘图标失败: {e}")
        return None

    def runner():
        try:
            icon.run()
        except Exception as e:
            logging.error(f"托盘运行失败: {e}")

    threading.Thread(target=runner, daemon=True).start()
    _tray_icon = icon
    logging.info("系统托盘已启动。")

    def poll():
        try:
            while True:
                cmd = _tray_queue.get_nowait()
                if cmd == "show":
                    try:
                        root.deiconify()
                        root.lift()
                        root.focus_force()
                    except Exception:
                        pass
                elif cmd == "quit":
                    try:
                        if _tray_icon is not None:
                            _tray_icon.stop()
                    except Exception:
                        pass
                    root.destroy()
                    return
        except queue.Empty:
            pass
        root.after(150, poll)

    root.after(200, poll)
    return icon


def on_window_close(root):
    if _tray_icon is not None:
        logging.info("窗口隐藏到系统托盘。")
        root.withdraw()
    else:
        root.destroy()


def start_main_app(root):
    root.geometry("680x560")
    root.title("py 2FA")
    app_frame = Mini2FAGuard(root)


if __name__ == "__main__":
    if not acquire_single_instance():
        sys.exit(0)

    setup_console()
    init_db()
    migrate_db()
    start_ntp_sync()

    root = tk.Tk()
    root.title("py 2FA")
    root.geometry("380x250")

    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    start_tray(root)
    root.protocol("WM_DELETE_WINDOW", lambda: on_window_close(root))

    if not get_setting('master_password_hash', ''):
        logging.info("检测到首次运行，等待用户设置主密码...")
        SetupPasswordFrame(root, on_success=lambda: start_main_app(root))
    else:
        logging.info("等待用户输入密码解锁...")
        UnlockFrame(root, on_success=lambda: start_main_app(root))

    root.mainloop()

    try:
        if _tray_icon is not None:
            _tray_icon.stop()
    except Exception:
        pass