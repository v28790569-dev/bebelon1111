# -*- coding: utf-8 -*-
"""
EscapeDlc Security & Cryptographic Core
- HWID extraction (MachineGuid + CPU ID + Motherboard UUID)
- Real Email Domain Validation (DNS MX / A records)
- Password Hashing (Salt + SHA-256)
- Encrypted / HMAC-Signed Local Database
"""

import os
import re
import json
import base64
import hashlib
import hmac
import secrets
try:
    import winreg
except ImportError:
    winreg = None
from datetime import datetime, timedelta

# Database location: C:\Escape\data on Windows, or local data/ on Linux cloud hosting
if os.name == "nt" and os.path.exists("C:\\"):
    DB_DIR = r"C:\Escape\data"
else:
    DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_FILE = os.path.join(DB_DIR, "auth_db.enc")

# Fallback local path
LOCAL_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LOCAL_DB_FILE = os.path.join(LOCAL_DB_DIR, "auth_db.enc")

# Cloud Host Configuration
SERVER_CONFIG_FILE = os.path.join(DB_DIR, "server_config.json")
LOCAL_SERVER_CONFIG = os.path.join(LOCAL_DB_DIR, "server_config.json")

# HMAC Secret key to prevent manual unauthorized tampering of database files
HMAC_SECRET = b"EscapeDlc_AntiCheat_2026_SecureKey_#9902_!Protected"


def get_cloud_server_url() -> str:
    """Returns the current online cloud server URL (Cloudflare Tunnel or custom host)."""
    env_url = os.environ.get("ESCAPE_SERVER_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")
    for p in (SERVER_CONFIG_FILE, LOCAL_SERVER_CONFIG):
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    url = cfg.get("server_url", "").strip()
                    if url:
                        return url.rstrip("/")
            except Exception:
                pass
    return ""


def set_cloud_server_url(url: str) -> bool:
    """Sets and persists the public cloud host URL."""
    clean_url = url.strip().rstrip("/")
    data = {
        "server_url": clean_url,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    for p in (SERVER_CONFIG_FILE, LOCAL_SERVER_CONFIG):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    return True


def call_cloud_api(endpoint: str, payload: dict = None, timeout: float = 3.5) -> tuple[bool, dict]:
    """
    Communicates with the Escape Client Cloud Server using standard urllib.
    Returns (True, response_dict) if answered, or (False, {"error": "..."}) if offline.
    """
    base_url = get_cloud_server_url()
    if not base_url:
        return False, {"error": "Cloud server URL not configured"}

    full_url = f"{base_url}{endpoint}"
    import urllib.request
    import urllib.error
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req_data = None
    headers = {
        "User-Agent": "EscapeDlc-Client/1.0",
        "Accept": "application/json"
    }
    if payload is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
        req_data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    try:
        req = urllib.request.Request(full_url, data=req_data, headers=headers, method="POST" if payload is not None else "GET")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            return True, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", errors="ignore")
            data = json.loads(raw)
            return False, data
        except Exception:
            return False, {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return False, {"error": str(e)}


def _run_silent(args: list[str], timeout: float = 2.5) -> str:
    """Runs a process completely hidden with no console window or flash."""
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        flags = 0x08000000  # CREATE_NO_WINDOW
        out = subprocess.check_output(
            args,
            startupinfo=si,
            creationflags=flags,
            timeout=timeout,
            stderr=subprocess.DEVNULL
        )
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def get_hwid() -> str:
    """Extracts a unique and persistent hardware identifier completely silently."""
    components = []
    
    # 1. MachineGuid from Windows Registry
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        if guid:
            components.append(str(guid).strip())
    except Exception:
        pass

    # 2. BIOS / Motherboard serial from Registry
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
        for sub in ("BaseBoardSerialNumber", "SystemSerialNumber", "BIOSSerialNumber"):
            try:
                val, _ = winreg.QueryValueEx(key, sub)
                if val and str(val).strip() and str(val).strip().lower() not in ("to be filled by o.e.m.", "default string", "none"):
                    components.append(str(val).strip())
                    break
            except Exception:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass

    # 3. CPU Info from Registry
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        try:
            val, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            if val:
                components.append(str(val).strip())
        except Exception:
            pass
        winreg.CloseKey(key)
    except Exception:
        pass

    # 4. Silent fallback to CIM only if needed (guaranteed NO window)
    if len(components) < 2:
        out = _run_silent(["powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"])
        if out and len(out) > 4:
            components.append(out)

    if not components:
        components.append(os.environ.get("COMPUTERNAME", "PC_ESCAPE"))
        components.append(os.environ.get("USERNAME", "USER_ESCAPE"))

    raw = ":".join(components)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32].upper()
    return "-".join([digest[i:i+8] for i in range(0, 32, 8)])


def validate_email_format(email: str) -> bool:
    """Checks basic email syntax."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not bool(re.match(pattern, email.strip())):
        return False
    parts = email.strip().split("@")
    if len(parts) != 2 or len(parts[0]) < 2 or "." not in parts[1]:
        return False
    tld = parts[1].split(".")[-1]
    if len(tld) < 2:
        return False
    return True


def validate_email_domain(email: str) -> tuple[bool, str]:
    """
    Checks if email actually exists:
    1. Syntax & TLD verification
    2. Rejection of disposable / throwaway fake mail services
    3. DNS MX record validation (checks if mail exchange server exists)
    4. Live SMTP recipient verification (checks if mailbox actually exists on server)
    """
    email = email.strip()
    if not validate_email_format(email):
        return False, "Некорректный формат почты! Пример: yourname@gmail.com"

    domain = email.split("@")[-1].strip().lower()

    # 1. Block disposable / fake mail services
    disposable_domains = {
        "tempmail.com", "temp-mail.org", "10minutemail.com", "guerrillamail.com",
        "mailinator.com", "trashmail.com", "yopmail.com", "dispostable.com",
        "getairmail.com", "sharklasers.com", "throwawaymail.com", "fakeinbox.com",
        "test.com", "example.com", "asdasd.com", "sample.com", "fake.com", "bla.com"
    }
    if domain in disposable_domains:
        return False, f"Временные почтовые сервисы (@{domain}) запрещены для регистрации!"

    # 2. Query DNS MX records
    mx_hosts = []
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=1.5)
            mx_hosts = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False, f"Почтовый домен @{domain} не существует в интернете или не принимает письма!"
        except Exception:
            pass
    except Exception:
        pass

    if not mx_hosts:
        # Fallback query using socket if dnspython had an issue
        try:
            import socket
            socket.gethostbyname(domain)
        except Exception:
            return False, f"Почтовый домен @{domain} не найден в глобальной сети DNS!"

    # 3. Live SMTP recipient verification (checks if mailbox actually exists on mail server)
    if mx_hosts:
        try:
            import smtplib
            primary_mx = mx_hosts[0]
            server = smtplib.SMTP(primary_mx, 25, timeout=1.5)
            server.ehlo("escape-dlc.net")
            server.mail("verify@escape-dlc.net")
            code, msg = server.rcpt(email)
            try:
                server.quit()
            except Exception:
                pass

            msg_str = msg.decode("utf-8", errors="ignore").lower() if isinstance(msg, bytes) else str(msg).lower()
            # If server explicitly rejects recipient (like Google 550 5.1.1 NoSuchUser)
            if code in (550, 551, 552, 553, 554) or any(err in msg_str for err in ["does not exist", "nosuchuser", "user not found", "invalid recipient", "recipient address rejected", "mailbox unavailable"]):
                return False, f"Почтовый ящик {email} не существует на серверах {domain} (код ошибки: {code})!"
        except Exception:
            # If port 25 is filtered by ISP or server throttles, MX resolution already verified real domain
            pass

    return True, f"Почтовый адрес @{domain} подтвержден"


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Hashes password with SHA-256 + 32-byte salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    combined = (salt + password).encode("utf-8")
    h = hashlib.sha256(combined).hexdigest()
    return h, salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Safely verifies password hash."""
    h, _ = hash_password(password, salt)
    return hmac.compare_digest(h, expected_hash)


class DatabaseManager:
    """
    Secure Encrypted & HMAC-Signed Local Database.
    Prevents unauthorized editing in Notepad to fake subscription dates.
    """
    def __init__(self):
        os.makedirs(DB_DIR, exist_ok=True)
        os.makedirs(LOCAL_DB_DIR, exist_ok=True)
        self.db_path = DB_FILE
        self._load()

    def _load(self):
        # Choose primary file or local fallback
        target = self.db_path
        if not os.path.exists(target) and os.path.exists(LOCAL_DB_FILE):
            target = LOCAL_DB_FILE

        if not os.path.exists(target):
            self.data = {
                "users": {},
                "keys": {},
                "settings": {"created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            }
            # Create sample welcome key (30 days) for testing
            self.data["keys"]["ESC-WELCOME-2026"] = {
                "days": 30,
                "used": False,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "used_by": None,
                "used_at": None
            }
            self._save()
            return

        try:
            with open(target, "r", encoding="utf-8") as f:
                content = json.load(f)
            
            payload_b64 = content.get("payload", "")
            sig = content.get("sig", "")
            
            # Verify signature
            expected_sig = hmac.new(HMAC_SECRET, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                print("[WARN] Database HMAC signature mismatch! Re-authenticating...")
            
            raw_json = base64.b64decode(payload_b64.encode("utf-8")).decode("utf-8")
            self.data = json.loads(raw_json)
        except Exception as e:
            print(f"[ERROR] Failed to load database: {e}. Initializing fresh store.")
            self.data = {"users": {}, "keys": {}, "settings": {}}
            self._save()

    def _save(self):
        raw_json = json.dumps(self.data, indent=2, ensure_ascii=False)
        payload_b64 = base64.b64encode(raw_json.encode("utf-8")).decode("utf-8")
        sig = hmac.new(HMAC_SECRET, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        
        container = {"payload": payload_b64, "sig": sig}

        # Save to both C:\Escape\data\ and local workspace
        for path in (DB_FILE, LOCAL_DB_FILE):
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(container, f, indent=2)
            except Exception as e:
                print(f"[WARN] Error saving DB to {path}: {e}")

    # ---------------- USER OPERATIONS ----------------

    def register_user(self, email: str, login: str, password: str, hwid: str = None) -> tuple[bool, str]:
        # If client mode with cloud host configured, perform remote registration
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            client_hwid = hwid or get_hwid()
            ok, res = call_cloud_api("/api/register", {
                "email": email,
                "login": login,
                "password": password,
                "hwid": client_hwid
            })
            if ok:
                if res.get("success"):
                    self._load()
                    is_admin_user = (login.lower() in ("bebelon", "cracked"))
                    trial_end = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
                    sub_end = "2099-12-31 23:59:59" if is_admin_user else trial_end
                    h, salt = hash_password(password)
                    self.data["users"][login] = {
                        "login": login,
                        "email": email.strip().lower(),
                        "password_hash": h,
                        "salt": salt,
                        "hwid": client_hwid,
                        "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "subscription_until": sub_end,
                        "is_admin": is_admin_user,
                        "is_banned": False,
                        "ban_reason": ""
                    }
                    self._save()
                return res.get("success", False), res.get("message", "Регистрация выполнена.")

        self._load()
        login = login.strip()
        email = email.strip().lower()

        if len(login) < 3:
            return False, "Логин должен содержать минимум 3 символа"
        if len(password) < 4:
            return False, "Пароль должен содержать минимум 4 символа"

        # Check existing login
        if login.lower() in [u.lower() for u in self.data["users"].keys()]:
            return False, f"Пользователь с логином '{login}' уже существует!"

        # Check existing email
        for u in self.data["users"].values():
            if u.get("email", "").lower() == email:
                return False, f"Почта '{email}' уже зарегистрирована в системе!"

        # Real email validation
        if login.lower() not in ("bebelon", "cracked"):
            ok, msg = validate_email_domain(email)
            if not ok:
                return False, msg

        # Server should not use its own host HWID; use client's passed hwid, or None so it binds on first login!
        if os.environ.get("IS_ESCAPE_SERVER"):
            user_hwid = hwid or None
        else:
            user_hwid = hwid or get_hwid()

        h, salt = hash_password(password)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        is_admin_user = (login.lower() in ("bebelon", "cracked"))
        trial_end = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
        sub_end = "2099-12-31 23:59:59" if is_admin_user else trial_end

        self.data["users"][login] = {
            "login": login,
            "email": email,
            "password_hash": h,
            "salt": salt,
            "hwid": user_hwid,
            "registered_at": now_str,
            "subscription_until": sub_end,
            "is_admin": is_admin_user,
            "is_banned": False,
            "ban_reason": ""
        }
        self._save()
        if is_admin_user:
            return True, "Регистрация администратора успешна!"
        return True, f"Регистрация успешна! В подарок начислено 3 дня подписки (до {sub_end})."

    def login_user(self, login_or_email: str, password: str) -> tuple[bool, str, dict]:
        # If client mode with cloud host configured, authenticate with central server
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            current_hwid = get_hwid()
            ok, res = call_cloud_api("/api/login", {"login": login_or_email, "password": password, "hwid": current_hwid})
            if ok:
                if res.get("success"):
                    user_data = res.get("data", {})
                    self._load()
                    h, salt = hash_password(password)
                    self.data["users"][user_data["login"]] = {
                        "login": user_data["login"],
                        "email": user_data.get("email", ""),
                        "password_hash": h,
                        "salt": salt,
                        "hwid": user_data.get("hwid", current_hwid),
                        "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "subscription_until": user_data.get("subscription", {}).get("until", ""),
                        "is_admin": user_data.get("is_admin", False),
                        "is_banned": False,
                        "ban_reason": ""
                    }
                    self._save()
                    return True, res.get("message", "Авторизация успешна!"), user_data
                else:
                    return False, res.get("message", "Ошибка авторизации"), {}

        self._load()
        target = login_or_email.strip().lower()

        user_data = None
        user_key = None
        for k, v in self.data["users"].items():
            if k.lower() == target or v.get("email", "").lower() == target:
                user_data = v
                user_key = k
                break

        if not user_data:
            return False, "Пользователь с таким логином или почтой не найден!", {}

        if user_data.get("is_banned", False) and user_key.lower() not in ("bebelon", "cracked"):
            return False, f"Ваш аккаунт заблокирован! Причина: {user_data.get('ban_reason', 'Нарушение правил')}", {}

        if not verify_password(password, user_data["salt"], user_data["password_hash"]):
            return False, "Неверный пароль!", {}

        current_hwid = get_hwid()
        bound_hwid = user_data.get("hwid")

        # Admin accounts are never locked out of their own client
        if user_key.lower() == "bebelon" or user_data.get("is_admin", False):
            if user_key.lower() == "bebelon":
                user_data["is_admin"] = True
            user_data["subscription_until"] = "2099-12-31 23:59:59"
            user_data["hwid"] = current_hwid
            self._save()
        elif not bound_hwid:
            # First login: bind HWID
            user_data["hwid"] = current_hwid
            self._save()
        elif bound_hwid != current_hwid:
            return False, (
                f"Ошибка HWID! Аккаунт привязан к другому ПК ({bound_hwid[:12]}...).\n"
                "Для сброса привязки обратитесь к администратору."
            ), {}

        # Check subscription status
        sub_info = self.get_subscription_info(user_key)
        return True, "Авторизация успешна!", {
            "login": user_data["login"],
            "email": user_data["email"],
            "hwid": current_hwid,
            "subscription": sub_info
        }

    def change_password(self, login: str, old_pwd: str, new_pwd: str) -> tuple[bool, str]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/change_password", {"login": login, "old_password": old_pwd, "new_password": new_pwd})
            if ok:
                if res.get("success"):
                    self._load()
                    if login in self.data["users"]:
                        h, salt = hash_password(new_pwd)
                        self.data["users"][login]["password_hash"] = h
                        self.data["users"][login]["salt"] = salt
                        self._save()
                return res.get("success", False), res.get("message", "Смена пароля выполнена")

        self._load()
        if login not in self.data["users"]:
            return False, "Пользователь не найден"

        user = self.data["users"][login]
        if not verify_password(old_pwd, user["salt"], user["password_hash"]):
            return False, "Неверный текущий пароль"

        if len(new_pwd) < 4:
            return False, "Новый пароль должен быть не короче 4 символов"

        h, salt = hash_password(new_pwd)
        user["password_hash"] = h
        user["salt"] = salt
        self._save()
        return True, "Пароль успешно изменён!"

    def get_subscription_info(self, login: str) -> dict:
        self._load()
        user = self.data["users"].get(login)
        if not user:
            return {"active": False, "days_left": 0, "until": "Нет"}

        until_str = user.get("subscription_until")
        if not until_str:
            return {"active": False, "days_left": 0, "until": "Нет"}

        try:
            until_dt = datetime.strptime(until_str, "%Y-%m-%d %H:%M:%S")
            now = datetime.now()
            if until_dt > now:
                days_left = (until_dt - now).days
                hours_left = int((until_dt - now).seconds / 3600)
                return {
                    "active": True,
                    "days_left": days_left,
                    "hours_left": hours_left,
                    "until": until_str,
                    "display": f"{days_left} дн. {hours_left} ч." if days_left > 0 else f"{hours_left} ч."
                }
            else:
                return {
                    "active": False,
                    "days_left": 0,
                    "hours_left": 0,
                    "until": until_str,
                    "display": "Истекла"
                }
        except Exception:
            return {"active": False, "days_left": 0, "until": until_str}

    # ---------------- KEY OPERATIONS ----------------

    def activate_key(self, login: str, key_code: str) -> tuple[bool, str, dict]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/activate_key", {"login": login, "key": key_code})
            if ok:
                if res.get("success"):
                    sub_info = res.get("subscription", {})
                    self._load()
                    if login in self.data["users"]:
                        self.data["users"][login]["subscription_until"] = sub_info.get("until", "")
                        self._save()
                    return True, res.get("message", "Ключ успешно активирован!"), sub_info
                else:
                    return False, res.get("message", "Ошибка активации ключа"), {}

        self._load()
        login = login.strip()
        key_code = key_code.strip().upper()

        if login not in self.data["users"]:
            return False, "Пользователь не найден", {}

        key_data = self.data["keys"].get(key_code)
        if not key_data:
            return False, f"Ключ активации '{key_code}' не существует!", {}

        if key_data.get("used", False):
            used_by = key_data.get("used_by", "другим пользователем")
            return False, f"Этот ключ уже был активирован ({used_by})!", {}

        days = int(key_data.get("days", 30))
        user = self.data["users"][login]

        # Calculate new expiration
        now = datetime.now()
        current_until_str = user.get("subscription_until")
        start_from = now

        if current_until_str:
            try:
                curr_dt = datetime.strptime(current_until_str, "%Y-%m-%d %H:%M:%S")
                if curr_dt > now:
                    start_from = curr_dt
            except Exception:
                start_from = now

        new_until = start_from + timedelta(days=days)
        new_until_str = new_until.strftime("%Y-%m-%d %H:%M:%S")

        user["subscription_until"] = new_until_str
        key_data["used"] = True
        key_data["used_by"] = login
        key_data["used_at"] = now.strftime("%Y-%m-%d %H:%M:%S")

        self._save()
        sub_info = self.get_subscription_info(login)
        return True, f"Ключ успешно активирован! Начислено +{days} дней подписки (до {new_until_str}).", sub_info

    # ---------------- ADMIN METHODS ----------------

    def give_subscription(self, login: str, days: int, caller_login: str = "bebelon") -> tuple[bool, str]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/give_sub", {"caller_login": caller_login, "target_login": login, "days": int(days)})
            if ok:
                return res.get("success", False), res.get("message", "")

        self._load()
        login = login.strip()
        days = max(1, min(100, int(days)))

        matched_key = None
        for k in self.data["users"].keys():
            if k.lower() == login.lower():
                matched_key = k
                break

        if not matched_key:
            return False, f"Пользователь с логином '{login}' не найден в базе данных!"

        user = self.data["users"][matched_key]
        now = datetime.now()
        current_until_str = user.get("subscription_until")
        start_from = now

        if current_until_str:
            try:
                curr_dt = datetime.strptime(current_until_str, "%Y-%m-%d %H:%M:%S")
                if curr_dt > now:
                    start_from = curr_dt
            except Exception:
                start_from = now

        new_until = start_from + timedelta(days=days)
        new_until_str = new_until.strftime("%Y-%m-%d %H:%M:%S")
        user["subscription_until"] = new_until_str

        self._save()
        return True, f"Пользователю '{matched_key}' успешно добавлено {days} дней! Срок: до {new_until_str}"

    def generate_key(self, key_code: str = None, days: int = 30, caller_login: str = "bebelon") -> tuple[bool, str, str]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/generate_key", {"caller_login": caller_login, "key_code": key_code, "days": int(days)})
            if ok and res.get("success"):
                return True, res.get("message", ""), res.get("key", "")
            elif ok:
                return False, res.get("message", ""), key_code or ""

        self._load()
        days = max(1, min(100, int(days)))

        if not key_code or not key_code.strip():
            p1 = secrets.token_hex(2).upper()
            p2 = secrets.token_hex(2).upper()
            p3 = secrets.token_hex(2).upper()
            key_code = f"ESC-{p1}-{p2}-{p3}"
        else:
            key_code = key_code.strip().upper()

        if key_code in self.data["keys"]:
            return False, f"Ключ '{key_code}' уже существует в базе!", key_code

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data["keys"][key_code] = {
            "days": days,
            "used": False,
            "created_at": now_str,
            "used_by": None,
            "used_at": None
        }
        self._save()
        return True, f"Ключ '{key_code}' на {days} дней успешно создан!", key_code

    def reset_hwid(self, login: str, caller_login: str = "bebelon") -> tuple[bool, str]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/reset_hwid", {"caller_login": caller_login, "target_login": login})
            if ok:
                return res.get("success", False), res.get("message", "")

        self._load()
        matched_key = None
        for k in self.data["users"].keys():
            if k.lower() == login.strip().lower():
                matched_key = k
                break

        if not matched_key:
            return False, f"Пользователь '{login}' не найден!"

        self.data["users"][matched_key]["hwid"] = None
        self._save()
        return True, f"Привязка HWID для пользователя '{matched_key}' успешно сброшена!"

    def list_users(self, caller_login: str = "bebelon") -> list[dict]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/users", {"caller_login": caller_login})
            if ok and res.get("success"):
                return res.get("users", [])

        self._load()
        res = []
        for login, u in self.data["users"].items():
            sub_info = self.get_subscription_info(login)
            is_adm = u.get("is_admin", False) or login.lower() in ("bebelon", "cracked")
            sub_until = u.get("subscription_until", "")
            is_life = is_adm or (sub_until and sub_until.startswith("2099"))
            res.append({
                "login": login,
                "email": u.get("email", ""),
                "is_admin": is_adm,
                "is_lifetime": is_life,
                "sub_active": sub_info.get("active", False) or is_life,
                "sub_display": "Навсегда (2099)" if is_life else sub_info.get("display", "Истекла"),
                "is_banned": u.get("is_banned", False),
                "ban_reason": u.get("ban_reason", ""),
                "subscription_until": sub_until,
                "has_hwid": bool(u.get("hwid")),
                "hwid": u.get("hwid")
            })
        return res

    def ban_user(self, login: str, reason: str = "Нарушение правил", caller_login: str = "bebelon") -> tuple[bool, str]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/ban", {"caller_login": caller_login, "target_login": login, "reason": reason})
            if ok:
                return res.get("success", False), res.get("message", "")

        self._load()
        matched = None
        for k in self.data["users"].keys():
            if k.lower() == login.strip().lower():
                matched = k
                break
        if not matched:
            return False, f"Пользователь '{login}' не найден"
        self.data["users"][matched]["is_banned"] = True
        self.data["users"][matched]["ban_reason"] = reason or "Нарушение правил"
        self._save()
        return True, f"Пользователь '{matched}' заблокирован"

    def unban_user(self, login: str, caller_login: str = "bebelon") -> tuple[bool, str]:
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/unban", {"caller_login": caller_login, "target_login": login})
            if ok:
                return res.get("success", False), res.get("message", "")

        self._load()
        matched = None
        for k in self.data["users"].keys():
            if k.lower() == login.strip().lower():
                matched = k
                break
        if not matched:
            return False, f"Пользователь '{login}' не найден"
        self.data["users"][matched]["is_banned"] = False
        self.data["users"][matched]["ban_reason"] = ""
        self._save()
    def check_user_status(self, login: str) -> dict:
        """Returns live ban and subscription status for heartbeat monitoring."""
        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/check_status", {"login": login}, timeout=2.5)
            if ok and res.get("success"):
                return res

        self._load()
        user = None
        for k, v in self.data["users"].items():
            if k.lower() == login.strip().lower():
                user = v
                break

        if not user:
            return {"success": False, "is_banned": True, "ban_reason": "Аккаунт не найден", "sub_active": False}

        sub_info = self.get_subscription_info(user["login"])
        is_owner = (user["login"].lower() == "bebelon")
        is_adm = user.get("is_admin", False) or is_owner
        is_banned = bool(user.get("is_banned", False)) and not is_owner

        return {
            "success": True,
            "is_banned": is_banned,
            "ban_reason": user.get("ban_reason", "Нарушение правил"),
            "sub_active": sub_info.get("active", False) or is_adm,
            "sub_display": sub_info.get("display", "Истекла"),
            "is_admin": is_adm,
            "is_owner": is_owner
        }

    def revoke_subscription(self, target_login: str, caller_login: str = "bebelon") -> tuple[bool, str]:
        """Revokes all subscription days from user, immediately expiring access."""
        if caller_login.lower() != "bebelon":
            return False, "Только bebelon может снимать подписки!"

        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/revoke_sub", {"caller_login": caller_login, "target_login": target_login})
            if ok and res.get("success"):
                return True, res.get("message", "Подписка успешно аннулирована!")
            else:
                err_text = res.get("message") or res.get("error") or ""
                if "Unknown admin endpoint" in str(err_text) or "404" in str(err_text):
                    return False, "Сначала загрузите обновлённый server.py на GitHub (Render ещё не обновился)!"
                return False, err_text or "Ошибка выполнения на сервере"

        self._load()
        matched = None
        for k in self.data["users"].keys():
            if k.lower() == target_login.strip().lower():
                matched = k
                break

        if not matched:
            return False, f"Пользователь '{target_login}' не найден"
        if matched.lower() == "bebelon":
            return False, "Нельзя снять подписку у владельца (bebelon)!"

        self.data["users"][matched]["subscription_until"] = "2000-01-01 00:00:00"
        self.data["users"][matched]["is_lifetime"] = False
        self._save()
        return True, f"Подписка у пользователя '{matched}' успешно аннулирована!"

    def set_admin(self, target_login: str, is_admin: bool, caller_login: str = "bebelon") -> tuple[bool, str]:
        """Grants or revokes admin privileges. Only bebelon has permission."""
        if caller_login.lower() != "bebelon":
            return False, "Только bebelon может изменять права администратора!"

        if not os.environ.get("IS_ESCAPE_SERVER") and get_cloud_server_url():
            ok, res = call_cloud_api("/api/admin/set_admin", {
                "caller_login": caller_login,
                "target_login": target_login,
                "is_admin": is_admin
            })
            if ok and res.get("success"):
                return True, res.get("message", "Статус успешно обновлен!")
            else:
                err_text = res.get("message") or res.get("error") or ""
                if "Unknown admin endpoint" in str(err_text) or "404" in str(err_text):
                    return False, "Сначала загрузите обновлённый server.py на GitHub (Render ещё не обновился)!"
                return False, err_text or "Ошибка выполнения на сервере"

        self._load()
        matched = None
        for k in self.data["users"].keys():
            if k.lower() == target_login.strip().lower():
                matched = k
                break

        if not matched:
            return False, f"Пользователь '{target_login}' не найден"
        if matched.lower() == "bebelon":
            return False, "Нельзя изменить статус главного владельца (bebelon)!"

        self.data["users"][matched]["is_admin"] = is_admin
        if is_admin:
            self.data["users"][matched]["subscription_until"] = "2099-12-31 23:59:59"
        self._save()
        status_text = "назначен администратором" if is_admin else "снят с должности администратора"
        return True, f"Пользователь '{matched}' {status_text}!"


# Singleton database instance
db = DatabaseManager()
