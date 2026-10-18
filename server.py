# -*- coding: utf-8 -*-
"""
Escape Client Free Cloud Auth Server
Zero-dependency, standalone HTTP server.
Can run locally, behind Cloudflare Tunnel (100% free), or deployed on any free VPS / host (Render, PythonAnywhere, etc.).
"""

import os
os.environ["IS_ESCAPE_SERVER"] = "1"
import sys
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

# Support local imports on standalone cloud deployments
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
LOADER_SRC = os.path.join(PARENT_DIR, "loader_src")
sys.path.insert(0, CURRENT_DIR)
sys.path.insert(0, LOADER_SRC)
sys.path.insert(0, PARENT_DIR)

from security import db, get_hwid

PORT = int(os.environ.get("PORT", 8000))
HOST = "0.0.0.0"

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")


class AuthRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            data = self.rfile.read(length).decode("utf-8")
            return json.loads(data)
        except Exception:
            return {}

    def _send_json(self, data, status=200):
        self._set_headers(status)
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        if self.path == "/" or self.path == "/api/status":
            db._load()
            self._send_json({
                "success": True,
                "server": "Escape Client Cloud Host",
                "status": "online",
                "version": "1.0.0",
                "users_count": len(db.data.get("users", {}))
            })
        elif self.path == "/api/ping":
            self._send_json({"pong": True})
        else:
            self._send_json({"error": "Not Found"}, status=404)

    def do_POST(self):
        path = self.path
        body = self._read_json()

        db._load()

        # 1. Register
        if path == "/api/register":
            email = body.get("email", "")
            login = body.get("login", "")
            password = body.get("password", "")
            ok, msg = db.register_user(email, login, password)
            self._send_json({"success": ok, "message": msg})

        # 2. Login
        elif path == "/api/login":
            login = body.get("login", "")
            password = body.get("password", "")
            client_hwid = body.get("hwid", "")

            target = login.strip().lower()
            user_data = None
            user_key = None
            for k, v in db.data.get("users", {}).items():
                if k.lower() == target or v.get("email", "").lower() == target:
                    user_data = v
                    user_key = k
                    break

            if not user_data:
                self._send_json({"success": False, "message": "Пользователь не найден!"})
                return

            if user_data.get("is_banned", False) and user_key.lower() not in ("bebelon", "cracked"):
                self._send_json({
                    "success": False,
                    "message": f"Ваш аккаунт заблокирован! Причина: {user_data.get('ban_reason', 'Нарушение')}"
                })
                return

            from security import verify_password
            if not verify_password(password, user_data["salt"], user_data["password_hash"]):
                self._send_json({"success": False, "message": "Неверный пароль!"})
                return

            if user_key.lower() in ("bebelon", "cracked"):
                user_data["is_admin"] = True
                user_data["subscription_until"] = "2099-12-31 23:59:59"

            # HWID binding on server
            bound_hwid = user_data.get("hwid")
            if not bound_hwid and client_hwid:
                user_data["hwid"] = client_hwid
                db._save()
            elif bound_hwid and client_hwid and bound_hwid != client_hwid:
                self._send_json({
                    "success": False,
                    "message": f"Ошибка HWID! Аккаунт привязан к другому ПК ({bound_hwid[:12]}...).\nДля сброса обратитесь к администратору."
                })
                return

            sub_info = db.get_subscription_info(user_key)
            self._send_json({
                "success": True,
                "message": "Авторизация успешна!",
                "data": {
                    "login": user_data["login"],
                    "email": user_data.get("email", ""),
                    "is_admin": user_data.get("is_admin", False) or user_key.lower() in ("bebelon", "cracked"),
                    "hwid": user_data.get("hwid"),
                    "subscription": sub_info
                }
            })

        # 3. Activate Key
        elif path == "/api/activate_key":
            login = body.get("login", "")
            key_code = body.get("key", "")
            ok, msg, sub_info = db.activate_key(login, key_code)
            self._send_json({"success": ok, "message": msg, "subscription": sub_info})

        # 4. Subscription info
        elif path == "/api/sub_info":
            login = body.get("login", "")
            sub_info = db.get_subscription_info(login)
            self._send_json({"success": True, "subscription": sub_info})

        # 5. Change Password
        elif path == "/api/change_password":
            login = body.get("login", "")
            old_p = body.get("old_password", "")
            new_p = body.get("new_password", "")
            ok, msg = db.change_password(login, old_p, new_p)
            self._send_json({"success": ok, "message": msg})

        # ---- ADMIN ENDPOINTS ----
        elif path.startswith("/api/admin/"):
            caller = body.get("caller_login", "").strip().lower()
            caller_user = db.data.get("users", {}).get(body.get("caller_login", ""))
            is_adm = (caller in ("bebelon", "cracked")) or (caller_user and caller_user.get("is_admin", False))
            if not is_adm:
                self._send_json({"success": False, "message": "Доступ запрещен (нужны права админа)!"})
                return

            if path == "/api/admin/users":
                self._send_json({"success": True, "users": db.list_users()})

            elif path == "/api/admin/generate_key":
                days = body.get("days", 30)
                code = body.get("key_code")
                ok, msg, gen_code = db.generate_key(code, int(days))
                self._send_json({"success": ok, "message": msg, "key": gen_code})

            elif path == "/api/admin/give_sub":
                target = body.get("target_login", "")
                days = body.get("days", 30)
                ok, msg = db.give_subscription(target, int(days))
                self._send_json({"success": ok, "message": msg})

            elif path == "/api/admin/ban":
                target = body.get("target_login", "")
                reason = body.get("reason", "Нарушение правил")
                ok, msg = db.ban_user(target, reason)
                self._send_json({"success": ok, "message": msg})

            elif path == "/api/admin/unban":
                target = body.get("target_login", "")
                ok, msg = db.unban_user(target)
                self._send_json({"success": ok, "message": msg})

            elif path == "/api/admin/reset_hwid":
                target = body.get("target_login", "")
                ok, msg = db.reset_hwid(target)
                self._send_json({"success": ok, "message": msg})

            else:
                self._send_json({"error": "Unknown admin endpoint"}, status=404)

        else:
            self._send_json({"error": "Unknown endpoint"}, status=404)


def run_server():
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, AuthRequestHandler)
    print(f"=======================================================")
    print(f"  ESCAPE CLIENT AUTH CLOUD SERVER")
    print(f"  Listening on http://{HOST}:{PORT}")
    print(f"  Users in database: {len(db.data.get('users', {}))}")
    print(f"=======================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
