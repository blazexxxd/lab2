"""
app_vulnerable.py — Лабораторная работа №2, Часть 1 (УЯЗВИМАЯ версия)
======================================================================

Простое веб-приложение «Мини-гостевая книга», написанное с нуля на
стандартной библиотеке Python (http.server, sqlite3) — без внешних
зависимостей, pip install не требуется.

Намеренно содержит 2 уязвимости из OWASP Top 10 (2021), обе относятся
к категории A03:2021 — Injection:

  [1] SQL Injection — в обработчике POST /login: логин и пароль
      подставляются в SQL-запрос через f-строку вместо параметризованного
      запроса.

  [2] Stored Cross-Site Scripting (XSS) — в обработчике GET /guestbook:
      содержимое сообщений вставляется в HTML-ответ без экранирования.

ВНИМАНИЕ: приложение создано ИСКЛЮЧИТЕЛЬНО в учебных целях.
Запускайте его только локально или в изолированной виртуальной машине,
никогда — в открытом/боевом окружении и никогда против чужих систем.

Запуск:
    python3 app_vulnerable.py
Приложение доступно на http://127.0.0.1:8000/
Учётная запись по умолчанию: admin / S3cretAdminPass!
"""

import html
import secrets
import sqlite3
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

MODE = "VULNERABLE"
DB_PATH = "lab2.db"
HOST, PORT = "127.0.0.1", 8000

# Простейшее хранилище сессий в памяти: token -> username
SESSIONS = {}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE NOT NULL,
               password TEXT NOT NULL
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS messages (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT NOT NULL,
               content TEXT NOT NULL
           )"""
    )
    if conn.execute("SELECT 1 FROM users WHERE username = ?", ("admin",)).fetchone() is None:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", "S3cretAdminPass!"),
        )
    conn.commit()
    conn.close()


PAGE_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body>
<nav>
  <a href="/">Главная</a> | <a href="/guestbook">Гостевая книга</a> | {nav_extra}
</nav>
<hr>
{body}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"

    # ---------- вспомогательные методы ----------

    def _send(self, body, status=200, extra_headers=None):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(encoded)

    def _current_user(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        jar = SimpleCookie()
        jar.load(cookie_header)
        if "session" in jar:
            return SESSIONS.get(jar["session"].value)
        return None

    def _render(self, title, body):
        user = self._current_user()
        if user:
            nav_extra = f"Вы вошли как {html.escape(user)} | <a href='/logout'>Выйти</a>"
        else:
            nav_extra = "<a href='/login'>Войти</a>"
        return PAGE_TEMPLATE.format(title=title, nav_extra=nav_extra, body=body)

    def _read_post_params(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return parse_qs(raw)

    # ---------- GET ----------

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            body = "<h1>Мини-гостевая книга</h1><p>Демо-приложение для лабораторной работы №2.</p>"
            self._send(self._render("Главная", body))

        elif path == "/login":
            body = """<h1>Вход</h1>
            <form method="post" action="/login">
              Логин: <input type="text" name="username"><br>
              Пароль: <input type="password" name="password"><br>
              <input type="submit" value="Войти">
            </form>"""
            self._send(self._render("Вход", body))

        elif path == "/logout":
            cookie_header = self.headers.get("Cookie")
            if cookie_header:
                jar = SimpleCookie()
                jar.load(cookie_header)
                if "session" in jar:
                    SESSIONS.pop(jar["session"].value, None)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")
            self.end_headers()

        elif path == "/guestbook":
            conn = get_db()
            rows = conn.execute(
                "SELECT username, content FROM messages ORDER BY id DESC"
            ).fetchall()
            conn.close()

            # ========================= [УЯЗВИМОСТЬ] STORED XSS =========================
            # Содержимое сообщений (username и content) вставляется в HTML
            # БЕЗ экранирования html.escape(). Если атакующий сохранит
            # <script>...</script>, этот код выполнится в браузере каждого,
            # кто откроет страницу /guestbook (кража cookie, сессии и т.п.).
            messages_html = "".join(
                f"<div><b>{row['username']}</b>: {row['content']}</div>"
                for row in rows
            )
            # =============================================================================

            body = f"""<h1>Гостевая книга</h1>
            <form method="post" action="/guestbook">
              <textarea name="content" placeholder="Оставьте сообщение"></textarea><br>
              <input type="submit" value="Отправить">
            </form>
            <hr>
            {messages_html}"""
            self._send(self._render("Гостевая книга", body))

        else:
            self._send("<h1>404 Not Found</h1>", status=404)

    # ---------- POST ----------

    def do_POST(self):
        path = urlparse(self.path).path
        params = self._read_post_params()

        if path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            # ========================= [УЯЗВИМОСТЬ] SQL INJECTION =========================
            # Логин и пароль подставляются прямо в текст SQL-запроса через
            # f-строку вместо параметризованного запроса. Это позволяет
            # атакующему изменить логику запроса, например, передав
            # username = "admin' -- " — тогда проверка пароля будет
            # закомментирована символами "--".
            query = (
                f"SELECT * FROM users WHERE username = '{username}' "
                f"AND password = '{password}'"
            )
            conn = get_db()
            try:
                user = conn.execute(query).fetchone()
            except sqlite3.Error as exc:
                conn.close()
                self._send(self._render("Вход", f"<p>Ошибка запроса: {html.escape(str(exc))}</p>"))
                return
            conn.close()
            # ================================================================================

            if user:
                token = secrets.token_hex(16)
                SESSIONS[token] = user["username"]
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", f"session={token}; Path=/")
                self.end_headers()
            else:
                self._send(self._render("Вход", "<p>Неверный логин или пароль</p>"))

        elif path == "/guestbook":
            user = self._current_user() or "anonymous"
            content = params.get("content", [""])[0]
            conn = get_db()
            conn.execute(
                "INSERT INTO messages (username, content) VALUES (?, ?)",
                (user, content),
            )
            conn.commit()
            conn.close()
            self.send_response(302)
            self.send_header("Location", "/guestbook")
            self.end_headers()

        else:
            self._send("<h1>404 Not Found</h1>", status=404)

    def log_message(self, fmt, *args):
        pass  # отключаем стандартный вывод лога запросов в консоль


if __name__ == "__main__":
    init_db()
    print(f"[{MODE}] Сервер запущен: http://{HOST}:{PORT}/  (admin / S3cretAdminPass!)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
