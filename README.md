# Лабораторная работа №2 — уязвимое веб-приложение, эксплойты, патч

Учебный проект по информационной безопасности. Простое веб-приложение
«Мини-гостевая книга» на чистой стандартной библиотеке Python (`http.server`,
`sqlite3` — без Flask/Django и без `pip install`), с двумя намеренно
внедрёнными уязвимостями из OWASP Top 10 (2021), скриптами их эксплуатации
и патчем в формате unified diff.
## Структура репозитория

| Файл                 | Часть | Назначение                                                        |
|----------------------|:-----:|--------------------------------------------------------------------|
| `app_vulnerable.py`  | 1     | Веб-приложение с SQL Injection и Stored XSS                       |
| `exploit_sqli.py`    | 2     | Эксплуатация SQL Injection (обход логина без пароля)              |
| `exploit_xss.py`     | 2     | Эксплуатация Stored XSS (сохранение и выполнение `<script>`)       |
| `app_patched.py`     | 3     | Та же логика, но с устранёнными уязвимостями                      |
| `patch.diff`         | 3     | `diff -u app_vulnerable.py app_patched.py` — патч в формате unified diff |

## Уязвимости и их маппинг на OWASP Top 10 (2021)

### 1. SQL Injection — `POST /login`
**Категория: A03:2021 – Injection**

Логин и пароль подставляются в SQL-запрос через f-строку:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

Если передать `username = "admin' -- "`, итоговый запрос превращается в:

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
```

`--` в SQLite — начало комментария, поэтому проверка пароля отбрасывается,
и запрос фактически выполняется как `... WHERE username = 'admin'`. Атакующий
входит как `admin`, не зная настоящего пароля.

### 2. Stored XSS — `GET/POST /guestbook`
**Категория: A03:2021 – Injection (Cross-Site Scripting)**

Содержимое сообщений гостевой книги вставляется в HTML без экранирования:

```python
f"<div><b>{row['username']}</b>: {row['content']}</div>"
```

Если сохранить сообщение `<script>...</script>`, оно попадёт в базу как есть
и будет отдано браузеру **каждого** посетителя страницы `/guestbook` —
скрипт выполнится от имени сайта (типичный сценарий — кража `document.cookie`
и угон сессии).

## Часть 1 — запуск уязвимого приложения

```bash
python3 app_vulnerable.py
```

Приложение поднимется на `http://127.0.0.1:8000/`.
Учётная запись по умолчанию: `admin` / `S3cretAdminPass!`.

## Часть 2 — эксплуатация

В отдельном терминале (сервер должен быть запущен):

```bash
python3 exploit_sqli.py
```
Скрипт сначала проверяет, что обычный вход с неверным паролем отклоняется,
затем входит как `admin`, подставив в поле логина `admin' -- `, и показывает
полученную сессионную cookie — **без знания настоящего пароля**.

```bash
python3 exploit_xss.py
```
Скрипт отправляет в гостевую книгу `<script>alert('XSS! document.cookie = ' + document.cookie)</script>`
и затем, читая страницу как обычный посетитель, убеждается, что payload
вернулся в HTML в неэкранированном виде — то есть реально выполнился бы в
браузере. Это же можно увидеть глазами, открыв
`http://127.0.0.1:8000/guestbook` в браузере.

## Часть 3 — патч

`app_patched.py` устраняет обе уязвимости:

- **SQLi → параметризованный запрос.** Значения передаются отдельно от
  текста запроса через `?`, драйвер `sqlite3` сам безопасно их экранирует:
  ```python
  query = "SELECT * FROM users WHERE username = ? AND password = ?"
  user = conn.execute(query, (username, password)).fetchone()
  ```
- **XSS → экранирование вывода.** Перед вставкой в HTML пользовательский
  ввод пропускается через `html.escape()`, так что `<script>` отображается
  как текст, а не исполняется:
  ```python
  f"<div><b>{html.escape(row['username'])}</b>: {html.escape(row['content'])}</div>"
  ```

Полный диф — в `patch.diff`. Применить его к уязвимой версии можно так:

```bash
patch -p0 app_vulnerable.py -i patch.diff -o app_patched_from_diff.py
diff app_patched_from_diff.py app_patched.py   # пусто => патч применился идентично
```

### Проверка, что патч действительно закрывает уязвимости

Остановите `app_vulnerable.py`, запустите вместо него `app_patched.py`
(тот же адрес `127.0.0.1:8000`) и повторно выполните те же эксплойты:

```bash
python3 app_patched.py
# в другом терминале:
python3 exploit_sqli.py   # теперь вернёт 200 и "Неверный логин или пароль"
python3 exploit_xss.py    # теперь payload придёт в экранированном виде (&lt;script&gt;...)
```

Оба скрипта эксплуатации сами сообщают об успехе/неуспехе — ничего
дополнительно менять в них не нужно.

## Дополнительно (не входит в патч, но стоит иметь в виду)

Пароли в БД хранятся в открытом виде (`A02:2021 – Cryptographic Failures`).
Это не эксплуатировалось в части 2 и поэтому не входит в `patch.diff`, но в
реальном проекте стоило бы хранить хеши паролей (например, через
`hashlib.pbkdf2_hmac` или `bcrypt`), а не исправлять только две
рассмотренные уязвимости.

## Публикация в GitHub/GitLab

```bash
git init
git add .
git commit -m "Lab 2: vulnerable app (SQLi + stored XSS), exploits, patch"
git branch -M main
git remote add origin <ссылка-на-ваш-репозиторий>
git push -u origin main
```
