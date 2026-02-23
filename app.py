from flask import Flask, render_template, request, redirect, session, flash, url_for
from collections import defaultdict, deque
import logging
import os
import re
import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlparse

try:
    from authlib.integrations.flask_client import OAuth
except ImportError:
    OAuth = None

try:
    import redis
except ImportError:
    redis = None
from werkzeug.exceptions import RequestEntityTooLarge

from utils.auth import hash_password, verify_password
from utils.db import get_db, get_cursor, insert_and_get_id
from utils.migrations import run_migrations


app = Flask(__name__)
flask_env = os.getenv("FLASK_ENV", "").lower()
configured_secret = os.getenv("FLASK_SECRET_KEY")
database_url = os.getenv("DATABASE_URL", "").strip()
if flask_env == "production" and not configured_secret:
    raise RuntimeError("FLASK_SECRET_KEY must be set in production.")
if flask_env == "production" and not database_url:
    raise RuntimeError("DATABASE_URL must be set in production.")

app.secret_key = configured_secret or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SECURE=flask_env == "production",
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

_rate_lock = threading.Lock()
_rate_buckets = defaultdict(deque)
_redis_client = None
redis_url = os.getenv("REDIS_URL", "").strip()
trust_proxy = os.getenv("TRUST_PROXY", "0") == "1"
google_client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

if flask_env == "production" and not redis_url:
    raise RuntimeError("REDIS_URL must be set in production.")

if redis_url:
    if redis is None:
        if flask_env == "production":
            raise RuntimeError("Redis package is not installed in production.")
        logger.warning("Redis package not installed; using in-memory rate limiting in development.")
    else:
        try:
            _redis_client = redis.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                health_check_interval=30,
            )
            _redis_client.ping()
            logger.info("Redis rate limiter enabled.")
        except Exception as redis_err:
            _redis_client = None
            if flask_env == "production":
                raise RuntimeError("Unable to connect to Redis in production.") from redis_err
            logger.warning("Redis unavailable, falling back to in-memory rate limiting: %s", redis_err)

oauth = None
google_oauth_enabled = bool(google_client_id and google_client_secret and OAuth is not None)
if google_oauth_enabled:
    oauth = OAuth(app)
    oauth.register(
        name="google",
        client_id=google_client_id,
        client_secret=google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
elif flask_env == "production":
    logger.warning("Google OAuth is not fully configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")


def get_client_ip():
    if trust_proxy:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "anon"


def rate_limit(key, limit=5, window=60):
    now = time.time()
    client_ip = get_client_ip()
    user_scope = f"user:{session['user_id']}" if session.get("user_id") else f"ip:{client_ip}"
    scope = f"{key}:{user_scope}"

    if _redis_client is not None:
        redis_key = f"ratelimit:{scope}"
        try:
            current = _redis_client.incr(redis_key)
            if current == 1:
                _redis_client.expire(redis_key, window)
            return current <= limit
        except Exception as redis_err:
            logger.error("Redis rate limit failure: %s", redis_err)
            if flask_env == "production":
                return False

    with _rate_lock:
        bucket = _rate_buckets[scope]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()

        if len(bucket) >= limit:
            return False

        bucket.append(now)
        return True


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    sent_token = request.form.get("csrf_token", "")
    current_token = session.get("_csrf_token", "")
    if not (current_token and sent_token and secrets.compare_digest(sent_token, current_token)):
        return False

    origin = request.headers.get("Origin")
    if origin:
        origin_host = urlparse(origin).netloc
        if origin_host and origin_host != request.host:
            return False

    return True


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if flask_env == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_large_request(_error):
    flash("Request too large.", "error")
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.errorhandler(500)
def handle_internal_error(error):
    logger.exception("Unhandled server error: %s", error)
    flash("Something went wrong. Please try again.", "error")
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


def clean_text(value, max_len):
    return (value or "").strip()[:max_len]


def normalize_email(value):
    return clean_text(value, 120).lower()


def is_gmail_address(email):
    return bool(email and re.fullmatch(r"[a-z0-9._%+-]+@gmail\.com", email))


def unique_username_from_email(cur, email):
    base = re.sub(r"[^A-Za-z0-9_]", "_", email.split("@")[0])[:24] or "user"
    candidate = base
    suffix = 0
    while True:
        cur.execute("SELECT id FROM users WHERE username = ?", (candidate,))
        if not cur.fetchone():
            return candidate
        suffix += 1
        candidate = f"{base[:24-len(str(suffix))]}{suffix}"


def parse_quiz_code(raw_code):
    code = (raw_code or "").strip().upper()
    if re.fullmatch(r"[A-Z0-9]{6}", code):
        return code
    return None


def is_quiz_owner(cur, quiz_id, user_id):
    cur.execute("SELECT host_id FROM quizzes WHERE id = ? AND deleted_at IS NULL", (quiz_id,))
    quiz = cur.fetchone()
    return bool(quiz and quiz["host_id"] == user_id)


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz():
    try:
        db = get_db()
        cur = get_cursor(db)
        cur.execute("SELECT 1")
        db.close()
        return {"status": "ok"}, 200
    except Exception:
        logger.exception("Health check failed.")
        return {"status": "error"}, 500


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid form session. Try again.", "error")
            return redirect(url_for("register"))

        if not rate_limit("register_limit", limit=6, window=60):
            flash("Too many registration attempts. Try again in a minute.", "error")
            return redirect(url_for("register"))

        username = clean_text(request.form.get("username"), 30)
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username must be 3-30 characters and use letters, numbers, or _.", "error")
            return redirect(url_for("register"))

        if not is_gmail_address(email):
            flash("Only real Gmail addresses are allowed (example: name@gmail.com).", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("register"))

        hashed = hash_password(password)

        db = None
        try:
            db = get_db()
            cur = get_cursor(db)
            cur.execute(
                """
                INSERT INTO users (username, email, password_hash, email_verified)
                VALUES (?, ?, ?, 1)
                """,
                (username, email, hashed),
            )
            db.commit()
            flash("Account created. You can sign in now.", "success")
            return redirect(url_for("login"))

        except Exception:
            if db:
                db.rollback()
            flash("Registration failed. Username or email may already be registered.", "error")
            logger.exception("Registration failed for username=%s", username)
            return redirect(url_for("register"))
        finally:
            if db:
                db.close()

    return render_template("register.html", title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid form session. Try again.", "error")
            return redirect(url_for("login"))

        if not rate_limit("login_limit", limit=8, window=60):
            flash("Too many login attempts. Try again in a minute.", "error")
            return redirect(url_for("login"))

        login_id = clean_text(request.form.get("username"), 120)
        password = request.form.get("password", "")

        if "@" in login_id and not is_gmail_address(normalize_email(login_id)):
            flash("Only Gmail login is supported.", "error")
            return redirect(url_for("login"))

        db = get_db()
        cur = get_cursor(db)
        cur.execute(
            """
            SELECT id, username, role, password_hash, email_verified
            FROM users
            WHERE username = ? OR LOWER(email) = LOWER(?)
            """,
            (login_id, login_id),
        )
        user = cur.fetchone()
        db.close()

        if user and user["email_verified"] == 1 and verify_password(password, user["password_hash"]):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html", title="Login")


@app.route("/login/google")
def login_google():
    if not google_oauth_enabled:
        flash("Google login is not configured by the server.", "error")
        return redirect(url_for("login"))

    redirect_uri = url_for("google_auth_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_auth_callback():
    if not google_oauth_enabled:
        flash("Google login is not configured by the server.", "error")
        return redirect(url_for("login"))

    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get("userinfo")
        if not userinfo:
            userinfo = oauth.google.get("userinfo").json()
    except Exception:
        logger.exception("Google OAuth callback failed.")
        flash("Google login failed. Try again.", "error")
        return redirect(url_for("login"))

    email = normalize_email(userinfo.get("email"))
    if not userinfo.get("email_verified") or not is_gmail_address(email):
        flash("Google account must be a verified Gmail address.", "error")
        return redirect(url_for("login"))

    google_sub = clean_text(userinfo.get("sub"), 128)
    if not google_sub:
        flash("Google account response is invalid.", "error")
        return redirect(url_for("login"))

    db = get_db()
    cur = get_cursor(db)
    cur.execute(
        """
        SELECT id, username, role
        FROM users
        WHERE google_id = ? OR LOWER(email) = LOWER(?)
        """,
        (google_sub, email),
    )
    user = cur.fetchone()

    if user:
        cur.execute(
            """
            UPDATE users
            SET google_id = ?, email_verified = 1
            WHERE id = ?
            """,
            (google_sub, user["id"]),
        )
        user_id = user["id"]
        username = user["username"]
        role = user["role"]
    else:
        username = unique_username_from_email(cur, email)
        random_password_hash = hash_password(secrets.token_urlsafe(32))
        user_id = insert_and_get_id(
            cur,
            """
            INSERT INTO users (username, email, password_hash, role, google_id, email_verified)
            VALUES (?, ?, ?, 'user', ?, 1)
            """,
            (username, email, random_password_hash, google_sub),
        )
        role = "user"

    db.commit()
    db.close()

    session["user_id"] = user_id
    session["username"] = username
    session["role"] = role
    flash("Signed in with Google.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not validate_csrf():
        flash("Invalid form session. Try again.", "error")
        return redirect(url_for("dashboard"))
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    cur = get_cursor(db)

    cur.execute(
        """
        SELECT q.id, q.title, q.description, q.quiz_code, q.status,
               (SELECT COUNT(*) FROM questions WHERE quiz_id = q.id) AS question_count,
               (SELECT COUNT(*) FROM quiz_attempts WHERE quiz_id = q.id) AS attempts_count
        FROM quizzes q
        WHERE q.host_id = ? AND q.deleted_at IS NULL
        ORDER BY q.created_at DESC
        """,
        (session["user_id"],),
    )
    quizzes = cur.fetchall()

    cur.execute(
        """
        SELECT COUNT(*) AS total_quizzes,
               SUM(CASE WHEN status = 'published' THEN 1 ELSE 0 END) AS published_quizzes
        FROM quizzes
        WHERE host_id = ? AND deleted_at IS NULL
        """,
        (session["user_id"],),
    )
    quiz_stats = cur.fetchone()

    cur.execute(
        """
        SELECT COUNT(*) AS attempts,
               COALESCE(ROUND(AVG(CASE WHEN total > 0 THEN (100.0 * score / total) END), 1), 0) AS avg_percent
        FROM quiz_attempts
        WHERE user_id = ?
        """,
        (session["user_id"],),
    )
    attempt_stats = cur.fetchone()

    db.close()

    stats = {
        "total_quizzes": quiz_stats["total_quizzes"] or 0,
        "published_quizzes": quiz_stats["published_quizzes"] or 0,
        "attempts": attempt_stats["attempts"] or 0,
        "avg_percent": attempt_stats["avg_percent"] or 0,
    }

    return render_template("dashboard.html", quizzes=quizzes, stats=stats, title="Dashboard")


@app.route("/join", methods=["GET", "POST"])
@login_required
def join_quiz():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid form session. Try again.", "error")
            return redirect(url_for("join_quiz"))

        if not rate_limit("join_limit", limit=15, window=60):
            flash("Too many attempts. Try again in a minute.", "error")
            return redirect(url_for("join_quiz"))

        code = parse_quiz_code(request.form.get("quiz_code"))
        if not code:
            flash("Code format must be 6 letters/numbers.", "error")
            return redirect(url_for("join_quiz"))

        db = get_db()
        cur = get_cursor(db)
        cur.execute(
            """
            SELECT id
            FROM quizzes
            WHERE quiz_code = ? AND status = 'published' AND deleted_at IS NULL
            """,
            (code,),
        )
        quiz = cur.fetchone()
        db.close()

        if not quiz:
            flash("Quiz not found or not published.", "error")
            return redirect(url_for("join_quiz"))

        return redirect(url_for("play_quiz", quiz_id=quiz["id"]))

    return render_template("join_quiz.html", title="Join Quiz")


@app.route("/create_quiz", methods=["GET", "POST"])
@login_required
def create_quiz():
    if request.method == "POST":
        if not validate_csrf():
            flash("Invalid form session. Try again.", "error")
            return redirect(url_for("create_quiz"))

        title = clean_text(request.form.get("title"), 100)
        description = clean_text(request.form.get("description"), 300)

        if len(title) < 3:
            flash("Quiz title must be at least 3 characters.", "error")
            return redirect(url_for("create_quiz"))

        db = get_db()
        cur = get_cursor(db)
        quiz_id = insert_and_get_id(
            cur,
            """
            INSERT INTO quizzes (title, description, host_id, status)
            VALUES (?, ?, ?, 'draft')
            """,
            (title, description, session["user_id"]),
        )

        db.commit()
        db.close()

        flash("Quiz created. Add at least one question before publishing.", "success")
        return redirect(url_for("add_question", quiz_id=quiz_id))

    return render_template("create_quiz.html", title="Create Quiz")


@app.route("/add_question/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def add_question(quiz_id):
    db = get_db()
    cur = get_cursor(db)

    cur.execute("SELECT id, title FROM quizzes WHERE id = ? AND deleted_at IS NULL", (quiz_id,))
    quiz = cur.fetchone()
    if not quiz:
        db.close()
        flash("Quiz not found.", "error")
        return redirect(url_for("dashboard"))

    if not is_quiz_owner(cur, quiz_id, session["user_id"]):
        db.close()
        flash("You are not allowed to edit this quiz.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if not validate_csrf():
            db.close()
            flash("Invalid form session. Try again.", "error")
            return redirect(url_for("add_question", quiz_id=quiz_id))

        question_text = clean_text(request.form.get("question"), 500)
        raw_options = request.form.getlist("options")

        if len(raw_options) != 4:
            db.close()
            flash("Exactly 4 options are required.", "error")
            return redirect(url_for("add_question", quiz_id=quiz_id))

        options = [clean_text(option, 200) for option in raw_options]

        if len(question_text) < 5:
            db.close()
            flash("Question must be at least 5 characters.", "error")
            return redirect(url_for("add_question", quiz_id=quiz_id))

        if any(not option for option in options):
            db.close()
            flash("All option fields are required.", "error")
            return redirect(url_for("add_question", quiz_id=quiz_id))

        try:
            correct_index = int(request.form.get("correct", "-1"))
        except ValueError:
            correct_index = -1

        if correct_index < 0 or correct_index >= len(options):
            db.close()
            flash("Choose a valid correct answer.", "error")
            return redirect(url_for("add_question", quiz_id=quiz_id))

        question_id = insert_and_get_id(
            cur,
            """
            INSERT INTO questions (quiz_id, question_text)
            VALUES (?, ?)
            """,
            (quiz_id, question_text),
        )

        for index, option in enumerate(options):
            cur.execute(
                """
                INSERT INTO options (question_id, option_text, is_correct)
                VALUES (?, ?, ?)
                """,
                (question_id, option, 1 if index == correct_index else 0),
            )

        db.commit()
        flash("Question added.", "success")

    cur.execute(
        """
        SELECT id, question_text
        FROM questions
        WHERE quiz_id = ?
        ORDER BY id DESC
        """,
        (quiz_id,),
    )
    questions = cur.fetchall()

    db.close()
    return render_template(
        "add_question.html",
        quiz=quiz,
        questions=questions,
        quiz_id=quiz_id,
        title="Add Questions",
    )


@app.route("/publish_quiz/<int:quiz_id>", methods=["POST"])
@login_required
def publish_quiz(quiz_id):
    if not validate_csrf():
        flash("Invalid form session. Try again.", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    cur = get_cursor(db)

    if not is_quiz_owner(cur, quiz_id, session["user_id"]):
        db.close()
        flash("You are not allowed to publish this quiz.", "error")
        return redirect(url_for("dashboard"))

    cur.execute("SELECT COUNT(*) AS cnt FROM questions WHERE quiz_id = ?", (quiz_id,))
    question_count = cur.fetchone()["cnt"]

    if question_count < 1:
        db.close()
        flash("Add at least one question before publishing.", "error")
        return redirect(url_for("add_question", quiz_id=quiz_id))

    cur.execute("UPDATE quizzes SET status = 'published' WHERE id = ?", (quiz_id,))
    db.commit()
    db.close()

    flash("Quiz published and ready to join by code.", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete_quiz/<int:quiz_id>", methods=["POST"])
@login_required
def delete_quiz(quiz_id):
    if not validate_csrf():
        flash("Invalid form session. Try again.", "error")
        return redirect(url_for("dashboard"))

    db = get_db()
    cur = get_cursor(db)

    if not is_quiz_owner(cur, quiz_id, session["user_id"]):
        db.close()
        flash("You are not allowed to delete this quiz.", "error")
        return redirect(url_for("dashboard"))

    # Keep hard delete explicit: remove attempts first, then quiz.
    cur.execute("DELETE FROM quiz_attempts WHERE quiz_id = ?", (quiz_id,))
    cur.execute("DELETE FROM quizzes WHERE id = ? AND host_id = ?", (quiz_id, session["user_id"]))
    db.commit()
    db.close()

    flash("Quiz deleted successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/quiz/<int:quiz_id>")
@login_required
def play_quiz(quiz_id):
    db = get_db()
    cur = get_cursor(db)

    cur.execute(
        """
        SELECT id, title, status, host_id
        FROM quizzes
        WHERE id = ? AND deleted_at IS NULL
        """,
        (quiz_id,),
    )
    quiz = cur.fetchone()

    if not quiz:
        db.close()
        flash("Quiz not found.", "error")
        return redirect(url_for("dashboard"))

    is_owner = quiz["host_id"] == session["user_id"]
    if quiz["status"] != "published" and not is_owner:
        db.close()
        flash("This quiz is not published.", "error")
        return redirect(url_for("dashboard"))

    cur.execute(
        """
        SELECT id, question_text
        FROM questions
        WHERE quiz_id = ?
        ORDER BY id ASC
        """,
        (quiz_id,),
    )
    raw_questions = cur.fetchall()

    questions = []
    for question in raw_questions:
        cur.execute(
            """
            SELECT id, option_text
            FROM options
            WHERE question_id = ?
            ORDER BY id ASC
            """,
            (question["id"],),
        )
        options = cur.fetchall()
        questions.append({"id": question["id"], "text": question["question_text"], "options": options})

    db.close()

    if not questions:
        flash("This quiz has no questions yet.", "error")
        if is_owner:
            return redirect(url_for("add_question", quiz_id=quiz_id))
        return redirect(url_for("dashboard"))

    return render_template("quiz.html", quiz=quiz, questions=questions, quiz_id=quiz_id, title=quiz["title"])


@app.route("/submit_quiz", methods=["POST"])
@login_required
def submit_quiz():
    if not validate_csrf():
        flash("Invalid form session. Try again.", "error")
        return redirect(url_for("dashboard"))

    try:
        quiz_id = int(request.form.get("quiz_id", "0"))
    except ValueError:
        flash("Invalid quiz request.", "error")
        return redirect(url_for("dashboard"))

    user_id = session["user_id"]

    db = get_db()
    cur = get_cursor(db)

    cur.execute("SELECT id, status, host_id FROM quizzes WHERE id = ? AND deleted_at IS NULL", (quiz_id,))
    quiz = cur.fetchone()
    if not quiz:
        db.close()
        flash("Quiz not found.", "error")
        return redirect(url_for("dashboard"))

    is_owner = quiz["host_id"] == user_id
    if quiz["status"] != "published" and not is_owner:
        db.close()
        flash("This quiz is not available.", "error")
        return redirect(url_for("dashboard"))

    cur.execute(
        """
        SELECT id, question_text
        FROM questions
        WHERE quiz_id = ?
        ORDER BY id ASC
        """,
        (quiz_id,),
    )
    quiz_questions = cur.fetchall()

    score = 0
    answer_sheet = []

    for idx, question in enumerate(quiz_questions, start=1):
        cur.execute(
            """
            SELECT id, option_text, is_correct
            FROM options
            WHERE question_id = ?
            ORDER BY id ASC
            """,
            (question["id"],),
        )
        option_rows = cur.fetchall()
        if not option_rows:
            continue

        option_map = {row["id"]: row["option_text"] for row in option_rows}
        correct_row = next((row for row in option_rows if row["is_correct"] == 1), None)
        if not correct_row:
            continue

        raw_selected = request.form.get(f"q_{question['id']}")
        selected_id = int(raw_selected) if raw_selected and raw_selected.isdigit() else None
        selected_text = option_map.get(selected_id)

        is_correct = selected_id == correct_row["id"] and selected_text is not None
        if is_correct:
            score += 1

        answer_sheet.append(
            {
                "number": idx,
                "question": question["question_text"],
                "selected_text": selected_text,
                "correct_text": correct_row["option_text"],
                "is_correct": is_correct,
            }
        )

    total = len(answer_sheet)

    cur.execute(
        """
        INSERT INTO quiz_attempts (user_id, quiz_id, score, total)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, quiz_id, score, total),
    )
    db.commit()
    db.close()

    percent = round((score / total) * 100, 1) if total else 0
    return render_template(
        "result.html",
        score=score,
        total=total,
        percent=percent,
        answer_sheet=answer_sheet,
        quiz_id=quiz_id,
        title="Quiz Result",
    )


@app.route("/history")
@login_required
def history():
    db = get_db()
    cur = get_cursor(db)

    cur.execute(
        """
        SELECT qa.score, qa.total, qa.attempted_at, q.title
        FROM quiz_attempts qa
        JOIN quizzes q ON q.id = qa.quiz_id
        WHERE qa.user_id = ?
        ORDER BY qa.attempted_at DESC
        LIMIT 100
        """,
        (session["user_id"],),
    )
    attempts = cur.fetchall()
    db.close()

    return render_template("history.html", attempts=attempts, title="History")


if __name__ == "__main__":
    run_migrations()
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode)
