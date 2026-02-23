import os
import random
import sqlite3
import string

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

try:
    from psycopg_pool import ConnectionPool
except ImportError:
    ConnectionPool = None


_pg_pool = None


def _database_url():
    return os.getenv("DATABASE_URL", "").strip()


def _sqlite_db_path():
    return os.getenv("SQLITE_DB_PATH", "database.db").strip() or "database.db"


def using_postgres():
    db_url = _database_url().lower()
    return db_url.startswith("postgresql://") or db_url.startswith("postgres://")


def _adapt_query(query):
    if using_postgres():
        return query.replace("?", "%s")
    return query


class CompatCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, params=()):
        return self._cursor.execute(_adapt_query(query), params)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)


class PooledConnection:
    def __init__(self, pool, conn):
        self._pool = pool
        self._conn = conn

    def __getattr__(self, item):
        return getattr(self._conn, item)

    def close(self):
        if self._conn is None:
            return
        try:
            self._conn.rollback()
        except Exception:
            pass
        self._pool.putconn(self._conn)
        self._conn = None


def _get_pg_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool

    if ConnectionPool is None:
        raise RuntimeError(
            "PostgreSQL pooling requires 'psycopg-pool'. Run: pip install psycopg-pool"
        )

    min_pool = int(os.getenv("PG_POOL_MIN_SIZE", "1"))
    max_pool = int(os.getenv("PG_POOL_MAX_SIZE", "10"))

    _pg_pool = ConnectionPool(
        conninfo=_database_url(),
        min_size=min_pool,
        max_size=max_pool,
        kwargs={"row_factory": dict_row},
        timeout=5,
    )
    _pg_pool.open(wait=True)
    return _pg_pool


def get_db():
    if using_postgres():
        if psycopg is None:
            raise RuntimeError(
                "PostgreSQL is configured in DATABASE_URL but 'psycopg' is not installed. "
                "Run: pip install psycopg[binary]"
            )
        pool = _get_pg_pool()
        conn = pool.getconn()
        return PooledConnection(pool, conn)

    conn = sqlite3.connect(_sqlite_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_cursor(conn):
    return CompatCursor(conn.cursor())


def insert_and_get_id(cur, query, params=()):
    if using_postgres():
        insert_query = _adapt_query(query)
        if " returning " not in insert_query.lower():
            insert_query = f"{insert_query} RETURNING id"
        cur._cursor.execute(insert_query, params)
        row = cur._cursor.fetchone()
        if row is None:
            return None
        if isinstance(row, dict):
            return row.get("id")
        return row[0]

    cur.execute(query, params)
    return cur.lastrowid


def _ensure_sqlite_column(cur, table, column, definition):
    cur.execute(f"PRAGMA table_info({table})")
    existing_cols = {row[1] for row in cur.fetchall()}
    if column not in existing_cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def _generate_quiz_code(existing_codes, length=6):
    alphabet = string.ascii_uppercase + string.digits
    while True:
        code = "".join(random.choices(alphabet, k=length))
        if code not in existing_codes:
            return code


def _init_sqlite(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            quiz_code TEXT UNIQUE,
            status TEXT DEFAULT 'draft',
            deleted_at TIMESTAMP NULL,
            host_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES users(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER,
            question_text TEXT NOT NULL,
            FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_id INTEGER,
            option_text TEXT NOT NULL,
            is_correct INTEGER DEFAULT 0,
            FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            quiz_id INTEGER,
            score INTEGER,
            total INTEGER,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
        )
        """
    )

    _ensure_sqlite_column(cur, "users", "role", "role TEXT DEFAULT 'user'")
    _ensure_sqlite_column(cur, "quizzes", "description", "description TEXT DEFAULT ''")
    _ensure_sqlite_column(cur, "quizzes", "quiz_code", "quiz_code TEXT")
    _ensure_sqlite_column(cur, "quizzes", "status", "status TEXT DEFAULT 'draft'")
    _ensure_sqlite_column(cur, "quizzes", "deleted_at", "deleted_at TIMESTAMP NULL")

    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_quizzes_quiz_code ON quizzes(quiz_code)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_quizzes_host_id ON quizzes(host_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_questions_quiz_id ON questions(quiz_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_options_question_id ON options(question_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attempts_user_id ON quiz_attempts(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attempts_quiz_id ON quiz_attempts(quiz_id)")

    cur.execute("SELECT quiz_code FROM quizzes WHERE quiz_code IS NOT NULL AND quiz_code <> ''")
    used_codes = {row[0] for row in cur.fetchall()}

    cur.execute("SELECT id FROM quizzes WHERE quiz_code IS NULL OR quiz_code = ''")
    for (quiz_id,) in cur.fetchall():
        code = _generate_quiz_code(used_codes)
        used_codes.add(code)
        cur.execute("UPDATE quizzes SET quiz_code = ? WHERE id = ?", (code, quiz_id))

    cur.execute(
        """
        UPDATE quizzes
        SET status = 'draft'
        WHERE status IS NULL OR status NOT IN ('draft', 'published')
        """
    )


def _init_postgres(cur):
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(30) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(20) DEFAULT 'user'
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quizzes (
            id BIGSERIAL PRIMARY KEY,
            title VARCHAR(100) NOT NULL,
            description TEXT DEFAULT '',
            quiz_code VARCHAR(6) UNIQUE,
            status VARCHAR(20) DEFAULT 'draft',
            deleted_at TIMESTAMP NULL,
            host_id BIGINT REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS questions (
            id BIGSERIAL PRIMARY KEY,
            quiz_id BIGINT REFERENCES quizzes(id) ON DELETE CASCADE,
            question_text TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS options (
            id BIGSERIAL PRIMARY KEY,
            question_id BIGINT REFERENCES questions(id) ON DELETE CASCADE,
            option_text TEXT NOT NULL,
            is_correct INTEGER DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
            quiz_id BIGINT REFERENCES quizzes(id) ON DELETE CASCADE,
            score INTEGER,
            total INTEGER,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user'")
    cur.execute("ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''")
    cur.execute("ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS quiz_code VARCHAR(6)")
    cur.execute("ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'draft'")
    cur.execute("ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL")

    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_quizzes_quiz_code ON quizzes(quiz_code)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_quizzes_host_id ON quizzes(host_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_questions_quiz_id ON questions(quiz_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_options_question_id ON options(question_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attempts_user_id ON quiz_attempts(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attempts_quiz_id ON quiz_attempts(quiz_id)")

    cur.execute("SELECT quiz_code FROM quizzes WHERE quiz_code IS NOT NULL AND quiz_code <> ''")
    used_codes = {row["quiz_code"] for row in cur.fetchall()}

    cur.execute("SELECT id FROM quizzes WHERE quiz_code IS NULL OR quiz_code = ''")
    for row in cur.fetchall():
        code = _generate_quiz_code(used_codes)
        used_codes.add(code)
        cur.execute("UPDATE quizzes SET quiz_code = %s WHERE id = %s", (code, row["id"]))

    cur.execute(
        """
        UPDATE quizzes
        SET status = 'draft'
        WHERE status IS NULL OR status NOT IN ('draft', 'published')
        """
    )


def init_db():
    # Legacy bootstrap kept for backward compatibility.
    conn = get_db()
    cur = get_cursor(conn)

    if using_postgres():
        _init_postgres(cur)
    else:
        _init_sqlite(cur)

    conn.commit()
    conn.close()
