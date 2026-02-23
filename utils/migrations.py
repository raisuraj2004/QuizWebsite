import pathlib
import random
import re
import string

from utils.db import get_db, get_cursor, using_postgres

_MIGRATION_RE = re.compile(r"^(\d+)_.*\.sql$")
_IGNORED_SQLITE_ERRORS = (
    "duplicate column name",
    "already exists",
    "no such table",
)


def _migration_dir():
    backend = "postgres" if using_postgres() else "sqlite"
    return pathlib.Path(__file__).resolve().parents[1] / "migrations" / backend


def _load_migration_files():
    files = []
    for path in _migration_dir().glob("*.sql"):
        match = _MIGRATION_RE.match(path.name)
        if not match:
            continue
        files.append((int(match.group(1)), path))
    files.sort(key=lambda item: item[0])
    return files


def _split_statements(sql_text):
    chunks = [chunk.strip() for chunk in sql_text.split(";")]
    return [f"{chunk};" for chunk in chunks if chunk]


def _generate_quiz_code(existing_codes, length=6):
    alphabet = string.ascii_uppercase + string.digits
    while True:
        code = "".join(random.choices(alphabet, k=length))
        if code not in existing_codes:
            return code


def _backfill_quiz_codes(cur):
    cur.execute("SELECT quiz_code FROM quizzes WHERE quiz_code IS NOT NULL AND quiz_code <> ''")
    rows = cur.fetchall()
    used_codes = set()
    for row in rows:
        value = row["quiz_code"] if isinstance(row, dict) else row[0]
        used_codes.add(value)

    cur.execute("SELECT id FROM quizzes WHERE quiz_code IS NULL OR quiz_code = ''")
    quiz_rows = cur.fetchall()

    for row in quiz_rows:
        quiz_id = row["id"] if isinstance(row, dict) else row[0]
        code = _generate_quiz_code(used_codes)
        used_codes.add(code)
        cur.execute("UPDATE quizzes SET quiz_code = ? WHERE id = ?", (code, quiz_id))


def run_migrations():
    conn = get_db()
    cur = get_cursor(conn)

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute("SELECT version FROM schema_migrations")
    applied = {
        row["version"] if isinstance(row, dict) else row[0]
        for row in cur.fetchall()
    }

    for version, path in _load_migration_files():
        version_key = f"{version:04d}"
        if version_key in applied:
            continue

        sql_text = path.read_text(encoding="utf-8")
        for statement in _split_statements(sql_text):
            try:
                cur.execute(statement)
            except Exception as err:
                if not using_postgres() and any(token in str(err).lower() for token in _IGNORED_SQLITE_ERRORS):
                    continue
                conn.rollback()
                conn.close()
                raise

        cur.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version_key,))

    _backfill_quiz_codes(cur)

    conn.commit()
    conn.close()
