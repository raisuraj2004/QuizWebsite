import random
import sqlite3

def get_questions(difficulty, limit=5):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute(
        "SELECT id, question_text, option_a, option_b, option_c, option_d, correct_option "
        "FROM questions WHERE difficulty = ? ORDER BY RANDOM() LIMIT ?",
        (difficulty, limit)
    )

    questions = cur.fetchall()
    conn.close()
    return questions
