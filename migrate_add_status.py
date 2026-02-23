import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("""
ALTER TABLE users
ADD COLUMN role TEXT DEFAULT 'user'
""")

conn.commit()
conn.close()

print("role column added to users table")
