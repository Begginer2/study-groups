# quick_check.py
import sqlite3
from pathlib import Path

project_root = Path(__file__).resolve().parent
db_path = project_root / "instance" / "site.db"

con = sqlite3.connect(str(db_path))
cur = con.cursor()
print("user table columns:")
for row in cur.execute("PRAGMA table_info(user)"):
    print(row)
con.close()
print("Done.")