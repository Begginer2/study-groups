# add_columns.py
import sqlite3
from pathlib import Path

db_path = Path('studygroup.db')
if not db_path.exists():
    print("No studygroup.db found in current folder.")
    raise SystemExit(1)

con = sqlite3.connect(str(db_path))
cur = con.cursor()

def add_col(name, coltype='TEXT'):
    try:
        cur.execute(f"ALTER TABLE user ADD COLUMN {name} {coltype}")
        print(f"Added column: {name}")
    except sqlite3.OperationalError as e:
        print(f"Could not add '{name}' (maybe already exists): {e}")

add_col('courses', 'TEXT')
add_col('interests', 'TEXT')

con.commit()
con.close()
print("Done.")
