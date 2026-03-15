# add_columns.py
import sqlite3
from pathlib import Path

project_root = Path(__file__).resolve().parent
db_path = project_root / 'instance' / 'site.db'
if not db_path.exists():
    print(f"No database found at: {db_path}")
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
