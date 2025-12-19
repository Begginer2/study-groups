# quick_check.py
import sqlite3
con = sqlite3.connect("studygroup.db")
cur = con.cursor()
print("user table columns:")
for row in cur.execute("PRAGMA table_info(user)"):
    print(row)
con.close()
print("Done.")