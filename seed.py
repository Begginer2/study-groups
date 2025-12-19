# seed.py
import sys
from pathlib import Path

# ensure we run from project root so imports work
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.append(str(PROJECT_ROOT))

# Import app and models
try:
    from app import app, db, User
except Exception as e:
    print("Error importing app, db, or User from app.py:", e)
    raise

users = [
    {'name':'Alice','email':'alice@example.com','password':'123','courses':'Math,Physics','interests':'AI,Robotics'},
    {'name':'Bob','email':'bob@example.com','password':'123','courses':'Math,Chemistry','interests':'Chemistry,AI'},
    {'name':'Charlie','email':'charlie@example.com','password':'123','courses':'Biology,Physics','interests':'Medicine,AI'},
    # add more test users here if you want
]

def seed():
    with app.app_context():
        print("Ensuring database tables exist...")
        db.create_all()

        for u in users:
            email = u['email'].strip().lower()
            existing = User.query.filter_by(email=email).first()
            if existing:
                print(f"Skipping {email} — already exists.")
                continue
            user = User(
                name=u['name'],
                email=email,
                courses=u.get('courses',''),
                interests=u.get('interests','')
            )
            user.set_password(u['password'])
            db.session.add(user)
            try:
                db.session.commit()
                print(f"Created user: {email}")
            except Exception as ex:
                db.session.rollback()
                print(f"Failed to create {email}: {ex}")

if __name__ == "__main__":
    seed()
    print("Seeding finished.")
