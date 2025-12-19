from sqlalchemy import create_engine, Column, Integer, String, text  # <-- add text here
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String)

def main():
    engine = create_engine('sqlite:///test.db')
    Base.metadata.create_all(engine)

def test_table_creation():
    engine = create_engine('sqlite:///test.db')
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='users';"))  # <-- wrap with text()
        assert result.fetchone() is not None