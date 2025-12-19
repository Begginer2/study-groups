# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# Association table for the many-to-many relationship
# A user can be in many groups, a group can have many users
memberships = db.Table('memberships',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True) # <-- MAKE IT nullable=True
# --- based on interests ---
    interested_subjects = db.Column(db.Text, nullable=True) # Store as comma-separated string
    is_admin = db.Column(db.Boolean, nullable=False, default=False)# admin flag

    # Relationship: 'My groups' (groups this user has created)
    created_groups = db.relationship('Group', backref='creator', lazy=True)
    
    # Relationship: 'Joined groups' (groups this user is a member of)
    joined_groups = db.relationship('Group', secondary=memberships, lazy='subquery',
        backref=db.backref('members', lazy=True))

    def __repr__(self):
        return f'<User {self.username}>'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Foreign Key: Link to the user who created the group
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):

        return f'<Group {self.name}>'
 #resorce sharing       
class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # 'file' or 'link'
    resource_type = db.Column(db.String(10), nullable=False)
    # For links
    url = db.Column(db.String(500), nullable=True)
    # For files
    filename = db.Column(db.String(300), nullable=True) 
    # Foreign Key to User (who posted it)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Foreign Key to Group (where it was posted)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    # --- This part creates 'group.resources' ---
    poster = db.relationship('User', backref='posted_resources', lazy=True)
    group = db.relationship('Group', backref='resources', lazy=True)
    def __repr__(self):
        return f'<Resource {self.title}>'
    # --- ADD THIS NEW CLASS ---
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    event_datetime = db.Column(db.DateTime, nullable=False) # Stores date and time
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Foreign Key to User (who created it)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Foreign Key to Group (where it belongs)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)

    # Relationships
    creator = db.relationship('User', backref='created_events', lazy=True)
    group = db.relationship('Group', backref='events', lazy=True) # Allows group.events

    def __repr__(self):
        return f'<Event {self.title}>'