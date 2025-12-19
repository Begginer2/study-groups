

# --- Core Flask and Extensions ---
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, jsonify   
import os
from werkzeug.utils import secure_filename 
from functools import wraps
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_socketio import SocketIO, join_room, leave_room, emit
from sqlalchemy import not_
from authlib.integrations.flask_client import OAuth # sign up with google
# --- New Imports for Password Reset ---
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# --- Your Database Models ---
from models import db, User, Group, memberships, Resource, Event
from datetime import datetime
# --- Your Forms (ALL OF THEM) ---
from forms import (
    SignUpForm, 
    LoginForm, 
    CreateGroupForm, 
    RequestResetForm,  # <-- This is reset
    ResetPasswordForm,  # <-- This is password
    ResourceForm,   # <-- This is resorce
    UpdateProfileForm,
    EventForm    # <-- ADD THIS LINE for updating interests
)


# --- APP CONFIGURATION ---

# Get the absolute path for the directory where this file (app.py) is
basedir = os.path.abspath(os.path.dirname(__file__))
# Define the path for the 'instance' folder
instance_path = os.path.join(basedir, 'instance')

# --- This is the new part: ---
# Check if the 'instance' folder exists. If not, create it.
if not os.path.exists(instance_path):
    try:
        os.makedirs(instance_path)
    except OSError as e:
        print(f"Error creating instance directory: {e}")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_you_should_change'
# --- This is the modified line: ---
# Set the database URI to an absolute path inside the 'instance' folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- MAIL SERVER CONFIGURATION (ADD THIS ENTIRE BLOCK) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'madhavi.cdk1234@gmail.com'  # <-- PUT YOUR EMAIL HERE
app.config['MAIL_PASSWORD'] = 'tvjxpxizwdte gpuf' # <-- PUT YOUR PASSWORD HERE
app.config['MAIL_DEFAULT_SENDER'] = 'madhavi.cdk1234@gmail.com' # <-- PUT YOUR EMAIL HERE
app.config['MAIL_DEFAULT_SENDER'] = 'madhavi.cdk1234@gmail.com'


# --- UPLOAD FOLDER CONFIG (ADD THIS BLOCK) ---
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
# --- END OF BLOCK ---

# --- INITIALIZE EXTENSIONS ---
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
socketio = SocketIO(app)

mail = Mail(app)  # <-- ADD THIS LINE

# --- TOKEN SERIALIZER (ADD THIS LINE) ---
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- OAUTH SETUP (ADD THIS) ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config.get('GOOGLE_CLIENT_ID'),
    client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is the endpoint to get user info
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)
# --- END OF OAUTH SETUP ---

# --- FLASK-LOGIN CONFIG ---
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ADD THIS ADMIN DECORATOR ---
def admin_required(f):
    """Decorator to restrict access to admins."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
# --- END OF DECORATOR ---
# --- AUTHENTICATION ROUTES ---
# sign-in google 
@app.route('/google/login')
def google_login():
    """Redirects to Google's OAuth login page."""
    # The 'google' name must match what we registered with oauth
    redirect_uri = url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/google/callback')
def google_callback():
    """Handles the response from Google after login."""
    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        flash('An error occurred while trying to log in with Google.', 'danger')
        return redirect(url_for('login'))

    # Get user info from Google
    user_info = oauth.google.get('userinfo').json()
    
    user_email = user_info.get('email')
    user_username = user_info.get('name')

    # Find or create the user in our database
    user = User.query.filter_by(email=user_email).first()
    
    if user:
        # User already exists, just log them in
        login_user(user)
        flash('Logged in successfully with Google!', 'success')
        return redirect(url_for('dashboard'))
    else:
        # User doesn't exist, create a new one
        # Note: They won't have a password.
        new_user = User(
            email=user_email,
            username=user_username,
            password_hash=None  # No password for OAuth users
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Log in the new user
        login_user(new_user)
        flash('Account created successfully with Google!', 'success')
        return redirect(url_for('dashboard'))

# ... (your /signup, /login, /logout routes...)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = SignUpForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', title='Sign Up', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- MAIN PAGE ROUTES ---

@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html')

# app.py

@app.route("/dashboard")
@login_required
def dashboard():
    user_group_ids = [group.id for group in current_user.joined_groups]

    # --- REPLACE OLD RECOMMENDATION LOGIC WITH THIS ---
    recommended_groups = []
    if current_user.interested_subjects:
        # Get interests, clean them up (remove spaces, lowercase)
        interests = [interest.strip().lower() for interest in current_user.interested_subjects.split(',') if interest.strip()]

        if interests:
            # Find groups matching interests (case-insensitive) that user hasn't joined
            recommended_groups = Group.query.filter(
                db.func.lower(Group.subject).in_(interests), # Case-insensitive check
                not_(Group.id.in_(user_group_ids))
            ).order_by(Group.created_at.desc()).limit(6).all() # Show up to 6

    # Fallback if no interest-based recommendations found
    if not recommended_groups:
         recommended_groups = Group.query.filter(
            not_(Group.id.in_(user_group_ids))
        ).order_by(Group.created_at.desc()).limit(3).all() # Show 3 recent ones
    # --- END OF NEW RECOMMENDATION LOGIC ---

    # Get all other groups (excluding joined and recommended)
    recommended_ids = [group.id for group in recommended_groups]
    exclude_ids = user_group_ids + recommended_ids
    all_groups = Group.query.filter(
        not_(Group.id.in_(exclude_ids))
    ).order_by(Group.created_at.desc()).all()

    my_groups = current_user.joined_groups

    # Pass variables to the template (this part stays the same)
    return render_template('dashboard.html',
                           title='Dashboard',
                           my_groups=my_groups,
                           all_groups=all_groups,
                           recommended_groups=recommended_groups)

@app.route("/group/create", methods=['GET', 'POST'])
@login_required
def create_group():
    form = CreateGroupForm()
    if form.validate_on_submit():
        group = Group(name=form.name.data, 
                      subject=form.subject.data, 
                      description=form.description.data, 
                      creator=current_user)
        db.session.add(group)
        # Add the creator as the first member
        group.members.append(current_user)
        db.session.commit()
        flash('Your group has been created!', 'success')
        return redirect(url_for('group_detail', group_id=group.id))
    return render_template('create_group.html', title='Create Group', form=form)


@app.route("/group/<int:group_id>/join")
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    if current_user in group.members:
        flash('You are already a member of this group.', 'info')
    else:
        group.members.append(current_user)
        db.session.commit()
        flash(f'You have joined the group: {group.name}!', 'success')
    return redirect(url_for('group_detail', group_id=group.id))

@app.route("/group/<int:group_id>/leave")
@login_required
def leave_group(group_id):
    group = Group.query.get_or_404(group_id)
    if current_user not in group.members:
        flash('You are not a member of this group.', 'info')
    elif current_user == group.creator:
        flash('As the creator, you cannot leave the group. You must delete it.', 'danger')
    else:
        group.members.remove(current_user)
        db.session.commit()
        flash(f'You have left the group: {group.name}.', 'success')
    return redirect(url_for('dashboard'))

# --- THIS IS THE ONLY group_detail FUNCTION YOU SHOULD HAVE ---
@app.route("/group/<int:group_id>", methods=['GET', 'POST'])
@login_required
def group_detail(group_id):
    group = Group.query.get_or_404(group_id)
    if current_user not in group.members:
        flash('You must be a member of this group to view it.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = ResourceForm()
    if form.validate_on_submit():
        resource = None
        if form.resource_type.data == 'link':
            if not form.url.data:
                flash('URL is required for link resources.', 'danger')
            else:
                resource = Resource(title=form.title.data,
                                    description=form.description.data,
                                    resource_type='link',
                                    url=form.url.data,
                                    poster=current_user,
                                    group=group)
        
        elif form.resource_type.data == 'file':
            if not form.file.data:
                flash('File is required for file resources.', 'danger')
            else:
                file = form.file.data
                original_filename = secure_filename(file.filename)
                unique_id = str(uuid.uuid4())
                filename = f"{unique_id}_{original_filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                resource = Resource(title=form.title.data,
                                    description=form.description.data,
                                    resource_type='file',
                                    filename=filename,
                                    poster=current_user,
                                    group=group)
        
        if resource:
            db.session.add(resource)
            db.session.commit()
            flash('Resource added!', 'success')
            # --- ADD NOTIFICATION LOGIC ---
            notification_msg = f"{current_user.username} posted '{resource.title}' in {group.name}"
            for member in group.members:
                if member != current_user: # Don't notify the poster
                    socketio.emit('receive_notification',
                                  {'msg': notification_msg, 'url': url_for('group_detail', group_id=group.id)},
                                  room=member.id) # Emit to user's personal room
            # --- END NOTIFICATION LOGIC ---
            return redirect(url_for('group_detail', group_id=group.id))
    event_form = EventForm()
    resources = group.resources
    events = sorted(group.events, key=lambda e: e.event_datetime)
        
    return render_template('group_detail.html', 
                           title=group.name, 
                           group=group, 
                           form=form,    # Resource form
                           event_form=event_form, # Event form << MUST BE HERE
                           resources=resources,   # List of resources
                           events=events)
# --- END OF group_detail FUNCTION ---



# --- Profile ---
@app.route("/profile", methods=['GET', 'POST']) # Add methods
@login_required
def profile():
    form = UpdateProfileForm() # Create the new form instance

    if form.validate_on_submit():
        # Save the interests from the form to the current user
        current_user.interested_subjects = form.interested_subjects.data
        db.session.commit()
        flash('Your interests have been updated!', 'success')
        return redirect(url_for('profile')) # Redirect back to the profile page
    elif request.method == 'GET':
        # If it's a GET request, fill the form with the user's current interests
        form.interested_subjects.data = current_user.interested_subjects


    # Pass the form to the template
    return render_template('profile.html', title='Profile', form=form)
# --- END OF NEW FUNCTION ---


# app.py

# ... (after /profile route) ...

# --- ADMIN PANEL ROUTES ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Main dashboard for the admin panel."""
    user_count = User.query.count()
    group_count = Group.query.count()
    return render_template('admin/dashboard.html', title='Admin', 
                           user_count=user_count, group_count=group_count)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Shows a list of all users."""
    users = User.query.all()
    return render_template('admin/users.html', title='Manage Users', users=users)

@app.route('/admin/groups')
@admin_required
def admin_groups():
    """Shows a list of all groups."""
    groups = Group.query.all()
    return render_template('admin/groups.html', title='Manage Groups', groups=groups)

@app.route('/admin/group/<int:group_id>/delete', methods=['POST'])
@admin_required
def admin_delete_group(group_id):
    """Deletes a group and all its related content."""
    group = Group.query.get_or_404(group_id)

    # Delete associated resources
    Resource.query.filter_by(group_id=group.id).delete()
    # Delete associated events
    Event.query.filter_by(group_id=group.id).delete()
    # Clear members from the association table
    group.members = []

    db.session.commit() # Commit changes for members/resources/events

    # Delete the group itself
    db.session.delete(group)
    db.session.commit()

    flash(f'Group "{group.name}" and all its contents have been deleted.', 'success')
    return redirect(url_for('admin_groups'))

# --- END OF ADMIN ROUTES ---


#adding route to download files
@app.route('/uploads/<string:filename>')
@login_required
def download_file(filename):
    """Serves an uploaded file for download."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# --- END OF BLOCK ---

# --- ADD THIS NEW ROUTE ---
@app.route('/resource/<int:resource_id>/delete', methods=['POST'])
@login_required
def delete_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    
    # Security check: Make sure the current user is the one who posted it
    if current_user != resource.poster:
        flash('You do not have permission to delete this resource.', 'danger')
        return redirect(url_for('group_detail', group_id=resource.group_id))
        
    # If it's a file, delete the file from the 'uploads' folder
    if resource.resource_type == 'file' and resource.filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], resource.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
    # Delete the resource from the database
    db.session.delete(resource)
    db.session.commit()
    
    flash('Resource has been deleted.', 'success')
    return redirect(url_for('group_detail', group_id=resource.group_id))
# --- END OF NEW ROUTE ---

# --- CREATE EVENT ROUTE (Handles POST from group_detail page) ---
@app.route('/group/<int:group_id>/event/create', methods=['POST'])
@login_required
def create_event(group_id):
    group = Group.query.get_or_404(group_id)
    if current_user not in group.members:
        flash('You must be a member to add events.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    form = EventForm()
    if form.validate_on_submit():
        # Combine date and time from the form into a single datetime object
        combined_datetime = datetime.combine(form.event_date.data, form.event_time.data) # <-- Combine here
        event = Event(title=form.title.data,
                      description=form.description.data,
                      event_datetime=combined_datetime,# <-- Save the combined object
                      creator=current_user,
                      group=group)
        db.session.add(event)
        db.session.commit()
        flash('Event added successfully!', 'success')

        # --- ADD NOTIFICATION LOGIC ---
        notification_msg = f"{current_user.username} scheduled '{event.title}' in {group.name}"
        for member in group.members:
            if member != current_user: # Don't notify the creator
                socketio.emit('receive_notification',
                              {'msg': notification_msg, 'url': url_for('group_detail', group_id=group.id)},
                              room=member.id) # Emit to user's personal room
        # --- END NOTIFICATION LOGIC ---
    else:
        # Flash validation errors if form fails
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')

    return redirect(url_for('group_detail', group_id=group_id))



# --- EDIT EVENT ROUTE (Handles GET to show form, POST to save changes) ---
@app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    # Permission Check: Only the creator can edit
    if event.creator != current_user:
        flash('You do not have permission to edit this event.', 'danger')
        return redirect(url_for('group_detail', group_id=event.group_id))

    form = EventForm()
    if form.validate_on_submit(): # If form submitted and valid (POST)
        # Combine date and time from the form
        combined_datetime = datetime.combine(form.event_date.data, form.event_time.data) # <-- Combine here
        
        event.title = form.title.data
        event.description = form.description.data
        event.event_datetime = combined_datetime # <-- Save combined object
        db.session.commit()
        flash('Event updated successfully!', 'success')
        return redirect(url_for('group_detail', group_id=event.group_id))
    elif request.method == 'GET': # If just visiting the page (GET)
        # Pre-populate the form with the event's current data
        form.title.data = event.title
        form.description.data = event.description
        form.event_date.data = event.event_datetime.date() # <-- Split date
        form.event_time.data = event.event_datetime.time() # <-- Split time
    # Render a separate template for editing
    return render_template('edit_event.html', title='Edit Event', form=form, event=event)

# --- DELETE EVENT ROUTE (Handles POST for deletion) ---
@app.route('/event/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    group_id = event.group_id # Store group ID before deleting event
    # Permission Check: Only the creator can delete
    if event.creator != current_user:
        flash('You do not have permission to delete this event.', 'danger')
        return redirect(url_for('group_detail', group_id=group_id))

    db.session.delete(event)
    db.session.commit()
    flash('Event deleted successfully.', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


# ... (reset password) ...

def send_reset_email(user_email, token):
    """Helper function to send the password reset email."""
    msg = Message('Password Reset Request',
                  recipients=[user_email])
    
    # The 'reset_password' here is the name of our route function
    reset_url = url_for('reset_password', token=token, _external=True)
    
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    try:
        mail.send(msg)
        print("Email sent!")
    except Exception as e:
        print(f"Error sending email: {e}")


@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate a token with the user's email
            # The 'salt' makes this token specific for password resets
            token = s.dumps(user.email, salt='password-reset-salt')
            send_reset_email(user.email, token)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html', title='Forgot Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    try:
        # Try to decode the token, max_age is in seconds (30 minutes)
        email = s.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('The password reset link is invalid.', 'danger')
        return redirect(url_for('forgot_password'))
    except Exception:
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('Invalid user. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Hash the new password and save it
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password_hash = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', title='Reset Password', form=form)
#rule-based bot logic

def get_bot_response(user_question):
    """Contains the logic for the rule-based bot."""
    question = user_question.lower().strip() # Clean the input

    # --- Define Your Rules Here ---
    rules = {
        "hello": "Hi! I'm the Study Circle assistant. How can I help you?",
        "hi": "Hi! I'm the Study Circle assistant. How can I help you?",
        "create group": "You can create a new group by clicking the 'Create New Group' button on your Dashboard.",
        "join group": "From the Dashboard, you can join any group listed under 'Recommended' or 'Find New Groups' by clicking 'Join Group'.",
        "share file": "Inside a group, go to the 'Resources' tab. You can add a file or a link using the form there.",
        "share resource": "Inside a group, go to the 'Resources' tab. You can add a file or a link using the form there.",
        "schedule event": "Inside a group, go to the 'Events' tab and use the 'Add New Event' form.",
        "add event": "Inside a group, go to the 'Events' tab and use the 'Add New Event' form.",
        "delete resource": "You can delete a resource you posted by finding it in the 'Resources' tab and clicking the 'Delete' button.",
        "delete event": "You can delete an event you created by finding it in the 'Events' tab and clicking the 'Delete' button.",
        "edit event": "You can edit an event you created by clicking the 'Edit' button next to it in the 'Events' tab.",
        "interests": "You can update your interests on your 'Profile' page. This will help me recommend better groups for you!",
        "recommendations": "Recommendations on your Dashboard are based on the 'Interested Subjects' you set in your Profile."
    }

    # --- Find a Matching Rule ---
    for key, answer in rules.items():
        if key in question:
            return answer

    # --- Fallback Response ---
    return "I'm sorry, I don't understand that. Please try asking about creating groups, sharing resources, or scheduling events."

@app.route("/ask_bot", methods=['POST'])
@login_required # Only logged-in users can use the bot
def ask_bot():
    """Receives a question from the user and returns the bot's answer."""
    user_question = request.json.get('question')

    if not user_question:
        return jsonify({'error': 'No question provided'}), 400

    bot_answer = get_bot_response(user_question)
    return jsonify({'answer': bot_answer})


# --- SOCKET.IO HANDLERS (for chat) ---

@socketio.on('connect')
def on_connect():
    """A user connects to the server."""
    if current_user.is_authenticated:
        # Join a private room named after the user's ID
        join_room(current_user.id)
        print(f'Client {current_user.username} joined personal room {current_user.id}')

@socketio.on('disconnect')
def on_disconnect():
    """A user disconnects."""
    if current_user.is_authenticated:
        # Leave the private room
        leave_room(current_user.id)
        print(f'Client {current_user.username} left personal room {current_user.id}')
# --- END OF NEW HANDLERS ---

@socketio.on('join')
def on_join(data):
    """User joins a room when they load the group_detail page"""
    room = data['room']
    join_room(room)
    # You could optionally emit a "user has joined" message here
    # emit('receive_message', {'msg': current_user.username + ' has joined.'}, to=room)

@socketio.on('send_message')
def on_send_message(data):
    """A user sends a message to a room"""
    if current_user.is_authenticated:
        room_id = data['room'] # This is the group.id
        message_content = data['msg']
        
        group = Group.query.get(room_id)
        if not group:
            return 

        # 1. Send the message to the CHAT WINDOW
        message_packet = {
            'username': current_user.username,
            'msg': message_content
        }
        emit('receive_message', message_packet, to=room_id)

        # 2. Send a NOTIFICATION to the BELL
        
        # --- FIX: Create an app context to use url_for() ---
        with app.app_context():
            notification_msg = f"{current_user.username} sent a message in {group.name}"
            notification_url = url_for('group_detail', group_id=group.id)
        # --- END OF FIX ---

        for member in group.members:
            if member != current_user:
                socketio.emit('receive_notification',
                              {'msg': notification_msg, 'url': notification_url}, # Use the new variable
                              room=member.id)
# --- RUN THE APP ---
if __name__ == '__main__':
    # ADD THESE TWO LINES:
    with app.app_context():
        db.create_all()
    # This line was already there:
    socketio.run(app, debug=True)