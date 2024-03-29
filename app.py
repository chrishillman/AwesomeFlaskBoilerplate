from flask import Flask, render_template, redirect, request, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from datetime import datetime, timedelta, date
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, HiddenField, FileField, SelectField, \
    TextAreaField, DateField, DateTimeField, SelectMultipleField, MultipleFileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired, NoneOf, ValidationError, Optional
import hashlib
import uuid
from functools import wraps

import elements


defaultapp = Flask(__name__)
defaultapp.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db?check_same_thread=False'
defaultapp.config['SECRET_KEY'] = '84g3hin3v88b3nuceif83b94uf59b4n9u5nf487fni5u3ng379bf9374b'
defaultapp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
defaultapp.config['TESTING'] = False
defaultapp.jinja_env.add_extension(extension='jinja2.ext.do')
bigkey = "76438953g48th9384g8397h45f3683b5798fn34fy834eyhfg8487y6ujhgt"

db = SQLAlchemy(defaultapp)
login_manager = LoginManager()
login_manager.init_app(defaultapp)
login_manager.login_view = "login"


def hashme(cleartext):
    return hashlib.md5((cleartext + bigkey).encode()).hexdigest()

def getuuidhash():
    return hashme(uuid.uuid1().hex)

def logthis(data):
    data = str(datetime.now())+":"+str(data)
    data = "".join(data.split("'"))
    data = "".join(data.split('"'))
    thislog = logs(data)
    db.session.add(thislog)
    db.session.commit()
    return True

# Data Models (can't seem to get this to work as separate python files)
class users(db.Model):
    __tablename__ = "users"
    active = db.Column(db.Boolean, nullable=False)
    authenticated = db.Column(db.Boolean, nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(32), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    userpasswordhash = db.Column(db.String(64), nullable=False)
    usertype = db.Column(db.Integer, nullable=False)
    # normally 1=user ... 99=admin
    notes = db.Column(db.Text, nullable=True)

    def create(self):
        db.session.add(self)
        db.session.commit()
        logthis(f"WARN: Commit from User Create: {self.username} {self.usertype}")
        return self

    def __init__(self, username, userpasswordhash, usertype, active, notes):
        self.uuid = getuuidhash()
        self.username = username
        self.userpasswordhash = userpasswordhash
        self.usertype = int(usertype)
        self.active = active
        self.authenticated = False
        self.notes = notes

    def is_admin(self):
        if self.usertype > 10:
            return True
        else:
            return False

    def is_active(self):
        return self.active

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        # No Anonymous Users
        return False

    def __repr__(self):
        return self.username

class logs(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(400), nullable=False)

    def create(self):
        db.session.add(self)
        db.session.commit()
        return self

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return self.id

# Build Database
db.create_all()

#default data

user = users.query.filter(users.username.like("administrator")).one_or_none()
if not user:
    administrator = users(username="administrator", userpasswordhash=hashme("ThisIsThePassword123456!@#$%^"), usertype=99, active=True, notes=None)
    db.session.add(administrator)
    db.session.commit()
    logthis("WARN: Administrator Account Created.")

class UserDataUpdateForm(FlaskForm):
    username = StringField("User Name*", validators=[Optional()])

    def validate_uniqueuser(self, field):
        allusers = db.session.query(users.username).all()
        for inputuser in allusers:
            if field.data.lower() == inputuser.username.lower():
                raise ValidationError('This username already registered')

    usertype = SelectField("User Type*", coerce=int, choices=[(1, "Basic User"), (99, "Administrator")])
    active = BooleanField("Active?", validators=[Optional()])
    id = HiddenField(validators=[Optional()])
    uuid = HiddenField(validators=[Optional()])
    newpassword = PasswordField("Password",
                                validators=[Length(min=10, message="Passwords must be more than 10 characters"),
                                            Optional()])

    def validate_newpassword(self, field):
        # Firefox password manager only provides upper, lower, and number passwords
        alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        alphaLower = alphaUpper.lower()
        nums = "1234567890"
        if not ((1 in [c in alphaUpper for c in field.data]) and (1 in [c in alphaLower for c in field.data]) and
                (1 in [c in nums for c in field.data])):
            raise ValidationError('Password must contain at least 1 upper, 1 lower, and 1 number.')

    repeatpassword = PasswordField("Confirm Password",
                                   validators=[Optional(), EqualTo('newpassword', message='Passwords must match')])
    notes = TextAreaField("User Notes")
    submit = SubmitField("Update User")

class UserPasswordResetForm(FlaskForm):
    newpassword = PasswordField("New Password",
                                validators=[Length(min=10, message="Passwords must be more than 10 characters"),
                                            InputRequired()])

    def validate_newpassword(self, field):
        alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        alphaLower = alphaUpper.lower()
        nums = "1234567890"
        if not ((1 in [c in alphaUpper for c in field.data]) and (1 in [c in alphaLower for c in field.data]) and
                (1 in [c in nums for c in field.data])):
            raise ValidationError('Password must contain at least 1 upper, 1 lower, and 1 number.')

    repeatpassword = PasswordField("Confirm Password",
                                   validators=[InputRequired(), EqualTo('newpassword', message='Passwords must match')])
    submit = SubmitField("Update Password")

class UserLoginForm(FlaskForm):
    username = StringField("User Name*", validators=[InputRequired()])
    password = PasswordField("Password*", validators=[InputRequired()])
    submit = SubmitField("Log In")

# Flask

def superuser(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@defaultapp.before_request
def before_request():
    session.permanent = True
    defaultapp.permanent_session_lifetime = timedelta(minutes=45)

@login_manager.user_loader
def user_loader(userid):
    userquery = users.query.filter(users.id == userid).first()
    return userquery

@login_manager.unauthorized_handler
def unauthorized():
    logthis(f"Unauthorized: URL: {request.url} IP: {request.remote_addr} UserAgent: {request.user_agent}")
    return redirect(url_for("index"))

@login_manager.request_loader
def load_user_from_request(request):
    logthis(f"load_user_from_request: {request}")
    return None

@defaultapp.route('/', methods=["GET"])
@defaultapp.route('/index.html', methods=["GET"])
def index():
    links = [{'url': '/index.html', 'display': '<i class="material-icons left">home</i>Main</a>'}]
    navbar = elements.NavBar(links=links)
    if current_user.is_authenticated:
        return redirect(url_for("switchboard"))
    return render_template('index.html', navbar=navbar)

@defaultapp.route('/login.html', methods=["GET", "POST"])
def login():
    links = [{'url': '/index.html', 'display': '<i class="material-icons left">home</i>Main</a>'}]
    navbar = elements.NavBar(links=links)
    userlogin = UserLoginForm()
    error = False
    errortype = ""
    if current_user.is_authenticated:
        return redirect(url_for("switchboard"))
    if userlogin.validate_on_submit():
        thisuser = users.query.filter(users.username.like(userlogin.username.data.strip())).one_or_none()
        if thisuser:
            if thisuser.active:
                if hashme(userlogin.password.data) == thisuser.userpasswordhash:
                    thisuser.authenticated = True
                    db.session.add(thisuser)
                    db.session.commit()
                    login_user(thisuser, remember=True, duration=timedelta(minutes=45))
                    logthis(f"User Logged In: {userlogin.username.data}")
                    return redirect(url_for("switchboard"))
                else:
                    logthis(f"Password Login Failed: {userlogin.username.data}")
                    error = True
                    errortype = "password"
            else:
                error = True
                errortype = "activation"
        else:
            logthis(f"User Login Failed: {userlogin.username.data}")
            error = True
            errortype = "username"
    return render_template("login.html", userlogin=userlogin, error=error, errortype=errortype, navbar=navbar)

@defaultapp.route('/logout.html', methods=["GET"])
@login_required
def logout():
    thisuser = current_user
    thisuser.authenticated = False
    db.session.add(thisuser)
    db.session.commit()
    logthis(f"User {thisuser.username} Logged out.")
    logout_user()
    return redirect(url_for("index"))

@defaultapp.route('/switchboard.html', methods=["GET", "POST"])
@login_required
def switchboard():
    links = [{'url': '/switchboard.html', 'display': '<i class="material-icons left">home</i>Main</a>'}]
    navbar = elements.NavBar(links=links)
    return render_template("switchboard.html", navbar=navbar)

@defaultapp.route('/admingetusers.html')
@login_required
@superuser
def admingetusers():
    links = [{'url': '/switchboard.html', 'display': '<i class="material-icons left">home</i>Main</a>'},
             {'url': '#!', 'display': 'List User'}]
    navbar = elements.NavBar(links=links)
    qusers = users.query.all()
    return render_template("admingetusers.html", users=qusers, navbar=navbar)

@defaultapp.route('/adminupdateuser.html', methods=["GET", "POST"])
@login_required
@superuser
def adminupdateuser():
    navlinks = [{'url': '/switchboard.html', 'display': '<i class="material-icons left">home</i>Main</a>'},
             {'url':'/admingetusers.html', 'display':' List Users'},
             {'url':'#!', 'display':'Update User'}]
    navbar = elements.NavBar(links=navlinks)
    confirm = False
    confirmlinks = [
        {'url': '/admingetusers.html', 'display': 'Edit Other Users', 'color': 'fgSNOW bgORANGE'},
        {'url': '/adminupdateuser.html', 'display': 'Create New User', 'color': 'fgSNOW bgBLUE'},
        {'url': '/switchboard.html', 'display': 'Return', 'color': 'fgSNOW bgGOLD'}
    ]
    userdataupdateform = UserDataUpdateForm()
    if request.values.get("uuid"):
        thisuser = users.query.filter(users.uuid == request.values.get("uuid")).one_or_none()
        if request.method == "GET":
            userdataupdateform.username.data = thisuser.username
            userdataupdateform.usertype.data = thisuser.usertype
            userdataupdateform.active.data = thisuser.active
            userdataupdateform.id.data = thisuser.id
            userdataupdateform.uuid.data = thisuser.uuid
            userdataupdateform.notes.data = thisuser.notes
        elif request.method == "POST":
            if userdataupdateform.validate_on_submit():
                confirm = elements.ConfirmBar(links=confirmlinks, message="User Updated")
                thisuser.username = userdataupdateform.username.data.strip().lower()
                thisuser.usertype = int(userdataupdateform.usertype.data)
                if userdataupdateform.newpassword.data:
                    thisuser.userpasswordhash = hashme(userdataupdateform.newpassword.data)
                thisuser.active = userdataupdateform.active.data
                thisuser.notes = userdataupdateform.notes.data
                db.session.commit()
                logthis(f"WARN: {current_user.username} Updated User: {request.values.get('uuid')} {thisuser.username} {thisuser.usertype}")
    else:
        if request.method == "POST" and userdataupdateform.validate_on_submit():
            confirm = elements.ConfirmBar(links=confirmlinks, message="User Updated")
            username = userdataupdateform.username.data
            usertype = userdataupdateform.usertype.data
            userpasswordhash = hashme(userdataupdateform.newpassword.data)
            usernotes = userdataupdateform.notes.data
            active = userdataupdateform.active.data
            newuser = users(username=username, usertype=usertype, userpasswordhash=userpasswordhash, active=active, notes=usernotes)
            db.session.add(newuser)
            db.session.commit()
            logthis(f"WARN: {current_user.username} Created User: {username} {usertype}")
    return render_template("adminupdateuser.html", userdataupdateform=userdataupdateform, confirm=confirm, navbar=navbar)

# Flask App

if __name__ == "__main__":
    defaultapp.run(debug=False, host="127.0.0.1", port=5550)
