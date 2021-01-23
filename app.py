from flask import Flask, render_template, redirect, request, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from datetime import datetime, timedelta, date
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, HiddenField, FileField, SelectField, \
    TextAreaField, DateField, DateTimeField, SelectMultipleField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired, NoneOf, ValidationError, Optional
import hashlib
import uuid

defaultapp = Flask(__name__)
defaultapp.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
#TODO: Change this key!
defaultapp.config['SECRET_KEY'] = 'ansdv898hw9vrhq34nkjntgir9abeee8r7voeinv5i4ungdsjfbgvdsbduyb87hrn5bvurh354iu5bn7ve'
defaultapp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
defaultapp.config['TESTING'] = False

#TODO: Change this key!
bigkey = "892y301t98h913409gh934h9014hf134h987538y9gh352984bh2953924895"

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
    db.session.add(logs(data))
    db.session.commit()

# Data Models
class users(db.Model):
    __tablename__ = "users"
    active = db.Column(db.Boolean, nullable=False)
    authenticated = db.Column(db.Boolean, nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(32), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    passwordhash = db.Column(db.String(64), nullable=False)
    usertype = db.Column(db.Integer, nullable=False)
    # normally 1=user ... 99=admin

    def create(self):
        db.session.add(self)
        db.session.commit()
        return self

    def __init__(self, username, passwordhash, usertype):
        self.uuid = getuuidhash()
        self.username = username
        self.passwordhash = passwordhash
        self.usertype = int(usertype)
        self.active = True
        self.authenticated = False

    def is_admin(self):
        if self.usertype > 10:
            return True
        else:
            return False

    def is_active(self):
        return self.active

    def get_id(self):
        return self.username

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
        return '{}:"{}"'.format(self.id, self.data)

# Build Database
db.create_all()

#default data

user = users.query.filter(users.username.like("administrator")).one_or_none()
if not user:
    administrator = users(username="administrator", passwordhash=hashme("ThisIsThePassword123456!@#$%^"), usertype=99)
    db.session.add(administrator)
    db.session.commit()
    logthis("WARN: Administrator Account Created.")

# WTForms
class UserDataCreateForm(FlaskForm):
    username = StringField("User Name*", validators=[InputRequired()])
    usertype = SelectField("User Type*", choices=[(1, "Basic User"), (99, "Administrator")])
    newpassword = PasswordField("Password",
                                validators=[Length(min=10, message="Passwords must be more than 10 characters"),
                                            InputRequired()])
    def validate_newpassword(self, field):
        #Firefox password manager only provides upper, lower, and number passwords
        alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        alphaLower = alphaUpper.lower()
        nums = "1234567890"
        if not ((1 in [c in alphaUpper for c in field.data]) and (1 in [c in alphaLower for c in field.data]) and
                (1 in [c in nums for c in field.data])):
            raise ValidationError('Password must contain at least 1 upper, 1 lower, and 1 number.')
    repeatpassword = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo('newpassword', message='Passwords must match')])
    submit = SubmitField("Create User")

class UserDataUpdateForm(FlaskForm):
    username = StringField("User Name*", validators=[InputRequired()])
    usertype = SelectField("User Type*", choices=[(1, "Basic User"), (99, "Administrator")])
    active = BooleanField("Active?", validators=[DataRequired()])
    id = HiddenField(validators=[Optional()])
    uuid = HiddenField(validators=[Optional()])
    newpassword = PasswordField("Password",
                                validators=[Length(min=10, message="Passwords must be more than 10 characters"),
                                            Optional()])
    def validate_newpassword(self, field):
        #Firefox password manager only provides upper, lower, and number passwords
        alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        alphaLower = alphaUpper.lower()
        nums = "1234567890"
        if not ((1 in [c in alphaUpper for c in field.data]) and (1 in [c in alphaLower for c in field.data]) and
                (1 in [c in nums for c in field.data])):
            raise ValidationError('Password must contain at least 1 upper, 1 lower, and 1 number.')
    repeatpassword = PasswordField("Confirm Password", validators=[Optional(), EqualTo('newpassword', message='Passwords must match')])
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
    repeatpassword = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo('newpassword', message='Passwords must match')])
    submit = SubmitField("Update Password")

class UserLoginForm(FlaskForm):
    username = StringField("User Name*", validators=[InputRequired()])
    password = PasswordField("Password*", validators=[InputRequired()])
    submit = SubmitField("Log In")

# Flask

@defaultapp.before_request
def before_request():
    session.permanent = True
    defaultapp.permanent_session_lifetime = timedelta(minutes=45)

@login_manager.user_loader
def user_loader(username):
    return users.query.get(username)

@login_manager.unauthorized_handler
def unauthorized():
    logthis("Unauthorized: URL: {} IP: {} UserAgent: {}".format(request.url, request.remote_addr, request.user_agent))
    return redirect(url_for("login"))

@login_manager.request_loader
def load_user_from_request(request):
    logthis("load_user_from_request: {}".format(request))
    return None

@defaultapp.route('/', methods=["GET", "POST"])
@defaultapp.route('/index.html', methods=["GET", "POST"])
def index():
    return render_template('index.html')

@defaultapp.route('/login.html', methods=["GET", "POST"])
def login():
    userlogin = UserLoginForm()
    error = False
    errortype = ""
    if userlogin.validate_on_submit():
        thisuser = users.query.filter(users.username.like(userlogin.username.data.strip())).one_or_none()
        if thisuser:
            if thisuser.active:
                if hashme(userlogin.password.data) == thisuser.passwordhash:
                    thisuser.authenticated = True
                    db.session.add(thisuser)
                    db.session.commit()
                    login_user(thisuser, remember=True, duration=timedelta(minutes=45))
                    logthis("User Logged In: {}".format(userlogin.username.data))
                    return redirect(url_for("switchboard"))
                else:
                    logthis("Password Login Failed: {}".format(userlogin.username.data))
                    error = True
                    errortype = "password"
            else:
                error = True
                errortype = "activation"
        else:
            logthis("User Login Failed: {}".format(userlogin.username.data))
            error = True
            errortype = "username"
    return render_template("login.html", userlogin=userlogin, error=error, errortype=errortype)

@defaultapp.route('/logout.html', methods=["GET"])
@login_required
def logout():
    thisuser = current_user
    thisuser.authenticated = False
    db.session.add(thisuser)
    db.session.commit()
    logthis("User {} Logged out.".format(thisuser.username))
    logout_user()
    return redirect(url_for("userRegister"))

@defaultapp.route('/switchboard.html', methods=["GET", "POST"])
@login_required
def switchboard():
    return render_template("switchboard.html")

@defaultapp.route('/admincreateuser.html', methods=["GET", "POST"])
@login_required
def admincreateuser():
    if current_user.is_admin():
        confirm = False
        error = False
        userdatacreateform = UserDataCreateForm
        if userdatacreateform.validate_on_submit():
            #request is post and form is filled and valid
            confirm = True
            username = userdatacreateform.username.data.strip().lower()
            usertype = int(userdatacreateform.usertype.data)
            userpassword = hashme(userdatacreateform.newpassword.data)
            newuser = users(username=username, usertype=usertype, passwordhash=userpassword)
            db.session.add(newuser)
            db.session.commit()
            logthis("WARN: {} Created New User: {} {}".format(current_user.username, username, usertype))
        else:
            if not userdatacreateform.validate_on_submit():
                #form is invalid
                error = True
                confirm = True
        return render_template("admincreateuser.html", userdatacreateform=userdatacreateform, error=error, confirm=confirm)
    else:
        return redirect(url_for("switchboard"))

@defaultapp.route('/adminupdateuser.html', methods=["GET", "POST"])
@login_required
def adminupdateuser():
    if current_user.is_admin() and request.values.get("uuid"):
        confirm = False
        error = False
        userdataupdateform = UserDataUpdateForm
        thisuser = users.query.filter(users.uuid == request.values.get("uuid")).one_or_none()
        if request.method == "GET":
            userdataupdateform.username.data = thisuser.username
            userdataupdateform.usertype.data = thisuser.usertype
            userdataupdateform.active.data = thisuser.active
        else:
            if userdataupdateform.validate_on_submit():
                #request is post and form is filled and valid
                confirm = True
                username = userdataupdateform.username.data.strip().lower()
                usertype = int(userdataupdateform.usertype.data)
                userpassword = hashme(userdataupdateform.newpassword.data)
                newuser = users(username=username, usertype=usertype, passwordhash=userpassword)
                db.session.add(newuser)
                db.session.commit()
                logthis("WARN: {} Updated User: {} {} {}".format(current_user.username, request.values.get("uuid"), username, usertype))
            else:
                if not userdataupdateform.validate_on_submit():
                    #form is invalid
                    error = True
                    confirm = True
        return render_template("adminupdateuser.html", userdataupdateform=userdataupdateform, error=error, confirm=confirm)
    else:
        return redirect(url_for("switchboard"))

# Flask App

if __name__ == "__main__":
    defaultapp.run(debug=False, host="127.0.0.1", port=5550)
