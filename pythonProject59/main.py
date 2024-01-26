from flask import Flask, render_template, request, url_for, flash, redirect, current_app
from flask_sqlalchemy import SQLAlchemy
from forms import (SigninForm, LoginForm, MekanicForm, ChangePassword, EditProfileForm, ContactUsForm, ResetRequestForm,
                   PasswordResetForm)
from flask_bootstrap import Bootstrap4
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required
import os
from twilio.rest import Client
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


TWILIO_ACCOUNT_SID = "ACb0dc1c32c958b74af2bf2334026949df"
TWILIO_AUTH_TOKEN = "c16a75d8514bbd06c80df10d59639749"
TWILIO_PHONE = +13123865170


app = Flask(__name__)

db = SQLAlchemy()

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mekanic.db"

app.config['SECRET_KEY'] = 'any secret string'

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "isedeemmanuel26@gmail.com"
app.config["MAIL_PASSWORD"] = "Austin200*556"

mail = Mail(app)

db.init_app(app)

bootstrap = Bootstrap4(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # phone = db.Column(db.Integer, nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return db.session.execute(db.select(User).where(User.id == user_id))
            #User.query.get(user_id)

    def __repr__(self):
        return f"User({self.name}, {self.email})"


with app.app_context():
    db.create_all()


class MechanicList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.Integer, nullable=False, unique=True)
    specialty = db.Column(db.String(30), nullable=False)


with app.app_context():
    db.create_all()


class ContactUs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    message = db.Column(db.String, nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route("/", methods=["POST", "GET"])
def home():
    return render_template("mekanic.html", current_user=current_user)


@app.route("/signup", methods=["POST", "GET"])
def signup():
    form = SigninForm()
    if form.validate_on_submit():
        user_email = request.form.get("email")
        existing_user = db.session.execute(db.select(User).where(User.email == user_email)).scalar()
        if existing_user:
            form = LoginForm()
            flash("Account already exist for this email, kindly login")
            return redirect(url_for("login", form=form))
        else:
            password = generate_password_hash(password=request.form.get("password"), salt_length=6, method="pbkdf2:sha1")
            user = User(name=request.form.get("name"), email=request.form.get("email"), password=password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("You are welcome")
            content = db.session.execute(db.select(MechanicList).order_by(MechanicList.name)).scalars()
            return render_template("full_list.html", content=content,
                                   name=user.name, current_user=current_user)

    return render_template("signup.html", form=form, current_user=current_user)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = request.form.get("email")
        user_password = request.form.get("password")
        user = db.session.execute(db.select(User).where(User.email == user_email)).scalar()
        if not user:
            flash("Email account does not exist, please check your input and try again")
            return render_template("login.html", form=form)
        elif not check_password_hash(user.password, user_password):
            flash("Your password entry is incorrect, try again.")
            return render_template("login.html", form=form)
        else:
            flash("You are welcome")
            content = db.session.execute(db.select(MechanicList).order_by(MechanicList.name)).scalars()
            login_user(user)
            return render_template("full_list.html", content=content, name=user.name,
                                   current_user=current_user)
    return render_template("login.html", form=form)


@app.route("/add-mechanic", methods=["POST", "GET"])
def add_mechanic():
    form = MekanicForm()
    if form.validate_on_submit():
        mechanic = MechanicList(name=request.form.get("name"),
                                location=request.form.get("location"),
                                phone=request.form.get("phone"),
                                specialty=request.form.get("car_specialty"))
        with app.app_context():
            db.session.add(mechanic)
            db.session.commit()
        mekanic_list = db.session.execute(db.select(MechanicList).order_by(MechanicList.name)).scalars()
        return render_template("full_list.html", content=mekanic_list)
    return render_template("add_mechanic.html", form=form)


@app.route('/profile')
@login_required
def profile():
    flash("Here is your profile")
    return render_template('profile.html', current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/change-password", methods=["POST", "GET"])
@login_required
def change_password():
    form = ChangePassword()
    if form.validate_on_submit():
        user = db.get_or_404(User, current_user.id)
        updated_password = request.form.get("new_password")
        hashed_password = generate_password_hash(password=updated_password, salt_length=6, method="pbkdf2:sha1")
        user.password = hashed_password
        db.session.commit()
        flash("Password successfully updated")
        mekanic_list = db.session.execute(db.select(MechanicList).order_by(MechanicList.name)).scalars()
        return render_template("full_list.html", name=current_user.name, content=mekanic_list, current_user=current_user)
    return render_template("editprofile.html", form=form)


@app.route("/edit-password", methods=["POST", "GET"])
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        flash("Profile successfully updated")
        user = db.get_or_404(User, current_user.id)
        new_name = request.form.get("name")
        user.name = new_name
        db.session.commit()
        return render_template("profile.html", current_user=current_user)
    return render_template("editprofile.html", form=form, current_user=current_user)


@app.route("/full-list", methods=["POST", "GET"])
@login_required
def full_list():
    mekanic_list = db.session.execute(db.select(MechanicList).order_by(MechanicList.name)).scalars()
    return render_template("full_list.html", name=current_user.name, content=mekanic_list, current_user=current_user)


@app.route("/about")
def about():
    with open("./templates/about.txt") as file:
        content = file.read()
    return render_template("about.html", content=content, redirect=redirect)


@app.route("/mechanic-item/<id_>", methods=["GET"])
@login_required
def mechanic_item(id_):
    mechanic = db.get_or_404(MechanicList, id_)
    return render_template("mechanic_item.html", current_user=current_user, mechanic=mechanic)


@app.route("/Contact-Us", methods=["POST", "GET"])
@login_required
def contact_us():
    form = ContactUsForm()
    if form.validate_on_submit():
        flash("You successfully contacted us via our Contact Us button option. We will send a reply to the mail address"
              " provided, thank you.")
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")
        contactus = ContactUs(name=name, email=email, message=message)
        db.session.add(contactus)
        db.session.commit()
        msg = Message(subject=f"{name}", sender="isedeemmanuel26@gmail.com", body=f"{message}",
                      recipients=["isedeemmanuel26@gmail.com"])

        # mail.send(msg)
        return redirect(url_for("home", message=message))
    return render_template("contactus.html", form=form)


def send_mail(user):
    token = user.get_reset_token()
    msg = Message("Password Reset Request", recipients=[user.email], sender="isedeemmanuel26@gmail.com")
    msg.body = f""" To reset password, please follow the link below.
    {url_for("password_reset", token=token, _external=True)}
    
    If you didn't send a password reset request, kindly ignore this message. 
    """
    mail.send(msg)


@app.route("/Forgot-password", methods=["POST", "GET"])
def forgot_password():
    form = ResetRequestForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            send_mail(user)
            flash("Hi there! Kindly check your email to reset your password", "success")
            #check how password reset happen in real websites and code written for it
            return redirect(url_for("login"))
        else:
            flash("No account for this email exist. Kindly try again", "warning")
            return render_template("request_reset.html", form=form)
    return render_template("request_reset.html", form=form)


@app.route("/reset_password/<token>", methods=["POST", "GET"])
def password_reset(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is invalid or expired token, please try again.", "warning")
        return redirect(url_for("forgot_password"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        password = generate_password_hash(password=request.form.get("password"), salt_length=6, method="pbkdf2:sha1")
        user.password = password
        db.session.commit()
        flash("Password successfully changed. Please Login", "success")
        return redirect(url_for("login"))
    return render_template("password_reset.html", form=form)


@app.route("/rating")
@login_required
def rating():
    return render_template("rating.html")

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
