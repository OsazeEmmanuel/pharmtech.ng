from flask import Flask, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, InputRequired, EqualTo


class SigninForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    # phone = IntegerField("Phone Number", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', [InputRequired(), EqualTo('password',
                                                                               message='Passwords must match')])
    terms_conditions = BooleanField('I accept the terms, conditions and privacy policy', validators=[DataRequired()])
    submit = SubmitField("Sign up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class MekanicForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    location = StringField("Location", validators=[DataRequired()])
    phone = IntegerField("Phone", validators=[DataRequired()])
    car_specialty = StringField("Car Specialty", validators=[DataRequired()])
    submit = SubmitField("Add to Mechanic List")


class ChangePassword(FlaskForm):
    new_password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', [InputRequired(), EqualTo('new_password',
                                                                                   message='Passwords must match')])
    button = SubmitField("Change Password")


class EditProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    button = SubmitField("Change name")


class ContactUsForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")


class ResetRequestForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    submit = SubmitField("Password Reset Request")


class PasswordResetForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', [InputRequired(), EqualTo('password',
                                                                                   message='Passwords must match')])
    button = SubmitField("Reset Password")



