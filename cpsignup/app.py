from flask import Flask, render_template, url_for, flash, redirect,request
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager,UserMixin,login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo,ValidationError



app = Flask(__name__, static_url_path='/static')

app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quelin.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'



class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    form = db.relationship('form', backref='items', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    complete=db.Column(db.Boolean,default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"form('{self.content}', '{self.date_posted}')"

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    # username = StringField('Username')
    # email = StringField('Email')
    # password = PasswordField('Password', validators=[DataRequired()])
    # confirm_password = PasswordField('Confirm Password',
    #                                  validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('username already exist. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('email already exist. Please choose a different one.')
   
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
    # email = StringField('Email')
    # password = PasswordField('Password')
    # remember = BooleanField('Remember Me')
    # submit = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/index")
@login_required
def index():
    forms=form.query.filter_by(user_id=current_user.id)
    return render_template('index.html',forms=forms)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful.', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('Logout successful.', 'success')
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    
    return render_template('account.html', title='Account')

@app.route("/add",methods=["POST"])
@login_required
def add():
    user_id=current_user.id
    if request.form['formitem'] != "" :
        forms=form(content=request.form['formitem'],complete=False,user_id=user_id)
        db.session.add(forms)
        db.session.commit()
    else:
        flash('cannot add empty list', 'danger')
        return redirect(url_for("index"))
        
    return redirect(url_for("index"))


@app.route("/complete/<int:id>")
@login_required
def complete(id):
    form= form.query.get(id)

    if not form:
        return redirect("/index")

    if form.complete:
        form.complete=False
    else:
        form.complete=True

    db.session.add(form)
    db.session.commit()
    
    return redirect("/index")

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    form=form.query.get(id)
    if not form:
        return redirect("/index")
    
    db.session.delete(form)
    db.session.commit()

    return redirect("/index")




if __name__ == '__main__':
    app.run()