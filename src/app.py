from flask import Flask, redirect, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, logout_user, LoginManager, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate, upgrade
from flask.cli import with_appcontext


app = Flask(__name__)
bcrypt = Bcrypt(app)
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'S3cR3t'
db.init_app(app)
Bootstrap(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_"


def drop_tables():
    """Drop all tables."""
    db.drop_all()
    print("Dropped all tables.")


def create_tables():
    """Create all tables."""
    db.create_all()
    print("Created all tables.")


def upgrade_tables():
    """Upgrade the database schema."""
    upgrade()
    print("Upgraded database schema.")


def init_db():
    """Initialize the database."""
    drop_tables()
    create_tables()
    print("Initialized the database.")


@app.cli.command("initdb")
@with_appcontext
def initdb_command():
    """Initialize the database."""
    init_db()


@app.cli.command("drop_db")
@with_appcontext
def drop_db_command():
    """Drop all tables."""
    drop_tables()


@app.cli.command("create_db")
@with_appcontext
def create_db_command():
    """Create all tables."""
    create_tables()


@app.cli.command("upgrade_db")
@with_appcontext
def upgrade_db_command():
    """Upgrade the database schema."""
    upgrade_tables()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


# Create all tables within the Flask application context
# with app.app_context():
#     db.create_all()


class RegisterForm(FlaskForm):
    name = StringField(
        validators=[InputRequired(), Length(min=1, max=100)],
        render_kw={"placeholder": "Full Name"}
    )
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    email = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Email"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Password"}
    )
    verify_password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Retype Password"}
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()

        if existing_username:
            raise ValidationError("This username already exists. Please choose another")

    def validate_password(self, password):
        if password.data != self.verify_password.data:
            raise ValidationError("Passwords do not match")


class LoginForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=8, max=20)],
        render_kw={"placeholder": "Password"}
    )
    submit = SubmitField("Login")


@app.route('/')
def index_():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login_():
    form = LoginForm()
    message = ""
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home_'))
        else:
            message = "Wrong Username or Password"
            flash(message, 'danger')

    return render_template('login.html', form=form, message=message)


@app.route('/register', methods=['GET', 'POST'])
def register_():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.name.data,
                        username=form.username.data,
                        email=form.email.data,
                        password=hashed_password,
                        is_active=True)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login_'))
    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout_():
    logout_user()
    return redirect(url_for('login_'))


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home_():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True)
