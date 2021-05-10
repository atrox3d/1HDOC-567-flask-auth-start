# https://www.udemy.com/course/100-days-of-code/learn/lecture/22827443#questions

import logging

import flask_sqlalchemy
from flask import (
    Flask,
    render_template,
    request,
    url_for,
    redirect,
    flash,
    send_from_directory
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_sqlalchemy import (
    SQLAlchemy,
    # sqlalchemy
)

from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError
)

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user
)

import util.network
import util.logging

util.logging.get_root_logger()
logger = logging.getLogger(__name__)

# create flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-yup!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# init db
db = SQLAlchemy(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # plainpassword = db.Column(db.String(100))


# reset db at every run
logger.warning("DELETING tables")
db.drop_all()
# Line below only required once, when creating DB.
logger.info("creating tables")
db.create_all()

# init login manager
login_manager = LoginManager()
login_manager.init_app(app)


#
#   called by flask before every route
#
@login_manager.user_loader
@util.logging.log_decorator()
def load_user(user_id):
    logger.info(f"query user with {user_id=}")
    user = User.query.get(user_id)
    logger.info(f"{user=}")
    return user


@app.route('/')
@util.logging.log_decorator()
def home():
    logger.info("rendering index.html")
    return render_template("index.html", loggedin=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
@util.logging.log_decorator()
def register():
    logger.info(f"{request.method=}")
    if request.method == "POST":
        #
        #   POST: get values from register form
        #
        logger.info(f"{request.form=}")
        #
        #   create hashed password
        #
        plaintext_password = request.form.get("password")
        hashed_password = generate_password_hash(
            request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )
        #
        #   create new user
        #
        user = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=hashed_password,
        )

        logger.info("add user:")
        logger.info(f"{user.name=}")
        logger.info(f"{user.email=}")
        logger.info(f"{plaintext_password=}")
        logger.info(f"{user.password=}")
        #
        #   add new user to db
        #
        try:
            db.session.add(user)
            db.session.commit()
            #
            #   if succesful authenticates user
            #
            logger.info(f"logging in {user=}")
            login_user(user)
            #
            #   redirect to privare area
            #
            url = url_for("secrets", loggedin=current_user.is_authenticated)
            logger.info(f"redirect to {url=}")
            return redirect(url)
        except IntegrityError as e:
            logger.critical(e)
            logger.critical(repr(e))
            flash(f"email {user.email} already registered")
        except SQLAlchemyError as e:
            logger.critical(e)
            logger.critical(repr(e))
            flash(f"Critical Database Error, please try again later")

    #
    #   GET or register fail: render register form
    #
    logger.info(f"render register.html")
    return render_template("register.html", loggedin=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
@util.logging.log_decorator()
def login():
    logger.info(f"{request.method=}")
    if request.method == 'POST':
        #
        #   POST: get values from login form
        #
        email = request.form.get('email')
        password = request.form.get('password')

        logger.info("authenticate user:")
        logger.info(f"{email=}")
        logger.info(f"{password=}")
        #
        #   try to load user from db
        #
        user = User.query.filter_by(email=email).first()
        logger.info(f"found {user=}")
        if not user:
            flash(f"email {email} not found, please register")
            url = url_for('register', loggedin=current_user.is_authenticated)
            return redirect(url)
        #
        #   check password against hashed password
        #
        logger.info(f"checking {password=}")
        if check_password_hash(user.password, password):
            #
            #   if succesful authenticates user
            #
            logger.info(f"SUCCESS| logging in")
            login_user(user)
            #
            #   redirect to privare area
            #
            flash("login completed succesfully!")
            url = url_for("secrets", loggedin=current_user.is_authenticated)
            logger.info(f"redirect to {url=}")
            return redirect(url)
        flash("wrong password, try again")
    #
    #   GET or login fail: render login form
    #
    logger.info(f"render login.html")
    return render_template("login.html", loggedin=current_user.is_authenticated)


@app.route('/secrets')
@login_required
@util.logging.log_decorator()
def secrets():
    #
    #   current_user is a flask global object just like request
    #
    logger.info(f"{current_user.name=}")
    logger.info(f"render secrest.html with name={current_user.name}")
    return render_template("secrets.html", name=current_user.name, loggedin=current_user.is_authenticated)


@app.route('/download/<path:filename>')
@login_required
@util.logging.log_decorator()
def download(filename):
    logger.info(f"send_from_directory 'static' filename=files/{filename}")
    return send_from_directory('static', filename=f"files/{filename}")


@app.route('/logout')
# @login_required
@util.logging.log_decorator()
def logout():
    """
    logs out user and redirects to home
    """
    logger.info("logout_user")
    logout_user()

    url = url_for('home', loggedin=current_user.is_authenticated)
    logger.info(f"redirect to {url=}")
    return redirect(url)


if __name__ == "__main__":
    app.run(
        debug=True,
        host=util.network.get_ipaddress()
    )
