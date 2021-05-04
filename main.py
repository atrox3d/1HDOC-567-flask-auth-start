import logging

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import util.network
import util.logging

util.logging.get_root_logger()
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret-key-yup!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# def dump_config():
#     for k, v in sorted(app.config.items()):
#         align = ">"
#         width = 30
#         logger.info(f"{k:{align}{width}} : {v}")


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # plainpassword = db.Column(db.String(100))


# Line below only required once, when creating DB.
logger.warning("DELETING tables")
db.drop_all()
logger.info("creating tables")
db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


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
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
@util.logging.log_decorator()
def register():
    logger.info(f"{request.method=}")
    if request.method == "POST":
        logger.info(f"{request.form=}")
        hashed_password = generate_password_hash(
            request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )
        user = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=hashed_password,
        )
        logger.info("add user:")
        logger.info(f"{user.name=}")
        logger.info(f"{user.email=}")
        logger.info(f"{user.password=}")
        db.session.add(user)
        db.session.commit()

        logger.info(f"logging in {user=}")
        login_user(user)

        url = url_for("secrets")
        logger.info(f"redirect to {url=}")
        return redirect(url)
    else:
        logger.info(f"render register.html")
        return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
@util.logging.log_decorator()
def login():
    logger.info(f"{request.method=}")
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        logger.info("authenticate user:")
        logger.info(f"{email=}")
        logger.info(f"{password=}")

        user = User.query.filter_by(email=email).first()
        logger.info(f"found {user=}")

        logger.info(f"checking {password=}")
        if check_password_hash(user.password, password):
            logger.info(f"SUCCESS| logging in")
            login_user(user)

            url = url_for("secrets")
            logger.info(f"redirect to {url=}")
            return redirect(url)
    else:
        logger.info(f"render login.html")
        return render_template("login.html")


@app.route('/secrets')
@login_required
@util.logging.log_decorator()
def secrets():
    # name = request.args.get("name")
    logger.info(f"{current_user.name=}")
    logger.info(f"render secrest.html with name={current_user.name}")
    return render_template("secrets.html", name=current_user.name)


@app.route('/download/<path:filename>')
@login_required
@util.logging.log_decorator()
def download(filename):
    logger.info(f"send_from_directory 'static' filename=files/{filename}")
    return send_from_directory('static', filename=f"files/{filename}")


@app.route('/logout')
@login_required
@util.logging.log_decorator()
def logout():
    logger.info("logout_user")
    logout_user()

    url = url_for('home')
    logger.info(f"redirect to {url=}")
    return redirect(url)


if __name__ == "__main__":
    app.run(
        debug=True,
        host=util.network.get_ipaddress()
    )
