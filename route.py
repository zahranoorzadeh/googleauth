import os
import pathlib
import requests
from flask import Blueprint, render_template, flash, url_for, session, abort, redirect, request,Flask
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from __init__ import db   
from flask_login import login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import random
import string
from pip._vendor import cachecontrol
from flask_migrate import Migrate
import finnhub

app = Flask(__name__)

z = Blueprint('z', __name__)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app.secret_key = 'efdgdrgersdgrsgf rsdgfrsgg'
migrate = Migrate(app, db)


client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
finnhub_client = finnhub.Client(api_key="cmd9ra1r01qip5t7i7o0cmd9ra1r01qip5t7i7og")


GOOGLE_CLIENT_ID = "693577928815-kh9rqupbp8jp5a3tocf7a9n5jtamvvj6.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"



flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback",
)



@z.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('z.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@z.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('passwordC')
        password2 = request.form.get('passwordR')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:

            new_user = User(email=email, first_name = first_name, password=generate_password_hash( password1, method='pbkdf2:sha256' ))

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('z.home'))



    return render_template("sign_up.html", user=current_user)

@z.route('/login-google')
def login_bygoogle():

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@z.route('/callback')
def callback():



    flow.fetch_token(authorization_response=request.url)



    if not session["state"] == request.args["state"]:
        abort(500)  



    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
        
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        plain_password = ''.join(random.choice(string.ascii_letters) for i in range(10))
        hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')



        new_user = User(
            email=session["email"],
            first_name=session["name"],
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    flash('Logged in successfully!', category='success')
    login_user(user, remember=True)
    return redirect(url_for('z.home'))



@z.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('z.login'))



@z.route("/about")
def about():
    return render_template("about.html",user=current_user)


@z.route('/', methods=['GET', 'POST'])
@login_required

def home():
    try:
        news = finnhub_client.general_news('general', min_id=0)
        return render_template('home.html', news=news,user=current_user)
    except Exception as e:
        return render_template('home.html',user=current_user)

@z.route('/share_on_twitter')
def share_on_twitter():
    text_to_share = " this is a flask app by google auth and share to tweeter"
    url_to_share = request.args.get('url', 'http://127.0.0.1:5000')
    return render_template('share_template.html', text=text_to_share, url=url_to_share)