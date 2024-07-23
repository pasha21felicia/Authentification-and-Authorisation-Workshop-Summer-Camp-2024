from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
import os
from dotenv import load_dotenv
load_dotenv()

## TO DO
# Task 1: Definiti cheia secreta folosita la hashing
JWT_SECRET_KEY = ''

# se defineste aplicatia
app_auth = Flask(__name__)

## TO DO
# Task 2: Definiti politica de CORS
CORS(app_auth, resources={r"/*": {"origins": "*"}})


# setam conexiunea la baza de date sqlite
# baza de date va fi salvata intr-un fisier app.db
db_path = os.path.join(os.path.dirname(__file__), 'app.db')
db_uri = 'sqlite:///{}'.format(db_path)


# configurari de baza pentru flask
app_auth.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app_auth.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app_auth.config['WTF_CSRF_ENABLED'] = False
app_auth.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY


# definim instantele necesare pentru flask
db = SQLAlchemy(app_auth)
ma = Marshmallow(app_auth)
bcrypt = Bcrypt(app_auth)
jwt = JWTManager(app_auth)
