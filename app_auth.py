from datetime import timedelta

from flask import jsonify
from flask_jwt_extended import (
    jwt_required, create_access_token, current_user, unset_jwt_cookies,
)
from flask_jwt_extended.exceptions import JWTExtendedException

from config import db, app_auth, bcrypt, jwt
from forms import RegistrationForm, LoginForm
from models import User, UsersSchema
import json
from dotenv import load_dotenv

## Se definesc schemele tabelului User
user_schema = UsersSchema()
users_schema = UsersSchema(many=True)



### ----------------
### Functii Auxiliare
### ----------------

## Functie pentru a popula baza de date la creere cu un user 
def populate_db(user_data):
    email = user_data['email']
    role = user_data['role']
    password = user_data['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    users_instance = User(email=email, role=role, password=hashed_password)
    db.session.add(users_instance)
    db.session.commit()


## Crearea bazei de date
with app_auth.app_context():
    db.create_all()
    print('Database created successfully.')

    # daca baza de date e goala, populam cu un user definit in fisierul 'users.json'
    if db.session.query(User).count() == 0:
        with open('users.json') as json_file:
            users = json.load(json_file)
            for user_data in users:
                populate_db(user_data)
        print('Database populated successfully.')


# Define the JWT user identity and lookup callbacks
@jwt.user_identity_loader
def user_identity_lookup(email):
    user = User.query.filter_by(email=email).first()
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


### ----------------
### Authentification
### ----------------


## Funtia principala pentru User Registration
#   form = {
#       "email": "secretara1@gmail.com",
#       "role": "Secretara",
#       "password": "1234"
#   }
@app_auth.route('/auth/register', methods=['POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        ## TO DO 
        # Task 3: Extragem datele din form


        ## TO DO
        # Task 4: Generam hashul parolei, utilizand libraria 'bcrypt', decodare 'utf-8'


        # Cream instanta de User si il adaugam in baza de date
        user = User(email=email, role=role, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Returnam meesaj si cod de succes
        return jsonify({'message': 'User registered successfully'}), 201
    return jsonify({'errors': form.errors}), 400


## User Login
#  form = {
#       "email": "secretara1@gmail.com",
#       "password": "1234"
#  }
@app_auth.route('/auth/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        ## TO DO 
        # Task 5: Extragem datele din form

        
        # Cautam user-ul in baza de date dupa 'email'
        user = User.query.filter_by(email=email).first()

        ## TO DO
        # Task 6: Verificam ca User-ul exista SI/AND parola oferita in formular se potriveste cu hash-ul din BD
        if 1:
            
            # Obtinem JWT token-ul pentru authentificare
            access_token = create_access_token(identity=email, expires_delta=timedelta(hours=24),
                                               additional_claims={"email": email})
            result = user_schema.dump(user)
            ## TO DO
            # Task 7: Creaza raspunsul dat de server catre client in forma JSON
            # Raspunsul va contine
            #  Response = {
            #       "user": <user>(object),
            #       "access_token": access_token,
            #       "message": "Successful Login"
            #  }
            
            return response, 200

        if not user or not user.password == password:
            return jsonify({'message': 'Invalid email or password'}), 401


# User logout
@app_auth.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        # Clear the access token
        response = jsonify({'message': 'Successfully logged out'})
        unset_jwt_cookies(response)
        return response
    except JWTExtendedException as e:
        return jsonify({'message': str(e)}), 401



### ----------------
### Authorisation
### ----------------


## Ruta protejata pentru a accesa pagina de Student
@app_auth.route('/protected/student', methods=['GET'])
##TO DO
# Task 7: Adauga functia care protejeaza request-ul, impune existenta unui JWT Token

def student_dashboard():
    ## TO DO
    # Task 8: Vericare user-ul este Student
    if 1:
        return jsonify({'message': 'Access forbidden, you are not a Student'}), 403
    return jsonify({"message": "Welcome to the Student Dashboard"})


## TO DO 
## Task 9: Scrieti Ruta protejata pentru a accesa pagina de Profesor



### TO DO BONUS
# Task 10: Creati o functie si o ruta pentru a accessa pagina de Secretara




## intrarea in programul de main
if __name__ == "__main__":
    app_auth.run(host='0.0.0.0', port=8001, debug=True)
