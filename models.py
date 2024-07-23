from config import db, ma

## Definim tabelul model pentru un User
## Acest model va reprezenta tabela User și va conține coloanele corespunzătoare
#   {
#     "id": 1,
#     "email": "secretara1@gmail.com",
#     "role": "Secretara",
#     "password": "1234"
#   }
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), unique=False, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __init__(self, email, role, password):
        self.email = email
        self.role = role
        self.password = password


class UsersSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'role', 'password')
