from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(250),unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(250))
    admin = db.Column(db.Boolean)

    def __init__(self,public_id,name,password,admin):
        self.public_id = public_id
        self.name = name
        self.password = password
        self.admin = admin