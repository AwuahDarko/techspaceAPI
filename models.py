from app import db


class Users(db.Model):
    # __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(70), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    admin = db.Column(db.String(10), default="No")

    def __init__(self, public_id, email, password):
        self.email = email
        self.public_id = public_id
        self.password = password


