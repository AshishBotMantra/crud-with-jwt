from flask_marshmallow import Marshmallow

ma = Marshmallow()

class UserSchema(ma.Schema):
    class Meta():
        fields = ('id','public_id','name','password','admin','user_id', 'text', 'complete')

user_schema = UserSchema()
users_schema = UserSchema(many=True)