from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse, fields, marshal_with
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required


# generate_password_hash("x")  <- returns hash
# check_password_hash('hash', 'x')   <- should return True

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "whatever"
db = SQLAlchemy(app)
jwt = JWTManager(app)

resource_user = {
    "id": fields.Integer,
    "username": fields.String,
    "email": fields.String
}
resource_posts = {
    "id": fields.Integer,
    "name": fields.String,
    "recipe": fields.String,
    "user_id": fields.Integer
}


class UserModel(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"Bartender {self.username}"


class PostModel(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    recipe = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"Poison recipe {self.name}"


register_parser = reqparse.RequestParser()
register_parser.add_argument("email", type=str, required=True, help='Email must be a string')
register_parser.add_argument("password", type=str, required=True, help='Password must be a string')
register_parser.add_argument("username", type=str, help='user_name must be a string')

user_parser = reqparse.RequestParser()
user_parser.add_argument("username", type=str, help='user_name must be a string')
user_parser.add_argument("email", type=str, help='Email must be a string')
user_parser.add_argument("password", type=str, help='Password must be a string')

post_parser = reqparse.RequestParser()
post_parser.add_argument("id", type=int, help='Id must be an integer')
post_parser.add_argument("name", type=str, help='Name must be a string')
post_parser.add_argument("recipe", type=str, help='Recipe must be a string')
post_parser.add_argument("user_id", type=int, help='user_id must be an integer')


class Auth(Resource):
    def post(self):
        email = request.json.get("email", None)
        password = request.json.get("password", None)
        user = UserModel.query.filter_by(email=email).first()
        if user is None or check_password_hash(user.password, password) is False:
            return {"msg": "Wrong username or password"}, 401
        # else?
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token)


class Register(Resource):
    def post(self):
        args = register_parser.parse_args()
        user = UserModel(username=args['username'], email=args['email'],
                         password=generate_password_hash(args['password']))
        db.session.add(user)
        db.session.commit()
        return {"msg": "bartender user created"}, 201


class User(Resource):
    @marshal_with(resource_user)
    def get(self, user_id):
        if user_id == 999:
            return UserModel.query.all()
        user = UserModel.query.filter_by(id=user_id).first()
        return user

    # @marshal_with(resource_user)
    # @jwt_required()
    def post(self, user_id):
        args = user_parser.parse_args()
        # password = generate_password_hash(args['password'])  not working???
        user = UserModel(username=args["username"], email=args["email"], password=args['password'])
        db.session.add(user)
        db.session.commit()
        return f"Bartender {user_id} added"

    # @marshal_with(resource_user)
    @jwt_required()
    def put(self, user_id):
        args = user_parser.parse_args()
        user = UserModel.query.filter_by(id=user_id).first()
        if user is None:
            user = UserModel(username=args["username"], email=args["email"])
        else:
            user.username = args["username"]
            user.email = args["email"]
        db.session.add(user)
        db.session.commit()
        return f"Bartender {user_id} updated"

    @jwt_required()
    def delete(self, user_id):
        user = UserModel.query.filter_by(id=user_id).first()
        db.session.delete(user)
        db.session.commit()
        return f"Bartender {user_id} deleted"


class Post(Resource):
    @marshal_with(resource_posts)
    def get(self, item_id):
        if item_id == 000:
            return PostModel.query.all()
        args = post_parser.parse_args()
        post = PostModel.query.filter_by(id=item_id).first()
        return post

    # @marshal_with(resource_posts)
    # @jwt_required()
    def post(self, item_id):
        args = post_parser.parse_args()
        item = PostModel(name=args["name"], recipe=args["recipe"], user_id=args["user_id"])
        db.session.add(item)
        db.session.commit()
        return f"Poison {item_id} recipe added"

    # @marshal_with(resource_posts)
    @jwt_required()
    def put(self, item_id):
        args = post_parser.parse_args()
        item = PostModel.query.filter_by(id=item_id).first()
        if item is None:
            item = PostModel(name=args["name"], body=args["recipe"], user_id=args["user_id"])
        else:
            item.name = args["name"]
            item.body = args["recipe"]
            item.user_id = args["user_id"]
        db.session.add(item)
        db.session.commit()
        return f"Poison {item_id} recipe updated"

    @jwt_required()
    def delete(self, item_id):
        item = PostModel.query.filter_by(id=item_id).first()
        db.session.delete(item)
        db.session.commit()
        return f"Poison {item_id} deleted"


api.add_resource(Register, '/register')
api.add_resource(Auth, '/login')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(Post, '/item/<int:item_id>')


# db.create_all()

# @app.before_first_request
# def before_first_request():
#     import seed


if __name__ == "__main__":
    app.run()