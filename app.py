from flask import Flask, redirect, url_for, session, request, flash, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from authlib.oauth2.rfc6749.errors import OAuth2Error
import stripe
import os
from functools import wraps
import requests
from werkzeug.utils import secure_filename
from urllib.parse import urlencode
from graphene import ObjectType, String, Boolean, Field, Mutation, List, Int, Schema
from graphene_sqlalchemy import SQLAlchemyObjectType
from flask_graphql import GraphQLView
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

stripe.api_key = os.environ.get("STRIPE_API_KEY")

# OAuth configuration
oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=os.environ.get('KEYCLOAK_CLIENT_ID'),
    client_secret=os.environ.get('KEYCLOAK_CLIENT_SECRET'),
    server_metadata_url=os.environ.get('KEYCLOAK_METADATA_URL'),
    client_kwargs={
        'scope': 'openid profile email'
    }
)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keycloak_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_pro = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(200), nullable=True)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('todos', lazy=True))

# GraphQL Schema
class UserType(SQLAlchemyObjectType):
    class Meta:
        model = User

class TodoType(SQLAlchemyObjectType):
    class Meta:
        model = Todo

class Query(ObjectType):
    all_todos = List(TodoType)
    all_users = List(UserType)

    todo = Field(TodoType, id=Int())
    user = Field(UserType, id=Int())

    def resolve_all_todos(self, info):
        query = TodoType.get_query(info)
        return query.all()

    def resolve_all_users(self, info):
        query = UserType.get_query(info)
        return query.all()

    def resolve_todo(self, info, id):
        query = TodoType.get_query(info)
        return query.filter(Todo.id == id).first()

    def resolve_user(self, info, id):
        query = UserType.get_query(info)
        return query.filter(User.id == id).first()

class CreateTodo(Mutation):
    class Arguments:
        title = String(required=True)
        description = String(required=True)
        time = String(required=True)
        image = String()

    todo = Field(lambda: TodoType)

    def mutate(self, info, title, description, time, image=None):
        user_id = session['user']['id']
        user = User.query.get(user_id)
        if image and not user.is_pro:
            raise Exception("Pro license required to upload images")
        todo = Todo(title=title, description=description, time=time, image_url=image, user_id=user_id)
        db.session.add(todo)
        db.session.commit()
        return CreateTodo(todo=todo)

class UpdateTodo(Mutation):
    class Arguments:
        id = Int(required=True)
        title = String()
        description = String()
        time = String()
        image = String()

    todo = Field(lambda: TodoType)

    def mutate(self, info, id, title=None, description=None, time=None, image=None):
        todo = Todo.query.get(id)
        if not todo or todo.user_id != session['user']['id']:
            raise Exception("Todo not found or unauthorized")
        if title:
            todo.title = title
        if description:
            todo.description = description
        if time:
            todo.time = time
        if image:
            user = User.query.get(session['user']['id'])
            if not user.is_pro:
                raise Exception("Pro license required to upload images")
            todo.image_url = image
        db.session.commit()
        return UpdateTodo(todo=todo)

class DeleteTodo(Mutation):
    class Arguments:
        id = Int(required=True)

    ok = Boolean()

    def mutate(self, info, id):
        todo = Todo.query.get(id)
        if not todo or todo.user_id != session['user']['id']:
            raise Exception("Todo not found or unauthorized")
        db.session.delete(todo)
        db.session.commit()
        return DeleteTodo(ok=True)

class UpdateProfilePicture(Mutation):
    class Arguments:
        profile_picture = String(required=True)

    user = Field(lambda: UserType)

    def mutate(self, info, profile_picture):
        user = User.query.get(session['user']['id'])
        if not user:
            raise Exception("User not found")
        user.profile_picture = profile_picture
        db.session.commit()
        return UpdateProfilePicture(user=user)

class Mutation(ObjectType):
    create_todo = CreateTodo.Field()
    update_todo = UpdateTodo.Field()
    delete_todo = DeleteTodo.Field()
    update_profile_picture = UpdateProfilePicture.Field()

schema = Schema(query=Query, mutation=Mutation)

# Utility functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_info(token):
    userinfo_endpoint = 'http://localhost:8080/realms/todo-flask/protocol/openid-connect/userinfo'
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    userinfo_response = requests.get(userinfo_endpoint, headers=headers)
    if userinfo_response.status_code == 200:
        return userinfo_response.json()
    return None

@app.route('/')
@login_required
def home():
    user = User.query.filter_by(id=session['user']['id']).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('logout'))
    
    todos = Todo.query.filter_by(user_id=user.id).all()
    
    stripe_public_key = os.environ.get('STRIPE_PUBLIC_KEY')
    
    # Check if user has upgraded to pro and display message
    if session['user']['is_pro']:
        flash('You are currently using the Pro plan.', 'info')
    
    return render_template('index.html', todos=todos, user=user, stripe_public_key=stripe_public_key)

@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth():
    try:
        token = oauth.keycloak.authorize_access_token()
        session['token'] = token
    except OAuth2Error as error:
        return f'Access denied: {error.description}'
    
    user_info = get_user_info(token)
    if user_info:
        keycloak_id = user_info['sub']
        user = User.query.filter_by(keycloak_id=keycloak_id).first()
        if not user:
            user = User(keycloak_id=keycloak_id, email=user_info['email'])
            db.session.add(user)
            db.session.commit()
        session['user'] = {'id': user.id, 'keycloak_id': user.keycloak_id, 'email': user.email, 'is_pro': user.is_pro}
        return redirect('/')
    else:
        return 'Failed to fetch user info.'

@app.route('/logout')
def logout():
    token = session.get('token')
    if token:
        logout_url = "http://localhost:8080/realms/todo-flask/protocol/openid-connect/logout"
        redirect_uri = url_for('home', _external=True)
        params = {
            'id_token_hint': token['id_token'],
            'post_logout_redirect_uri': redirect_uri,
        }
        session.clear()
        return redirect(logout_url + '?' + urlencode(params))
    session.clear()
    return redirect('/')


@app.route('/buy_pro', methods=['POST'])
@login_required
def buy_pro():
    try:
        session_id = stripe.checkout.Session.create(
            payment_method_types=['amazon_pay'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Pro License',
                    },
                    'unit_amount': 1000,  # $10
                },
                'quantity': 1
            }],
            mode='payment',
            success_url=url_for('pro_success', _external=True),
            cancel_url=url_for('home', _external=True),
        )['id']
        return jsonify({'sessionId': session_id})
    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route('/pro_success')
@login_required
def pro_success():
    user = User.query.filter_by(id=session['user']['id']).first()
    if user:
        user.is_pro = True
        db.session.commit()
        session['user']['is_pro'] = True  # Update session to reflect pro status
        
        # Flash message indicating user needs to log in again to use pro features
        flash('Thank you!. You have successfully upgraded to Pro.', 'info')
    
    return redirect('/')

@app.route('/add_todo', methods=['POST'])
@login_required
def add_todo():
    title = request.form['title']
    description = request.form['description']
    time = request.form['time']
    image = request.files.get('image')

    if image:
        if not session['user']['is_pro']:
            flash('Pro license required to upload images', 'danger')
            return redirect(url_for('home'))
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_url = url_for('static', filename=f'uploads/{filename}')
    else:
        image_url = None

    user_id = session['user']['id']
    todo = Todo(title=title, description=description, time=time, image_url=image_url, user_id=user_id)
    db.session.add(todo)
    db.session.commit()

    flash('Todo added successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/edit_todo/<int:todo_id>', methods=['POST'])
@login_required
def edit_todo(todo_id):
    todo = Todo.query.get(todo_id)
    if not todo or todo.user_id != session['user']['id']:
        flash('Todo not found', 'danger')
        return redirect(url_for('home'))

    todo.title = request.form['title']
    todo.description = request.form['description']
    todo.time = request.form['time']
    image = request.files.get('image')

    if image:
        if not session['user']['is_pro']:
            flash('Pro license required to upload images', 'danger')
            return redirect(url_for('home'))
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        todo.image_url = url_for('static', filename=f'uploads/{filename}')

    db.session.commit()

    flash('Todo updated successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/delete_todo/<int:todo_id>', methods=['POST'])
@login_required
def delete_todo(todo_id):
    todo = Todo.query.get(todo_id)
    if not todo or todo.user_id != session['user']['id']:
        flash('Todo not found', 'danger')
        return redirect(url_for('home'))

    db.session.delete(todo)
    db.session.commit()

    flash('Todo deleted successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/update_profile_picture', methods=['POST'])
@login_required
def update_profile_picture():
    user = User.query.filter_by(id=session['user']['id']).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))

    profile_picture = request.files.get('profile_picture')
    if profile_picture:
        filename = secure_filename(profile_picture.filename)
        profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user.profile_picture = url_for('static', filename=f'uploads/{filename}')
        db.session.commit()

    flash('Profile picture updated successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/graphql', methods=['GET', 'POST'])
@login_required
def graphql():
    view_func = GraphQLView.as_view('graphql', schema=schema, graphiql=True)
    return view_func()

if __name__ == '__main__':
    # Ensure database and tables are created
    with app.app_context():
        db.create_all()
    app.run(debug=True)
