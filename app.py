from flask import Flask, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'secret-key'
jwt = JWTManager(app)

# Define a dictionary to store the roles and permissions for each user
roles_and_permissions = {
    'user1': ['read', 'write'],
    'user2': ['read']
}

# Define a decorator to check if a user has the proper permissions
def has_permission(permission):
    def decorator(func):
        @jwt_required
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if permission not in roles_and_permissions.get(current_user, []):
                return {'message': 'Permission denied'}, 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Define a route for the login endpoint
@app.route('/login', methods=['POST'])
def login():
    # Get the username and password from the request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # Authenticate the user (this is just a dummy authentication logic)
    if username != 'admin' or password != 'secret':
        return {'message': 'Bad username or password'}, 401

    # Create a JWT access token for the user
    access_token = create_access_token(identity=username)
    return {'access_token': access_token}, 200

# Define a route for the resource endpoint
@app.route('/resource', methods=['GET'])
@has_permission('read')
def get_resource():
    return {'data': 'This is the protected resource'}, 200

# Define a route for the resource endpoint
@app.route('/resource', methods=['POST'])
@has_permission('write')
def create_resource():
    # Create the resource (this is just a dummy implementation)
    return {'message': 'Resource created'}, 201

if __name__ == '__main__':
    app.run()