# Role-based access control (RBAC) microservice using Flask:



### roles_and_permissions dictionary stores the roles and permissions for each user.

`roles_and_permissions = {
    'user1': ['read', 'write'],
    'user2': ['read']
}` 

### has_permission decorator is used to check if a user has the proper permissions to access a certain resource.

`def has_permission(permission):
    def decorator(func):
        @jwt_required
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if permission not in roles_and_permissions.get(current_user, []):
                return {'message': 'Permission denied'}, 403
            return func(*args, **kwargs)
        return wrapper
    return decorator` 

### login endpoint is used to authenticate users and generate JWT access tokens.

`def login():
    # Get the username and password from the request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    
    if username != 'admin' or password != 'secret':
        return {'message': 'Bad username or password'}, 401

    # Create a JWT access token 
    access_token = create_access_token(identity=username)
    return {'access_token': access_token}, 200`


