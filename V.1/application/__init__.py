from flask import Flask

def create_app():
    app = Flask(__name__,
            template_folder = '../templates',
            static_folder = '../static')
    
    # Set the secret key for sessions and flashes
    app.secret_key = '515bffd66952e6174d49b6440b24ccf692d4e9dd6456f3f3'
    
    # Import and register the blueprint using relative import
    from application import routes
    app.register_blueprint(routes.bp)

    return app
