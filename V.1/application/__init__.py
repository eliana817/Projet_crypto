from flask import Flask

def create_app():
    app = Flask(__name__,
            template_folder = '../templates',
            static_folder = '../static')

    app.secret_key = 'secretkey'

    # Import and register the blueprint using relative import
    from .  import routes
    app.register_blueprint(routes.bp)

    return app
