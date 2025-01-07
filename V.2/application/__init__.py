from flask import Flask
from .utils.logging import setup_logging

def create_app():
    app = Flask(__name__,
            template_folder = '../templates',
            static_folder = '../static')

    # Import and register the blueprint using relative import
    from .  import routes
    app.register_blueprint(routes.bp)

    setup_logging(app)

    return app
