from flask import Flask
import logging

def create_app():
    app = Flask(__name__,
            template_folder = '../templates',
            static_folder = '../static')

    app.secret_key = '515bffd66952e6174d49b6440b24ccf692d4e9dd6456f3f3'
    logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

    # Import and register the blueprint using relative import
    from .  import routes
    app.register_blueprint(routes.bp)

    return app

