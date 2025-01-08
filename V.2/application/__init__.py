from flask import Flask
import logging
import os

def create_app():
    app = Flask(__name__,
            template_folder = '../templates',
            static_folder = '../static')

    app.secret_key = os.getenv("FLASK_SECRET_KEY", default=os.urandom(24))
    logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

    from application import routes
    app.register_blueprint(routes.bp)

    return app

