from flask import Flask
import logging
import os
import base64

def create_app():
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    # Utilisation d'une clé secrète générée ou d'une clé persistée dans l'environnement
    app.secret_key = os.getenv("FLASK_SECRET_KEY", default=base64.b64encode(os.urandom(24)).decode('utf-8'))

    logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

    # Importer et enregistrer le blueprint
    from . import routes
    app.register_blueprint(routes.bp)

    return app
