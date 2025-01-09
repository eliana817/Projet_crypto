from flask import Flask

def create_app():
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    # Utilisation d'une clé secrète générée ou d'une clé persistée dans l'environnement
    app.secret_key = '515bffd66952e6174d49b6440b24ccf692d4e9dd6456f3f3'

    # Importer et enregistrer le blueprint
    from . import routes
    app.register_blueprint(routes.bp)

    return app
