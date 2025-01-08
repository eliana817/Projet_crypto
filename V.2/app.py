from application import create_app
from python_files import database
import os

app = create_app()  # L'appel de create_app s'assure que la clé secrète est bien générée dans init.py

if __name__ == '__main__':
    # Création des tables si elles n'existent pas
    database.create_user_table()  # Crée la table des utilisateurs
    database.create_votes_table()  # Crée la table des votes si elle n'existe pas
    database.create_admin_user()  # Crée un utilisateur administrateur si nécessaire

    app.run(debug=True, port=5002, ssl_context='adhoc')  # SSL ad-hoc pour le développement
