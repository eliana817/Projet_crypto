from app import create_app
from python_files import database

app = create_app()  

if __name__ == '__main__':
    database.create_user_table()  # Crée la table des utilisateurs à chaque démarrage de l'application
    database.create_votes_table()  # Crée la table des votes si elle n'existe pas
    app.run(debug=True, port=5000)