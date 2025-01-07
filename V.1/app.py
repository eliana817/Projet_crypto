from application import create_app
from python_files import database

app = create_app()  
app.secret_key = 'secretkey'

if __name__ == '__main__':
    database.create_user_table()  # Crée la table des utilisateurs à chaque démarrage de l'application
    database.create_votes_table()  # Crée la table des votes si elle n'existe pas
    database.create_admin_user()
    app.run(debug=True, port=5001)