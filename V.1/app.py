from application import create_app
from python_files import database

<<<<<<< HEAD
app = create_app()
=======
app = create_app()  
>>>>>>> bf30de507258fe1650907266aa64ee08ada265d7

if __name__ == '__main__':
    database.create_user_table()  # Crée la table des utilisateurs à chaque démarrage de l'application
    database.create_votes_table()  # Crée la table des votes si elle n'existe pas
    database.create_admin_user()
    app.run(debug=True, port=5001)