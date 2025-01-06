from app import create_app  # Import the factory function

app = create_app()  # Create the app instance

if __name__ == '__main__':
    app.run(debug=True)
