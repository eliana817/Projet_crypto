from flask import Blueprint, render_template, request

bp = Blueprint('routes', __name__)


@bp.route('/')
def homepage():
	return render_template('homepage.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		# Extract the form data from the POST request
		username = request.form.get('username')
		password = request.form.get('password')
		
		# Print the login data to the console
		print({
			'username': username,
			'password': password
		})
		
		# Return nothing, just end the request
		return ''
	
	# If the method is GET, render the login page
	return render_template('login.html')


@bp.route('/register')
def register():
	return render_template('register.html')
