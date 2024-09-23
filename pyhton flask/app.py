from flask import *
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_redis import FlaskRedis
import redis

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key
app.config['REDIS_URL'] = "redis://localhost:6379/0"  # Redis config

# Redis connection
redis_store = FlaskRedis(app)

# In-memory user storage (use a database in production)
users_db = {}

# WTForms for login and signup
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=15), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField('Login')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        
        # Check if user already exists
        if username in users_db:
            flash('Username already exists', 'error')
        else:
            # Store user
            users_db[username] = password
            flash('Signup successful, please login', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html', form=form)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if user exists and password is correct
        if username in users_db and check_password_hash(users_db[username], password):
            session['username'] = username
            redis_store.set(username, 'loggedin')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

# Home route (after login)
@app.route('/home')
def home():
    username = session.get('username')
    
    if not username or redis_store.get(username) != b'loggedin':
        return redirect(url_for('login'))
    
    return render_template('home.html', username=username)

# Logout route
@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        redis_store.delete(username)
        session.pop('username', None)
    
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

