from flask import Flask, flash, request, render_template, redirect, session, make_response, url_for, g
import sqlite3
import re
from flask_bcrypt import Bcrypt
from markupsafe import escape
from functools import wraps
import logging

app = Flask(__name__)
app.secret_key = 'secret_key'
DATABASE = 'database.db'
bcrypt = Bcrypt(app)

# Function to connect to the SQLite database
def create_table():
    conn = sqlite3.connect(DATABASE) 
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
  

    # Drop the table if it exists
    # cursor.execute("DROP TABLE IF EXISTS User")

    # Recreate the table with the correct schema
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'user',               
    comments TEXT
      )
    ''')
    conn.commit()

def is_valid_input(input_data):
    return bool(re.match("^[a-zA-Z0-9.@]+$", input_data))

def is_suspicious_input(input_data):  
    suspicious_patterns = ["'", "--", " OR ", ";", "="]
    return any(pattern in input_data for pattern in suspicious_patterns)

def log_suspicious_activity(name, reason):
    logging.info(f"UnAuthorized act found: User: {name}, Reason: {reason}")

@app.after_request
def add_security_headers(response):
    # Prevents the app from being embedded in an iframe
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none';"
    return response
    

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = escape(request.form['name'])
        email = escape(request.form['email'])
        password = escape(request.form['password'])
        role = escape(request.form['role'])
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        bcrypt.check_password_hash(hashed_password, password)
        
        if not is_valid_input(email) or not is_valid_input(password):
            return "Invalid input. Provide valid alphanumeric characters."
        
        with get_db() as db:  # Using a parameterized query to prevent SQL injection
            db.execute('INSERT INTO User (name, email,password,role) VALUES (?, ?, ?,?)', (name, email, hashed_password,role))

            db.commit() 
        return redirect('/login')

    return render_template('register.html')


def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'email' not in session:
                return redirect('/login')
            
            with get_db() as db:
                user = db.execute('SELECT role FROM User WHERE email = ?', (session['email'],)).fetchone()
                if not user or user['role'] != required_role:
                    return "Access Denied. You do not have the required role.", 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    #return "Welcome to the admin dashboard!"
  return render_template('admin_dashboard.html')


@app.route('/assign_role', methods=['POST'])
@role_required('admin')
def assign_role():
    email = request.form.get('email')
    new_role = request.form.get('role')
    if not email or not new_role:
        return "Email or role not provided. Please fill out all fields.", 400

    with get_db() as db:
        db.execute('UPDATE User SET role = ? WHERE email = ?', (new_role, email))
        db.commit()
    
    flash(f'Role updated for {email} to {new_role}.', 'success')
    
    # if 'email' in session:
    #     with get_db() as db:
    #         db.execute('DELETE FROM User WHERE email = ?', (email,))
    #         db.commit()

    #     session.pop('email', None)
    #     flash('Your account has been deleted successfully.', 'success')
    return redirect('/admin_dashboard')
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # This used in register testing functionality
        # if not is_valid_input(email) or not is_valid_input(password): 
        #     return "Invalid input. Provide valid alphanumeric characters."
        
        if is_suspicious_input(email) or is_suspicious_input(password):
            log_suspicious_activity(email, "SQL Injection attempt in login")
            return "Suspicious action.User blocked.!!"
        
        with get_db() as db:
            user = db.execute('SELECT * FROM User WHERE email = ?', (email,)).fetchone()

        # if user and user['password'] == password:
        if user and bcrypt.check_password_hash(user['password'], password):
            session['email'] = user['email']
            resp = make_response(redirect('/dashboard')) 
            resp.set_cookie('email', user['email'],max_age=60*60*24,secure=True, httponly=True, samesite='Strict')   # Security parameters Cookies     
            return resp

        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html')


# @app.route('/dashboard')
# def dashboard():
#     if 'email' in session:
#         with get_db() as db:
#             user = db.execute('SELECT * FROM User WHERE email = ?', (session['email'],)).fetchone()
#             safe_name = escape(user['name'])
           
#         return render_template('dashboard.html', user={"name": safe_name, "email": user['email']})
    
#     return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        with get_db() as db:
            user = db.execute('SELECT * FROM User WHERE email = ?', (session['email'],)).fetchone()
            if user:
                return render_template('dashboard.html', user={
                    "name": escape(user['name']),
                    "email": user['email'],
                    "role": user['role']
                })
    
        return redirect('/login')
    return redirect('/admin')
    

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'email' in session:
        with get_db() as db:
            db.execute('DELETE FROM User WHERE email = ?', (session['email'],))
            db.commit()

        session.pop('email', None)
        flash('Your account has been deleted successfully.', 'success')
    return redirect('/login')

    


@app.route('/post', methods=['GET', 'POST'])
def post_message():
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    user_email = session['email']

    if request.method == 'POST':
      message = escape(request.form.get('message', ''))

    # if not is_valid_input(message):
    # return "Invalid search input. Only alphanumeric characters are allowed."(commented for testing functionality)
       
    return render_template('dashboard.html', user=user_email, message=message)

    # return render_template('dashboard.html', user=user_email)

@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; "
    return response

# Function to get a database connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    if 'db' in g:
        g.db.close()


if __name__ == '__main__':
    create_table()  
    app.run(debug=True)


    