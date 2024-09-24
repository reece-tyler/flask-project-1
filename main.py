from flask import Flask, flash, session, render_template, redirect
import cgi, os
from flask import Flask, render_template, url_for, redirect, request
from flask import session as login_session
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
import sqlite3
from flask_admin import Admin, form
from flask import Flask, flash, request, redirect, url_for
import requests
import json
import os

#from cs50 import SQL
from flask import Flask, flash, json, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from datetime import datetime
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
#from helpers import apology, passwordValid
#from flask_login import login_required, passwordValid
from flask_login import login_required
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
#import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps



app = Flask(__name__, static_folder='static')
app.secret_key = 'any random string'


login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
login_manager.init_app(app)


UPLOAD_FOLDER = 'static'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

connect = sqlite3.connect(r'C:\Users\745570\Downloads\SQLiteDatabaseBrowserPortable\healthA.db', check_same_thread=False)



connect.execute(
    'CREATE TABLE IF NOT EXISTS user (id INTEGER NOT NULL PRIMARY KEY autoincrement, username VARCHAR NOT NULL UNIQUE, \
firstname TEXT, lastname TEXT, email NOT NULL UNIQUE, password TEXT, path TEXT,regDateTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')


@app.route('/')
@app.route('/home')
def home():
    cur = connect.cursor()

    return render_template("home.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user_entered = request.form['password']
        cur = connect.cursor()
        cur.execute(f"SELECT id, username, password from user WHERE username='{username}'")
        if cur is not None:
            # Get Stored hashed and salted password - Need to change fetch one to only return the one username
            #login_user(user)
            data = cur.fetchone()
            print(data)
            id = data[0]
            password = data[2]

            print("user id is ",id)
            print(password)
            print(type(password))
            # Compare Password with hashed password- Bcrypt
            if bcrypt.check_password_hash(password, user_entered):
                session['logged_in'] = True
                session['username'] = username
                session['id'] = id

                flash('You are now logged in', 'success')
                return redirect(url_for('welcome'))
                # Close Connection
                cursor.close()

            else:
                error = 'Invalid Username or Password'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password_hash = request.form['password']
        path = "avator.jpg"

        hashed_password = bcrypt.generate_password_hash(
            password_hash).decode('utf-8')
        try:
            cur = connect.cursor()
            cur.execute(
                "INSERT INTO user(username,firstname, lastname, email, password, path) VALUES (?,?, ?, ?, ?, ?)", (username, firstname, lastname, email, hashed_password, path))
        except IntegrityError:
            session.rollback()
        else:
            connect.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/welcome')
def welcome():


    return render_template("welcome.html")

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if "username" in session:
        username = session['username']
        print(username)
        cur = connect.cursor()
        cur.execute(f"SELECT id, username, email, path from user WHERE username='{username}'")

        data = cur.fetchone()
        print("hellos first", data)
        #cur.execute(f"SELECT id, username, email, height, weight, bmi from user INNER JOIN health ON health.hid = user.id WHERE username='{username}'")

        if cur is not None:
            # Get Stored hashed and salted password - Need to change fetch one to only return the one username

            id = data[0]
            username = data[1]
            email = data[2]
            path = data[3]

            if request.method == 'POST':
                if 'file1' not in request.files:
                    return 'there is no file1 in form!'
                file1 = request.files['file1']
                path = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
                file1.save(path)
                print(path)
                try:
                    cur = connect.cursor()
                    print(path)
                    cur.execute("UPDATE user SET path=? WHERE username=?".format(username), (path, username,))
                except:
                    #session.rollback()
                    print('User details already exist. Try again ')
                else:
                    connect.commit()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('profile.html', name = username, email=email, path=path)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == "__main__":

    app.run(debug=True)