import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] #? Where does it come from?
        #----------------------------------------------------------------------    
            db = get_db()
            attempt = db.execute(
                "SELECT * FROM activationlink WHERE challenge = ? AND state = ?", (number, utils.U_UNCONFIRMED)#? all
            ).fetchone()
        #----------------------------------------------------------------------
            if attempt is not None:
                db.execute(
                    "UPDATE activationlink SET state = ? WHERE id = ?", (utils.U_CONFIRMED, attempt['id'])#?username or id
                )
                db.execute(
                    "INSERT INTO user (username, password, salt, email) VALUES (?,?,?,?)", (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])#?
                )
                db.commit()
        #----------------------------------------------------------------------
        return redirect(url_for('auth.login'))#?
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))#?
#-----------------------------------------------------------------------------------------------------------------------
#Cuando el usuario esta en 'register.html'
@bp.route('/register', methods=('GET','POST')) # Revisar register.html
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST':    
            username = request.form['username'] # Consulta a traves del metodo 'request' en la etiqueta 'form'
            password = request.form['password']
            email = request.form['email']
            
            db = get_db() # Hace la peticion a la base de datos
            error = None

            if not username: # Si no se digita un usuario
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')
            
            if not utils.isUsernameValid(username): # Si el usuario no es valido
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password: # Si no se digita una contrasena
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')
            #----------------------------------------------------------------------
            if db.execute('SELECT username FROM user WHERE username = ?', (username,)).fetchone() is not None:#? # Counsulta a la base de datos, no es necesario
            #----------------------------------------------------------------------                                                                      # declarar QUERY
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html')
            
            if (not email or (not utils.isEmailValid(email))): # Si no se digita email o es invalido
                error =  'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT email FROM user WHERE email = ?', (email,)).fetchone() is not None: # Si el email ya existe
                error =  'Email {} is already registered.'.format(email)#?
                flash(error)
                return render_template('auth/register.html')
            
            if (not utils.isPasswordValid(password)): # Si la contrasena es invalida
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')
            #---------------------------------------------------------------------- 
            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt) # Codificacion (seguridad)
            number = hex(random.getrandbits(512))[2:]
            #----------------------------------------------------------------------
            db.execute(
                'INSERT INTO activationlink (challenge,state,username,password,salt,email) VALUES (?,?,?,?,?,?)',
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)#?
            )
            db.commit()
            #----------------------------------------------------------------------
            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activate your account', message=content)
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') #? register or login
    except:
        return render_template('auth/register.html')
#-----------------------------------------------------------------------------------------------------------------------
# Cuando el usuario esta en /Confirm   
@bp.route('/confirm', methods= ('GET', 'POST'))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': 
            password = request.form['password'] 
            password1 = request.form['password1']
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password: # Si no se escribe la contrasena
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1: # Si no se escribe la confirmacion de la contrasena
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid)#########################?

            if password1 != password: # Si ambas contrasenas no coinciden
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid)###########################

            if not utils.isPasswordValid(password): # Si la contrasena es invalida
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)
            #----------------------------------------------------------------------
            db = get_db() # Conexion a la base de datos
            attempt = db.execute(
                "SELECT * FROM forgotlink WHERE challenge = ? AND state = ? AND CURRENT_TIMESTAMP BETWEEN created AND validuntil", (authid, utils.F_ACTIVE) ###?# Ejecuta el QUERY
            ).fetchone()
            #----------------------------------------------------------------------
            if attempt is not None:
                db.execute(
                    "UPDATE forgotlink SET state = ? WHERE id = ?", (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    "UPDATE user SET password = ?, salt = ? WHERE id = ?", (hashP, salt, attempt['userid'])####? username or id
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')
            #----------------------------------------------------------------------
        return render_template('auth/forgot.html')##?
    except:
        return render_template('auth/forgot.html')

#------------------------------------------------------------------------------------------------------------------
# Cambiar la contrasena
@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] ##? 
        #----------------------------------------------------------------------          
            db = get_db() # Conexion a la base de datos
            attempt = db.execute(
                "SELECT * FROM forgotlink WHERE challenge = ? AND state = ? AND CURRENT_TIMESTAMP BETWEEN created AND validuntil", (number, utils.F_ACTIVE)#?forgotlink or activationlink # Ejecuta el QUERY
            ).fetchone() # .fetchone() 
        #----------------------------------------------------------------------           
            if attempt is not None:
                return render_template('auth/change.html', number=number) ##?confirm
        
        return render_template('auth/login.html')
    except:
        return render_template('auth/forgot.html') #?# Agrege 'forgot' para verificar si ingresa al 'try' o si hay algun problema en el
                                                   # no logro decifrar la causa pero hay un problema en el 'try'

#-----------------------------------------------------------------------------------------------------------------------
@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email']
            
            if (not email or (not utils.isEmailValid(email))):
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db() # Conexion a la base de datos
            user = db.execute(
                'SELECT * FROM user WHERE email = ?', (email,) ####? all or username # Ejecuta el QUERY
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
            #----------------------------------------------------------------------               
                db.execute(
                    "UPDATE forgotlink SET state = ? WHERE userid = ?",
                    (utils.F_INACTIVE, user['id'])#?
                )
                db.execute(
                    "INSERT INTO forgotlink (userid, challenge, state) VALUES (?,?,?)",
                    (user['id'], number, utils.F_ACTIVE)#?
                )
                db.commit()
            #----------------------------------------------------------------------                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html')###?
    except:
        return render_template('auth/forgot.html')#TEMP

#-----------------------------------------------------------------------------------------------------------------------
# Cuando el usuario esta en /login.html
@bp.route('/login', methods= ('GET','POST'))
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            db = get_db() # Conexion a la base de datos
            error = None
            username = request.form['username'] # Consulta el 'name = username'
            password = request.form['password'] # Consulta el 'name = password'

            if not username:
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if not password:
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html')

            
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)##? # Ejecuta el codigo
            ).fetchone()
            
            if user is None:
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password!'   

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html')
    except:
        return render_template('auth/login.html') # Agrege 'forgot' para verificar si ingresa al 'try' o si hay algun problema en el
                                                   # no logro decifrar la causa 
#-----------------------------------------------------------------------------------------------------------------------
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

#-----------------------------------------------------------------------------------------------------------------------       
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()

