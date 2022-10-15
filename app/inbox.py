from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')

@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db()
    userid = g.user['id']
    messages = db.execute(
        'SELECT * FROM message m INNER JOIN user u ON u.id = m.from_id WHERE to_id = ? OR from_id = ?',(userid, userid)
    ).fetchall()

    return render_template('inbox/show.html', messages=messages)


@bp.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    if request.method == 'POST':        
        from_id = g.user['id']
        to_username = request.form['to'] # Destinatario
        subject = request.form['subject'] # Encabezado
        body = request.form['body'] # Mensaje

        db = get_db()
       
        if not to_username: # Si no hay destinatario
            flash('To field is required')
            return render_template('inbox/send.html') # Devuelve la misma pagina
        
        if not subject:
            flash('Subject field is required') # Si no hay encabezado
            return render_template('inbox/send.html') # Devuelve la misma pagina
        
        if not body:
            flash('Body field is required') # Si no hay mensaje
            return render_template('inbox/send.html') # Devuelve la misma pagina   
        
        error = None    
        userto = None 
        
        userto = db.execute(
            'SELECT * FROM user WHERE username = ?', (to_username,)
        ).fetchone()
        
        if userto is None:
            error = 'Recipient does not exist'
     
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO message (from_id, to_id, subject, body) VALUES (?,?,?,?)',#######################
                (g.user['id'], userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')