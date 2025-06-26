# app.py - Versión Final y Completa

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import click
import os 
import ttlock_manager as ttlock
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
import json
from dotenv import load_dotenv

# Carga las variables del archivo .env al entorno
load_dotenv()

# --- CONFIGURACIÓN ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key-for-dev')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'reservas.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MICROSOFT_CLIENT_ID'] = os.getenv('MICROSOFT_CLIENT_ID')
app.config['MICROSOFT_CLIENT_SECRET'] = os.getenv('MICROSOFT_CLIENT_SECRET')

# --- Configuración de Credenciales ---
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False # Asegúrate de que SSL esté en False si usas TLS
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# --- INICIALIZACIÓN DE EXTENSIONES ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
oauth = OAuth(app)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login'

# --- REGISTRO DE MICROSOFT OAUTH ---
oauth.register(
    name='microsoft',
    client_id=app.config.get('MICROSOFT_CLIENT_ID'),
    client_secret=app.config.get('MICROSOFT_CLIENT_SECRET'),
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'User.Read openid profile email'}
)

# --- MODELOS ---
class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nombre = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(128), nullable=True) 
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    reservas = db.relationship('Reserva', backref='usuario', lazy=True)
    def set_password(self, password): self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')
    def check_password(self, password): return self.password_hash and bcrypt.check_password_hash(self.password_hash, password)

class Sala(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_ttlock = db.Column(db.Integer, unique=True, nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    reservas = db.relationship('Reserva', backref='sala', lazy=True)

class Reserva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha_inicio = db.Column(db.DateTime, nullable=False)
    fecha_fin = db.Column(db.DateTime, nullable=False)
    codigo_acceso = db.Column(db.String(20), nullable=False)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    id_sala = db.Column(db.Integer, db.ForeignKey('sala.id'), nullable=False)

# --- LOGIN, ROLES Y FILTROS ---
@login_manager.user_loader
def load_user(user_id): return Usuario.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("Acceso no autorizado.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.template_filter('format_date')
def format_date_filter(value, format='%d de %B de %Y'):
    if isinstance(value, str):
        try: value = date.fromisoformat(value)
        except (ValueError, TypeError): return value
    return value.strftime(format)

#def send_email(to, subject, template):
    if not app.config.get('MAIL_DEFAULT_SENDER'):
        print("ADVERTENCIA: Credenciales de correo no configuradas en .env.")
        return
    msg = Message(subject, recipients=[to], html=template, sender=app.config['MAIL_DEFAULT_SENDER'])
    try:
        mail.send(msg)
        print(f"Correo enviado exitosamente a {to}")
    except Exception as e:
        print(f"Error al enviar correo a {to}: {e}")

# --- COMANDOS DE TERMINAL ---
@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    click.echo('Base de datos inicializada.')
    if not Sala.query.first():
        click.echo('Poblando salas...')
        token = ttlock.obtener_token_acceso(os.getenv('TTLOCK_CLIENT_ID'), os.getenv('TTLOCK_CLIENT_SECRET'), os.getenv('TTLOCK_USERNAME'), os.getenv('TTLOCK_PASSWORD'))
        if token:
            salas_reales = ttlock.obtener_lista_cerraduras(os.getenv('TTLOCK_CLIENT_ID'), token)
            for sala_info in salas_reales:
                nueva_sala = Sala(id_ttlock=sala_info['lockId'], nombre=sala_info['lockAlias'])
                db.session.add(nueva_sala)
            db.session.commit()
            click.echo('Salas sincronizadas.')
        else:
            click.echo('No se pudo obtener el token de TTLock. No se poblaron las salas.')

# --- RUTAS ---
@app.route('/')
def index():
    return render_template('landing_page.html')

@app.route('/dashboard')
@login_required
def dashboard():
    salas = Sala.query.all()
    return render_template('dashboard.html', salas=salas)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        usuario = Usuario.query.filter_by(email=request.form['email']).first()
        if usuario and usuario.password_hash and usuario.check_password(request.form['password']):
            login_user(usuario, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Email o contraseña incorrectos.', 'danger')
    return render_template('auth.html')

@app.route('/login/microsoft')
def login_microsoft():
    redirect_uri = url_for('callback_microsoft', _external=True, _scheme='http')
    return oauth.microsoft.authorize_redirect(redirect_uri)

@app.route('/microsoft/callback')
def callback_microsoft():
    try:
        token = oauth.microsoft.authorize_access_token(claims_options={'iss': {'essential': False}})
        user_info = token.get('userinfo')
        if not user_info:
             user_info = oauth.microsoft.parse_id_token(token, claims_options={'iss': {'essential': False}})
    except Exception as e:
        flash(f"Error al autenticar con Microsoft: {e}", "danger")
        return redirect(url_for('login'))
    
    email = user_info.get('preferred_username') or user_info.get('email')
    if not email or not (email.endswith('@mayor.cl') or email.endswith('@umayor.cl')):
        flash("Acceso denegado. Se requiere una cuenta institucional.", "danger")
        return redirect(url_for('login'))
        
    usuario = Usuario.query.filter_by(email=email).first()
    if not usuario:
        flash("Tu cuenta institucional no está registrada en el sistema. Contacta a un administrador.", "warning")
        return redirect(url_for('login'))
    
    login_user(usuario, remember=True)
    return redirect(url_for('dashboard'))
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    microsoft_logout_url = (f"https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri={url_for('index', _external=True)}")
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(microsoft_logout_url)

@app.route('/contacto', methods=['POST'])
def contacto():
    nombre_empresa = request.form.get('nombre_empresa')
    email_contacto = request.form.get('email_contacto')
    mensaje = request.form.get('mensaje')
    if not all([nombre_empresa, email_contacto, mensaje]):
        flash("Por favor, completa todos los campos del formulario.", "danger")
        return redirect(url_for('index') + '#contacto')
    asunto = f"Nuevo Contacto de Empresa: {nombre_empresa}"
    cuerpo = f"Has recibido una nueva consulta de contacto.\n\nEmpresa: {nombre_empresa}\nEmail: {email_contacto}\n\nMensaje:\n{mensaje}"
    msg = Message(asunto, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[app.config['MAIL_DEFAULT_SENDER']], charset='utf-8')
    send_email(app.config['MAIL_DEFAULT_SENDER'], asunto, cuerpo)
    flash("¡Gracias por tu mensaje! Nos pondremos en contacto contigo a la brevedad.", "success")
    return redirect(url_for('index') + '#contacto')

@app.route('/sala/<int:id_sala>', defaults={'date_str': None})
@app.route('/sala/<int:id_sala>/<date_str>')
@login_required
def ver_sala(id_sala, date_str):
    if date_str is None:
        return redirect(url_for('ver_sala', id_sala=id_sala, date_str=date.today().isoformat()))
    
    sala = Sala.query.get_or_404(id_sala)
    try:
        selected_date = date.fromisoformat(date_str)
    except ValueError:
        return redirect(url_for('ver_sala', id_sala=id_sala))

    mañana = date.today() + timedelta(days=1)
    if not (selected_date == date.today() or selected_date == mañana):
        flash("Solo puedes ver la disponibilidad para hoy o mañana.", "warning")
        return redirect(url_for('ver_sala', id_sala=id_sala))

    ahora = datetime.now()
    hoy = date.today()
    HORA_INICIO_DIA, HORA_FIN_DIA = 8, 23
    
    reservas_del_dia = Reserva.query.filter(Reserva.id_sala == id_sala, db.func.date(Reserva.fecha_inicio) == selected_date).all()
    horarios_ocupados = {r.fecha_inicio for r in reservas_del_dia}
    
    bloques_de_tiempo = []
    for hora in range(HORA_INICIO_DIA, HORA_FIN_DIA):
        inicio_bloque = datetime.combine(selected_date, datetime.min.time()).replace(hour=hora)
        
        # LÓGICA CORREGIDA: Solo filtra el pasado si estamos viendo HOY.
        if selected_date == hoy and inicio_bloque < ahora:
            continue 

        estado = 'ocupado' if inicio_bloque in horarios_ocupados else 'disponible'
        bloques_de_tiempo.append({'inicio': inicio_bloque, 'estado': estado})
            
    context = {"sala": sala, "bloques": bloques_de_tiempo, "selected_date_str": selected_date.isoformat(), "today_str": date.today().isoformat(), "tomorrow_str": mañana.isoformat()}
    return render_template('ver_sala.html', **context)

@app.route('/reservar', methods=['POST'])
@login_required
def reservar():
    id_sala = request.form.get('id_sala')
    start_time_str = request.form.get('start_time')
    
    if not id_sala or not start_time_str:
        flash('Error en la solicitud de reserva.', 'danger')
        return redirect(url_for('dashboard'))

    sala = Sala.query.get_or_404(id_sala)
    fecha_inicio = datetime.fromisoformat(start_time_str)
    fecha_fin = fecha_inicio + timedelta(hours=1)
    date_str = fecha_inicio.date().isoformat()
    
    if fecha_inicio < datetime.now() - timedelta(minutes=1):
        flash('Error: El horario seleccionado ya ha pasado.', 'danger')
        return redirect(url_for('ver_sala', id_sala=id_sala, date_str=date_str))
    
    conflicto = Reserva.query.filter(Reserva.id_sala == id_sala, Reserva.fecha_fin > fecha_inicio, Reserva.fecha_inicio < fecha_fin).first()
    if conflicto:
        flash(f"Error: Alguien reservó este horario justo antes que tú.", 'danger')
        return redirect(url_for('ver_sala', id_sala=id_sala, date_str=date_str))
        
    token = ttlock.obtener_token_acceso(os.getenv('TTLOCK_CLIENT_ID'), os.getenv('TTLOCK_CLIENT_SECRET'), os.getenv('TTLOCK_USERNAME'), os.getenv('TTLOCK_PASSWORD'))
    codigo_data = ttlock.generar_codigo_temporal(os.getenv('TTLOCK_CLIENT_ID'), token, sala.id_ttlock, fecha_inicio, fecha_fin)
    
    if not codigo_data or 'keyboardPwd' not in codigo_data:
        error_msg = codigo_data.get('errmsg', 'Error desconocido') if codigo_data else 'Error desconocido'
        flash(f"No se pudo generar el código. La API respondió: '{error_msg}'.", "danger")
        return redirect(url_for('ver_sala', id_sala=id_sala, date_str=date_str))
    
    codigo_acceso = codigo_data['keyboardPwd']
    nueva_reserva = Reserva(fecha_inicio=fecha_inicio, fecha_fin=fecha_fin, codigo_acceso=codigo_acceso, usuario=current_user, sala=sala)
    db.session.add(nueva_reserva)
    db.session.commit()
    
    asunto = f"Confirmación de Reserva: {sala.nombre}"
    html_body = render_template('emails/confirmacion_reserva.html', nombre_usuario=current_user.nombre, sala=sala, reserva=nueva_reserva)
    #send_email(current_user.email, asunto, html_body)
    
    flash(f"¡Reserva exitosa para la sala {sala.nombre}!", 'success')
    return redirect(url_for('mis_reservas'))

@app.route('/mis_reservas')
@login_required
def mis_reservas():
    reservas = Reserva.query.filter_by(id_usuario=current_user.id).order_by(Reserva.fecha_inicio.desc()).all()
    return render_template('mis_reservas.html', reservas=reservas, now=datetime.now())

@app.route('/cancelar_mi_reserva/<int:reserva_id>', methods=['POST'])
@login_required
def cancelar_mi_reserva(reserva_id):
    reserva = Reserva.query.get_or_404(reserva_id)
    if reserva.id_usuario != current_user.id:
        flash("No puedes cancelar una reserva que no es tuya.", "danger")
        return redirect(url_for('mis_reservas'))
    if reserva.fecha_inicio < datetime.now():
        flash("No se puede cancelar una reserva que ya ha comenzado o pasado.", "warning")
        return redirect(url_for('mis_reservas'))
    sala_nombre = reserva.sala.nombre
    fecha_reserva = reserva.fecha_inicio.strftime('%d-%m-%Y a las %H:%M')
    db.session.delete(reserva)
    db.session.commit()
    asunto = f"Cancelación de Reserva: {sala_nombre}"
    html_body = render_template('emails/cancelacion_reserva.html', nombre_usuario=current_user.nombre, sala_nombre=sala_nombre, fecha_reserva=fecha_reserva)
    #send_email(current_user.email, asunto, html_body)
    flash(f"Tu reserva para la sala '{sala_nombre}' ha sido cancelada.", "success")
    return redirect(url_for('mis_reservas'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    reservas = Reserva.query.order_by(Reserva.fecha_inicio.desc()).all()
    return render_template('admin.html', reservas=reservas)
    
@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = Usuario.query.order_by(Usuario.nombre).all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        email = request.form.get('email')
        nombre = request.form.get('nombre')
        is_admin = 'is_admin' in request.form
        dominios_permitidos = ['@mayor.cl', '@umayor.cl']
        if not any(email.endswith(d) for d in dominios_permitidos) and email != 'admin@mayor.cl':
             flash('El email debe pertenecer a los dominios institucionales.', 'danger')
             return redirect(url_for('add_user'))
        if Usuario.query.filter_by(email=email).first():
            flash('Ya existe un usuario con ese correo electrónico.', 'danger')
            return redirect(url_for('add_user'))
        nuevo_usuario = Usuario(email=email, nombre=nombre, is_admin=is_admin)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash(f'Usuario {nombre} creado con éxito.', 'success')
        return redirect(url_for('manage_users'))
    return render_template('add_user.html')

@app.route('/cancelar_reserva/<int:reserva_id>', methods=['POST'])
@login_required
@admin_required
def cancelar_reserva(reserva_id):
    reserva = Reserva.query.get_or_404(reserva_id)
    sala_nombre = reserva.sala.nombre
    usuario_a_notificar = reserva.usuario
    fecha_reserva = reserva.fecha_inicio.strftime('%d-%m-%Y a las %H:%M')
    db.session.delete(reserva)
    db.session.commit()
    asunto = f"Reserva Cancelada por Administrador: {sala_nombre}"
    html_body = render_template('emails/cancelacion_admin.html', nombre_usuario=usuario_a_notificar.nombre, sala_nombre=sala_nombre, fecha_reserva=fecha_reserva)
    #send_email(usuario_a_notificar.email, asunto, html_body)
    flash(f"Reserva para '{sala_nombre}' cancelada exitosamente.", 'success')
    return redirect(url_for('admin_dashboard'))
