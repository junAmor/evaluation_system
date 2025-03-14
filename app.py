import os
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from datetime import timedelta

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Configure session settings
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_NAME'] = 'evaluation_session'

# Configure database settings
database_url = os.environ.get("DATABASE_URL")

if database_url:
    # Ensure compatibility with SQLAlchemy
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    # Connection pool settings for PostgreSQL
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20
    }
else:
    # Use SQLite for local development
    db_path = os.path.join(os.path.abspath(os.getcwd()), 'project.db')
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Import models and routes
with app.app_context():
    import models
    import routes

    # Ensure the database is created only for SQLite
    if not database_url:
        db.create_all()

    # Perform initial setup for PostgreSQL only if migrations are handled
    from models import User, EvaluatorPassword, EventDetails, EvaluationCriteria
    from werkzeug.security import generate_password_hash

    # Create default admin account if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)

    # Add default event details if none exist
    if not EventDetails.query.first():
        default_event_details = EventDetails()
        db.session.add(default_event_details)

    db.session.commit()
