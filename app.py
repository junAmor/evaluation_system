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

# Configure session to be more secure and support multiple users
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)  # Session lifetime
app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookie
app.config['SESSION_COOKIE_NAME'] = 'evaluation_session'  # Custom session cookie name

# Configure database for persistence
database_url = os.environ.get("DATABASE_URL")
if database_url is None:
    # Use a SQLite database in the instance folder for persistence
    db_path = os.path.join(app.instance_path, 'project.db')
    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    
    # Additional SQLite-specific options for better persistence
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "connect_args": {"check_same_thread": False},
        "poolclass": None,  # Disable connection pooling for SQLite
    }
else:
    # Format the URL for SQLAlchemy if using Postgres
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

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

with app.app_context():
    import models
    import routes
    db.create_all()

    # Create default admin account if it doesn't exist
    from models import User, EvaluatorPassword, EventDetails, EvaluationCriteria
    from werkzeug.security import generate_password_hash

    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)

    # Add default event details if none exist
    if not EventDetails.query.first():
        default_event_details = EventDetails() # Assuming EventDetails model has a default constructor
        db.session.add(default_event_details)


    db.session.commit()