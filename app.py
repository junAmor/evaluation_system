import os
from flask import Flask
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

# Database Configuration
database_url = os.getenv("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20
    }
else:
    db_path = os.path.join(os.path.abspath(os.getcwd()), 'project.db')
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# Apply PRAGMA only if using SQLite
with app.app_context():
    import models
    import routes

    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        with db.engine.connect() as conn:
            conn.execute("PRAGMA foreign_keys=ON")  # ✅ Now runs only for SQLite

    # Database initialization (only for SQLite)
    if not database_url:
        db.create_all()

    # Add default data if necessary
    from models import User, EvaluatorPassword, EventDetails, EvaluationCriteria
    from werkzeug.security import generate_password_hash

    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)

    if not EventDetails.query.first():
        default_event_details = EventDetails()
        db.session.add(default_event_details)

    db.session.commit()
