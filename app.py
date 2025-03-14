import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event
from datetime import timedelta

class Base(DeclarativeBase):
    pass

# ✅ Define db before app, but do not bind it yet
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()

# ✅ Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# ✅ Configure the database
database_url = os.getenv("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    db_path = os.path.join(os.path.abspath(os.getcwd()), 'project.db')
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ✅ Initialize extensions AFTER creating the app
db.init_app(app)
login_manager.init_app(app)

# ✅ Ensure all queries run inside app context
with app.app_context():
    import models
    import routes
    db.create_all()  # ✅ Create tables inside app context

    from models import User, EvaluatorPassword, EventDetails, EvaluationCriteria
    from werkzeug.security import generate_password_hash

    # ✅ Run queries inside app context
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

    db.session.commit()  # ✅ Commit the changes
