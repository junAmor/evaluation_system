from app import db, login_manager
from flask_login import UserMixin
from sqlalchemy import event
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Add database event listeners for better persistence
@event.listens_for(db.engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforce foreign key constraints for SQLite"""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging for better concurrency
    cursor.close()

class EventDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(200), nullable=False, default="Arduino Innovator Challenge")
    event_description = db.Column(db.Text, nullable=True, default="An innovative challenge for Arduino enthusiasts")
    logo_path = db.Column(db.String(200), nullable=True)
    
class EvaluatorPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    project_title = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Float, default=0.0)
    evaluations = db.relationship('Evaluation', backref='participant', lazy=True)

class EvaluationCriteria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    weight_project_design = db.Column(db.Float, nullable=False, default=25.0)
    weight_functionality = db.Column(db.Float, nullable=False, default=30.0)
    weight_presentation = db.Column(db.Float, nullable=False, default=15.0)
    weight_web_design = db.Column(db.Float, nullable=False, default=10.0)
    weight_impact = db.Column(db.Float, nullable=False, default=20.0)
    score_precision = db.Column(db.Integer, nullable=False, default=2)
    min_score = db.Column(db.Float, nullable=False, default=1.0)
    max_score = db.Column(db.Float, nullable=False, default=100.0)

class Evaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey('participant.id'), nullable=False)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_design = db.Column(db.Float, nullable=False)  # 25%
    functionality = db.Column(db.Float, nullable=False)   # 30%
    presentation = db.Column(db.Float, nullable=False)    # 15%
    web_design = db.Column(db.Float, nullable=False)      # 10%
    impact = db.Column(db.Float, nullable=False)          # 20%
    comments = db.Column(db.Text)

    @property
    def total_score(self):
        # Weighted score calculation as explained in the requirements
        # Project Design (25%) + Functionality (30%) + Presentation (15%) + Web Design (10%) + Impact (20%)
        return (
            self.project_design * 0.25 +
            self.functionality * 0.30 +
            self.presentation * 0.15 +
            self.web_design * 0.10 +
            self.impact * 0.20
        )