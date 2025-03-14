from flask_sqlalchemy import SQLAlchemy
from app import db, login_manager
from flask_login import UserMixin
from sqlalchemy import event
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def get_id(self):
        return str(self.id)


class EventDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(200),
                           nullable=False,
                           default="Arduino Innovator Challenge")
    event_description = db.Column(
        db.Text,
        nullable=True,
        default="An innovative challenge for Arduino enthusiasts")
    logo_path = db.Column(db.String(200), nullable=True)


class EvaluatorPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)


class EvaluationCriteria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    weight_project_design = db.Column(db.Float, default=20.0)
    weight_functionality = db.Column(db.Float, default=20.0)
    weight_presentation = db.Column(db.Float, default=20.0)
    weight_web_design = db.Column(db.Float, default=20.0)
    weight_impact = db.Column(db.Float, default=20.0)
    score_precision = db.Column(db.Integer, default=1)
    min_score = db.Column(db.Float, default=0)


class Participant(db.Model):
    __tablename__ = "participants"  # ✅ Ensure correct table name

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    # ✅ Correct relationship to Evaluation
    evaluations = db.relationship('Evaluation', back_populates="participant", cascade="all, delete-orphan")


class Evaluation(db.Model):
    __tablename__ = "evaluations"  # ✅ Ensure correct table name

    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey("participants.id", ondelete="CASCADE"), nullable=False)

    # ✅ Correct relationship to Participant
    participant = db.relationship('Participant', back_populates="evaluations")

    project_design = db.Column(db.Float, nullable=False)
    functionality = db.Column(db.Float, nullable=False)
    presentation = db.Column(db.Float, nullable=False)
    web_design = db.Column(db.Float, nullable=False)
    impact = db.Column(db.Float, nullable=False)
    comments = db.Column(db.Text, nullable=True)

    @property
    def total_score(self):
        return (self.project_design * 0.25 + self.functionality * 0.30 +
                self.presentation * 0.15 + self.web_design * 0.10 +
                self.impact * 0.20)
