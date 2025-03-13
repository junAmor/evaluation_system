
from app import app, db
from models import User, Participant, Evaluation
import os

def update_participant_table():
    with app.app_context():
        # Check if column exists already
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('participant')]
        
        if 'group_number' not in columns:
            print("Adding group_number column to participant table...")
            # Add the column with a default value of 1
            db.session.execute(text('ALTER TABLE participant ADD COLUMN group_number INTEGER DEFAULT 1'))
            
            # Set each participant's group_number equal to their id to maintain existing ordering
            participants = Participant.query.all()
            for i, participant in enumerate(participants, 1):
                participant.group_number = i
            
            db.session.commit()
            print("Database updated successfully!")
        else:
            print("group_number column already exists.")

if __name__ == '__main__':
    update_participant_table()
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

def setup_database():
    """Set up the database with the required tables if they don't exist."""
    database_url = os.environ.get("DATABASE_URL")
    
    if not database_url:
        print("No DATABASE_URL environment variable found. Using SQLite.")
        database_url = "sqlite:///project.db"
    else:
        # Format the URL for SQLAlchemy if using Postgres
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    try:
        # Create engine and connect
        engine = create_engine(database_url)
        with engine.connect() as conn:
            # Test connection
            result = conn.execute(text("SELECT 1"))
            print("Database connection successful!")
            
        print(f"Successfully connected to the database at {database_url}")
        return True
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return False

if __name__ == "__main__":
    setup_database()
