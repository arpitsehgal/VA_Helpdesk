from datetime import datetime
from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    file_paths = db.Column(db.Text, nullable=True)  # Comma-separated file paths
    required_by = db.Column(db.Date, nullable=False)  # Deadline for the task
    request_type = db.Column(db.String(50), nullable=False)  # Type of request
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='tasks')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)  # Link to a specific task
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Sender of the message
    content = db.Column(db.Text, nullable=False)  # Message content
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Message timestamp
    sender = db.relationship('User', backref='sent_messages')
    task = db.relationship('Task', backref='messages')


