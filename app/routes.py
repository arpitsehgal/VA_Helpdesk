from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlalchemy as sa
from alembic import op
from app.models import User, Task, Message  # Import models
from app import db  # Import SQLAlchemy instance
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return render_template('home.html')

@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('main.register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'danger')
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(name=name, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['user_name'] = new_user.name
        session['user_role'] = new_user.role
        return redirect(url_for('main.welcome'))

    return render_template('register.html')

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password. Please try again.', 'danger')
            return render_template('login.html', email=email)

        # Store user details in session
        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_role'] = user.role

        # Redirect based on user role
        if user.role == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        elif user.role == 'analyst':
            return redirect(url_for('main.analyst_dashboard'))

    return render_template('login.html')



@main_bp.route('/welcome')
def welcome():
    if 'user_name' not in session:
        return redirect(url_for('main.login'))
    return render_template('welcome.html', name=session['user_name'])

@main_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main_bp.route('/list_users')
def list_users():
    users = User.query.all()
    return render_template('list_users.html', users=users)

@main_bp.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    # Ensure the logged-in user is an admin
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.login'))

    # Fetch all tasks with user details (analyst-created tasks)
    tasks = Task.query.all()
    return render_template('admin_dashboard.html', tasks=tasks)



@main_bp.route('/analyst_dashboard', methods=['GET', 'POST'])
def analyst_dashboard():
    if 'user_role' not in session or session['user_role'] != 'analyst':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        task_id = request.form.get('task_id')
        task_name = request.form['task_name']
        description = request.form['description']
        required_by_str = request.form['needed_by']  # Date as string
        request_type = request.form['request_type']  # Dropdown selection
        files = request.files.getlist('files')  # Handle multiple files

        # Convert string date to Python date object
        required_by = datetime.strptime(required_by_str, '%Y-%m-%d').date()

        file_paths = []
        for file in files:
            if file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                file_paths.append(file_path)

        if task_id:  # Update existing task
            task = Task.query.get(task_id)
            if task and task.created_by == session['user_id']:
                task.task_name = task_name
                task.description = description
                task.required_by = required_by
                task.request_type = request_type
                task.file_paths = ','.join(file_paths) if file_paths else task.file_paths
                db.session.commit()
                flash('Task updated successfully!', 'success')

        else:  # Create new task
            new_task = Task(
                task_name=task_name,
                description=description,
                required_by=required_by,
                request_type=request_type,
                file_paths=','.join(file_paths),
                created_by=session['user_id']
            )
            db.session.add(new_task)
            db.session.commit()
            flash('Task created successfully!', 'success')

    tasks = Task.query.filter_by(created_by=session['user_id']).all()
    return render_template('analyst_dashboard.html', tasks=tasks)

@main_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash('File not found.', 'danger')
        return redirect(url_for('main.analyst_dashboard'))
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@main_bp.route('/task/<int:task_id>', methods=['GET'])
def get_task(task_id):
    task = Task.query.get(task_id)
    if task and task.created_by == session['user_id']:
        return jsonify({
            'id': task.id,
            'task_name': task.task_name,
            'description': task.description
        })
    return jsonify({'error': 'Task not found or unauthorized'}), 404

@main_bp.route('/task/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    task = Task.query.get(task_id)
    if task and task.created_by == session['user_id']:
        data = request.get_json()
        task.task_name = data['task_name']
        task.description = data['description']
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Task not found or unauthorized'}), 404

@main_bp.route('/task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if task and task.created_by == session['user_id']:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Task not found or unauthorized'}), 404

@main_bp.route('/task/<int:task_id>/chat', methods=['GET', 'POST'])
def task_chat(task_id):
    task = Task.query.get(task_id)
    if not task:
        flash('Task not found.', 'danger')
        return redirect(url_for('main.admin_dashboard'))

    if request.method == 'POST':
        content = request.form['content']
        sender_id = session['user_id']
        new_message = Message(task_id=task_id, sender_id=sender_id, content=content)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')

    messages = Message.query.filter_by(task_id=task_id).order_by(Message.timestamp.asc()).all()
    return render_template('task_chat.html', task=task, messages=messages)


