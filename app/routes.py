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

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password. Please try again.', 'danger')
            return render_template('login.html', email=email)

        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_role'] = user.role

        # Redirect based on user role
        if user.role == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        elif user.role == 'analyst':
            return redirect(url_for('main.analyst_dashboard'))
        elif user.role == 'VA':
            return redirect(url_for('main.visual_artist_dashboard'))  # Correct endpoint
        else:
            flash('Invalid role.', 'danger')
            return redirect(url_for('main.login'))

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
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.login'))

    tasks = Task.query.order_by(Task.created_at.desc()).all()
    va_users = User.query.filter_by(role='VA').all()  # Fetch all VA users
    return render_template('admin_dashboard.html', tasks=tasks, va_users=va_users)

@main_bp.route('/task/<int:task_id>/assign_va', methods=['POST'])
def assign_va(task_id):
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    va_user = User.query.filter_by(id=user_id, role='VA').first()
    if not va_user and user_id:
        return jsonify({'error': 'Invalid VA user'}), 400

    task.assigned_poc = user_id  # Update the assigned VA in the database
    db.session.commit()
    return jsonify({'success': True})

@main_bp.route('/visual_artist_dashboard', methods=['GET'])
def visual_artist_dashboard():
    if 'user_role' not in session or session['user_role'] != 'VA':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.login'))

    # Fetch tasks assigned to the logged-in VA user
    tasks = Task.query.filter_by(assigned_poc=session['user_id']).order_by(Task.created_at.desc()).all()
    return render_template('visual_artist_dashboard.html', tasks=tasks)


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

    tasks = Task.query.filter_by(created_by=session['user_id']).order_by(Task.created_at.desc()).all()
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
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    # Return task details including file paths
    return jsonify({
        'task_name': task.task_name,
        'description': task.description,
        'required_by': task.required_by.strftime('%Y-%m-%d') if task.required_by else None,
        'request_type': task.request_type,
        'status': task.status,
        'file_paths': task.file_paths.split(',') if task.file_paths else []
    })


@main_bp.route('/task/<int:task_id>/edit', methods=['PUT'])
def edit_task(task_id):
    try:
        task = Task.query.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404

        # Allow admins to edit any task, analysts to edit their own tasks, and VAs to edit assigned tasks
        if session.get('user_role') == 'VA' and task.assigned_poc != session.get('user_id'):
            return jsonify({'error': 'Unauthorized action'}), 403
        elif session.get('user_role') not in ['admin', 'VA'] and task.created_by != session.get('user_id'):
            return jsonify({'error': 'Unauthorized action'}), 403

        data = request.form
        task.task_name = data.get('task_name', task.task_name)
        task.description = data.get('description', task.description)
        task.request_type = data.get('request_type', task.request_type)
        task.required_by = datetime.strptime(data.get('required_by'), '%Y-%m-%d').date() if data.get('required_by') else task.required_by
        task.status = data.get('status', task.status)

        # Handle dynamic file uploads
        files = request.files.getlist('files')
        if files:
            current_files = task.file_paths.split(',') if task.file_paths else []
            new_files = []
            for file in files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    new_files.append(file_path)
            task.file_paths = ','.join(current_files + new_files) if new_files else task.file_paths

        db.session.commit()
        return jsonify({'success': True, 'message': 'Task updated successfully', 'file_paths': task.file_paths.split(',')})
    except Exception as e:
        print(f"Error during task update: {e}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while updating the task'}), 500









@main_bp.route('/task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    try:
        task = Task.query.get(task_id)
        print(f"Attempting to delete task ID: {task_id}")

        if not task:
            print(f"Task ID {task_id} not found.")
            return jsonify({'error': 'Task not found'}), 404

        if task.created_by != session.get('user_id'):
            print(f"Unauthorized attempt by user ID {session.get('user_id')} to delete task ID {task_id}")
            return jsonify({'error': 'Unauthorized action'}), 403

        # Deleting the task will automatically delete related messages due to cascading delete
        db.session.delete(task)
        db.session.commit()
        print(f"Task ID {task_id} and related messages deleted successfully.")
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error during task deletion: {e}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while deleting the task'}), 500


@main_bp.route('/task/<int:task_id>/chat', methods=['GET', 'POST'])
def task_chat(task_id):
    task = Task.query.get(task_id)
    if not task:
        flash('Task not found.', 'danger')
        return redirect(url_for('main.analyst_dashboard'))

    # Fetch all tasks created by the logged-in user
    tasks = Task.query.filter_by(created_by=session['user_id']).all()

    if request.method == 'POST':
        content = request.form['content']
        sender_id = session['user_id']
        new_message = Message(task_id=task_id, sender_id=sender_id, content=content)
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')

    messages = Message.query.filter_by(task_id=task_id).order_by(Message.timestamp.asc()).all()
    return render_template('task_chat.html', task=task, tasks=tasks, messages=messages)



@main_bp.route('/task/<int:task_id>/status', methods=['POST'])
def update_status(task_id):
    try:
        task = Task.query.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404

        new_status = request.json.get('status')
        if new_status not in ['with VA', 'In progress', 'with Analyst', 'Review needed', 'Completed']:
            return jsonify({'error': 'Invalid status value'}), 400

        task.status = new_status
        db.session.commit()
        return jsonify({'success': True, 'status': new_status})
    except Exception as e:
        print(f"Error updating status: {e}")
        return jsonify({'error': 'An error occurred while updating status'}), 500
