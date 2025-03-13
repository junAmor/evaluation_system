from flask import render_template, redirect, url_for, flash, request, send_file, Response, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import app, db
from models import User, Participant, Evaluation, EvaluatorPassword, EventDetails, EvaluationCriteria
from sqlalchemy import and_
import io
import csv
import pandas as pd
from datetime import datetime
import os
import tempfile

@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'))

@app.route('/active_users')
@login_required
def active_users():
    # Only admin can see active users
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))
    
    # Get all active users from the database
    active_users = User.query.filter_by(is_active=True).all()
    
    # Filter users based on their last activity
    active_admin_users = [user for user in active_users if user.role == 'admin']
    active_evaluator_users = [user for user in active_users if user.role == 'evaluator']
    
    return render_template('active_users.html', 
                          active_admin_users=active_admin_users,
                          active_evaluator_users=active_evaluator_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'evaluator':
            return redirect(url_for('select_participant'))
        return redirect(url_for('leaderboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            # Create a session-specific user ID to maintain separate sessions
            login_user(user, remember=True)  # Use remember=True to maintain persistent sessions
            
            # Add user role to session for reference
            session['user_role'] = user.role
            session['user_id'] = user.id
            
            if user.role == 'evaluator':
                return redirect(url_for('select_participant'))
            return redirect(url_for('leaderboard'))
        flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Only clear the current user's session data
    user_id = current_user.id
    user_role = current_user.role
    
    logout_user()
    
    # Clear specific session data for this user only
    session.pop('user_role', None)
    session.pop('user_id', None)
    
    flash(f'You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    participants = Participant.query.all()
    evaluators = User.query.filter_by(role='evaluator').all()

    # Count total expected evaluations vs actual evaluations
    total_expected = len(participants) * len(evaluators)
    total_actual = Evaluation.query.count()

    # Check if all evaluations are complete
    all_evaluations_complete = total_actual >= total_expected if total_expected > 0 else False

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    # Convert weights to decimals for calculations
    weight_project_design = criteria.weight_project_design / 100
    weight_functionality = criteria.weight_functionality / 100
    weight_presentation = criteria.weight_presentation / 100 
    weight_web_design = criteria.weight_web_design / 100
    weight_impact = criteria.weight_impact / 100
    score_precision = criteria.score_precision


    # Calculate scores for all participants regardless of completion status
    # This ensures real-time updates on the leaderboard
    for participant in participants:
        evaluations = Evaluation.query.filter_by(participant_id=participant.id).all()

        if evaluations:
            # Calculate weighted scores for each criterion
            weighted_project_designs = [e.project_design * weight_project_design for e in evaluations]
            weighted_functionalities = [e.functionality * weight_functionality for e in evaluations]
            weighted_presentations = [e.presentation * weight_presentation for e in evaluations]
            weighted_web_designs = [e.web_design * weight_web_design for e in evaluations]
            weighted_impacts = [e.impact * weight_impact for e in evaluations]

            # Calculate average weighted scores for each criterion with proper precision
            participant.avg_weighted_project_design = round(sum(weighted_project_designs) / len(evaluations), score_precision)
            participant.avg_weighted_functionality = round(sum(weighted_functionalities) / len(evaluations), score_precision)
            participant.avg_weighted_presentation = round(sum(weighted_presentations) / len(evaluations), score_precision)
            participant.avg_weighted_web_design = round(sum(weighted_web_designs) / len(evaluations), score_precision)
            participant.avg_weighted_impact = round(sum(weighted_impacts) / len(evaluations), score_precision)

            # Store original averages for reference
            participant.avg_project_design = sum(e.project_design for e in evaluations) / len(evaluations)
            participant.avg_functionality = sum(e.functionality for e in evaluations) / len(evaluations)
            participant.avg_presentation = sum(e.presentation for e in evaluations) / len(evaluations)
            participant.avg_web_design = sum(e.web_design for e in evaluations) / len(evaluations)
            participant.avg_impact = sum(e.impact for e in evaluations) / len(evaluations)

            # Store evaluator data for display
            participant.evaluator_scores = []
            for evaluation in evaluations:
                evaluator = User.query.get(evaluation.evaluator_id)
                weighted_score = (
                    (evaluation.project_design * weight_project_design) +
                    (evaluation.functionality * weight_functionality) +
                    (evaluation.presentation * weight_presentation) +
                    (evaluation.web_design * weight_web_design) +
                    (evaluation.impact * weight_impact)
                )
                participant.evaluator_scores.append({
                    'evaluator_name': evaluator.username,
                    'weighted_score': weighted_score,
                    'weighted_project_design': evaluation.project_design * weight_project_design,
                    'weighted_functionality': evaluation.functionality * weight_functionality,
                    'weighted_presentation': evaluation.presentation * weight_presentation,
                    'weighted_web_design': evaluation.web_design * weight_web_design,
                    'weighted_impact': evaluation.impact * weight_impact
                })

            # Final score is the sum of average weighted criterion scores with proper precision
            participant.score = round(
                participant.avg_weighted_project_design +
                participant.avg_weighted_functionality +
                participant.avg_weighted_presentation +
                participant.avg_weighted_web_design +
                participant.avg_weighted_impact,
                score_precision
            )
        else:
            participant.avg_project_design = 0
            participant.avg_functionality = 0
            participant.avg_presentation = 0
            participant.avg_web_design = 0
            participant.avg_impact = 0
            participant.score = 0

    # Sort participants by score after calculation
    participants = sorted(participants, key=lambda p: p.score, reverse=True)

    return render_template('leaderboard.html', participants=participants, 
                          all_evaluations_complete=all_evaluations_complete,
                          completed_evaluations=total_actual,
                          total_evaluations=total_expected,
                          criteria=criteria)

@app.route('/api/participant/<int:participant_id>/evaluations')
@login_required
def participant_evaluations(participant_id):
    """API endpoint to get evaluation details for a specific participant"""
    participant = Participant.query.get_or_404(participant_id)
    evaluations = Evaluation.query.filter_by(participant_id=participant_id).all()

    evaluations_data = []
    for evaluation in evaluations:
        evaluator = User.query.get(evaluation.evaluator_id)
        criteria = EvaluationCriteria.query.first()
        weight_project_design = criteria.weight_project_design / 100
        weight_functionality = criteria.weight_functionality / 100
        weight_presentation = criteria.weight_presentation / 100
        weight_web_design = criteria.weight_web_design / 100
        weight_impact = criteria.weight_impact / 100
        weighted_score = (
            (evaluation.project_design * weight_project_design) +
            (evaluation.functionality * weight_functionality) +
            (evaluation.presentation * weight_presentation) +
            (evaluation.web_design * weight_web_design) +
            (evaluation.impact * weight_impact)
        )
        evaluations_data.append({
            'evaluator_name': evaluator.username,
            'evaluator_id': evaluator.id,
            'weighted_project_design': evaluation.project_design * weight_project_design,
            'weighted_functionality': evaluation.functionality * weight_functionality,
            'weighted_presentation': evaluation.presentation * weight_presentation,
            'weighted_web_design': evaluation.web_design * weight_web_design,
            'weighted_impact': evaluation.impact * weight_impact,
            'weighted_score': weighted_score
        })

    return jsonify({
        'participant_id': participant_id,
        'participant_name': participant.name,
        'evaluations': evaluations_data
    })

@app.route('/leaderboard_data')
@login_required
def leaderboard_data():
    """API endpoint to get leaderboard data for real-time updates"""
    participants = Participant.query.all()
    evaluators = User.query.filter_by(role='evaluator').all()

    # Count total expected evaluations vs actual evaluations
    total_expected = len(participants) * len(evaluators)
    total_actual = Evaluation.query.count()

    # Check if all evaluations are complete
    all_evaluations_complete = total_actual >= total_expected if total_expected > 0 else False

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    # Convert weights to decimals for calculations
    weight_project_design = criteria.weight_project_design / 100
    weight_functionality = criteria.weight_functionality / 100
    weight_presentation = criteria.weight_presentation / 100
    weight_web_design = criteria.weight_web_design / 100
    weight_impact = criteria.weight_impact / 100
    score_precision = criteria.score_precision

    # Process participant data
    participants_data = []
    for participant in participants:
        evaluations = Evaluation.query.filter_by(participant_id=participant.id).all()

        if evaluations:
            # Calculate weighted scores for each criterion using weights from settings
            weighted_project_designs = [e.project_design * weight_project_design for e in evaluations]
            weighted_functionalities = [e.functionality * weight_functionality for e in evaluations]
            weighted_presentations = [e.presentation * weight_presentation for e in evaluations]
            weighted_web_designs = [e.web_design * weight_web_design for e in evaluations]
            weighted_impacts = [e.impact * weight_impact for e in evaluations]

            # Calculate average weighted scores for each criterion with proper precision
            avg_weighted_project_design = round(sum(weighted_project_designs) / len(evaluations), score_precision)
            avg_weighted_functionality = round(sum(weighted_functionalities) / len(evaluations), score_precision)
            avg_weighted_presentation = round(sum(weighted_presentations) / len(evaluations), score_precision)
            avg_weighted_web_design = round(sum(weighted_web_designs) / len(evaluations), score_precision)
            avg_weighted_impact = round(sum(weighted_impacts) / len(evaluations), score_precision)

            # Store original averages for reference
            avg_project_design = sum(e.project_design for e in evaluations) / len(evaluations)
            avg_functionality = sum(e.functionality for e in evaluations) / len(evaluations)
            avg_presentation = sum(e.presentation for e in evaluations) / len(evaluations)
            avg_web_design = sum(e.web_design for e in evaluations) / len(evaluations)
            avg_impact = sum(e.impact for e in evaluations) / len(evaluations)

            # Get evaluator data
            evaluator_scores = []
            for evaluation in evaluations:
                evaluator = User.query.get(evaluation.evaluator_id)
                weighted_score = (
                    (evaluation.project_design * weight_project_design) +
                    (evaluation.functionality * weight_functionality) +
                    (evaluation.presentation * weight_presentation) +
                    (evaluation.web_design * weight_web_design) +
                    (evaluation.impact * weight_impact)
                )
                evaluator_scores.append({
                    'evaluator_name': evaluator.username,
                    'weighted_score': weighted_score,
                    'weighted_project_design': evaluation.project_design * weight_project_design,
                    'weighted_functionality': evaluation.functionality * weight_functionality,
                    'weighted_presentation': evaluation.presentation * weight_presentation,
                    'weighted_web_design': evaluation.web_design * weight_web_design,
                    'weighted_impact': evaluation.impact * weight_impact
                })

            # Final score is the sum of average weighted criterion scores with proper precision
            score = round(
                avg_weighted_project_design +
                avg_weighted_functionality +
                avg_weighted_presentation +
                avg_weighted_web_design +
                avg_weighted_impact,
                score_precision
            )
        else:
            avg_project_design = 0
            avg_functionality = 0
            avg_presentation = 0
            avg_web_design = 0
            avg_impact = 0
            score = 0

        participants_data.append({
            'id': participant.id,
            'group_number': participant.group_number,
            'name': participant.name,
            'project_title': participant.project_title,
            'avg_project_design': avg_project_design,
            'avg_functionality': avg_functionality,
            'avg_presentation': avg_presentation,
            'avg_web_design': avg_web_design,
            'avg_impact': avg_impact,
            'avg_weighted_project_design': avg_weighted_project_design,
            'avg_weighted_functionality': avg_weighted_functionality,
            'avg_weighted_presentation': avg_weighted_presentation,
            'avg_weighted_web_design': avg_weighted_web_design,
            'avg_weighted_impact': avg_weighted_impact,
            'evaluator_scores': evaluator_scores,
            'score': score
        })

    # Sort participants by score
    participants_data = sorted(participants_data, key=lambda p: p['score'], reverse=True)

    return {
        'participants': participants_data,
        'all_evaluations_complete': all_evaluations_complete,
        'completed_evaluations': total_actual,
        'total_evaluations': total_expected
    }

@app.route('/evaluators')
@login_required
def evaluators():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    evaluators = User.query.filter_by(role='evaluator').all()

    # Get all evaluations for each evaluator
    evaluator_evaluations = {}
    for evaluator in evaluators:
        evaluations = Evaluation.query.filter_by(evaluator_id=evaluator.id).all()
        evaluator_evaluations[evaluator.id] = []

        for evaluation in evaluations:
            participant = Participant.query.get(evaluation.participant_id)
            evaluator_evaluations[evaluator.id].append({
                'evaluation': evaluation,
                'participant': participant
            })

    # Get stored passwords from database
    stored_passwords = {}
    password_records = EvaluatorPassword.query.all()
    for record in password_records:
        stored_passwords[record.username] = record.password

    # If no passwords found, let's check if we need to recreate them
    if not stored_passwords:
        # Create password records for existing evaluators without passwords
        for evaluator in evaluators:
            # Default passwords if none are found
            default_pw = "default123" 
            if evaluator.username == "Jerome":
                default_pw = "jerome123"
            elif evaluator.username == "Glen":
                default_pw = "glen123"
            elif evaluator.username == "FLow":
                default_pw = "flow123"

            if not EvaluatorPassword.query.filter_by(username=evaluator.username).first():
                password_record = EvaluatorPassword(
                    username=evaluator.username,
                    password=default_pw
                )
                db.session.add(password_record)
                stored_passwords[evaluator.username] = default_pw

        db.session.commit()

    return render_template(
        'evaluators.html', 
        evaluators=evaluators, 
        default_passwords=stored_passwords,
        evaluator_evaluations=evaluator_evaluations
    )

@app.route('/evaluators/add', methods=['POST'])
@login_required
def add_evaluator():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Please provide both username and password', 'danger')
        return redirect(url_for('evaluators'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('evaluators'))

    # Create the evaluator user account
    new_evaluator = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='evaluator')
    db.session.add(new_evaluator)

    # Store the plaintext password for admin reference
    password_record = EvaluatorPassword(
        username=username,
        password=password
    )
    db.session.add(password_record)

    db.session.commit()

    flash('Evaluator added successfully', 'success')
    return redirect(url_for('evaluators'))

@app.route('/evaluators/toggle-status/<int:evaluator_id>', methods=['POST'])
@login_required
def toggle_evaluator_status(evaluator_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    evaluator = User.query.get_or_404(evaluator_id)
    if evaluator.role != 'evaluator':
        flash('Invalid evaluator', 'danger')
        return redirect(url_for('evaluators'))

    # Toggle the active status
    evaluator.is_active = not evaluator.is_active
    db.session.commit()

    status = "enabled" if evaluator.is_active else "disabled"
    flash(f'Evaluator {evaluator.username} {status} successfully', 'success')
    return redirect(url_for('evaluators'))

@app.route('/evaluators/delete/<int:evaluator_id>', methods=['POST'])
@login_required
def delete_evaluator(evaluator_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    evaluator = User.query.get_or_404(evaluator_id)
    if evaluator.role != 'evaluator':
        flash('Invalid evaluator', 'danger')
        return redirect(url_for('evaluators'))

    # Check if evaluator has any evaluations
    evaluations = Evaluation.query.filter_by(evaluator_id=evaluator_id).all()
    if evaluations:
        flash('Cannot delete evaluator with existing evaluations', 'danger')
        return redirect(url_for('evaluators'))

    # Remove the password record from database
    password_record = EvaluatorPassword.query.filter_by(username=evaluator.username).first()
    if password_record:
        db.session.delete(password_record)

    db.session.delete(evaluator)
    db.session.commit()
    flash('Evaluator removed successfully', 'success')
    return redirect(url_for('evaluators'))

@app.route('/participants')
@login_required
def participants():
    participants = Participant.query.all()
    return render_template('participants.html', participants=participants)

@app.route('/participants/add', methods=['POST'])
@login_required
def add_participant():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))

    group_number = request.form.get('group_number')
    name = request.form.get('name')
    project_title = request.form.get('project_title')

    if not group_number or not name or not project_title:
        flash('Please provide group number, group name, and project title', 'danger')
        return redirect(url_for('participants'))

    try:
        group_number = int(group_number)
    except ValueError:
        flash('Group number must be a valid integer', 'danger')
        return redirect(url_for('participants'))

    # Check if group number already exists
    if Participant.query.filter_by(group_number=group_number).first():
        flash('A group with this number already exists', 'danger')
        return redirect(url_for('participants'))

    new_participant = Participant(
        group_number=group_number,
        name=name,
        project_title=project_title
    )
    db.session.add(new_participant)
    db.session.commit()

    flash('Group added successfully', 'success')
    return redirect(url_for('participants'))

@app.route('/participants/delete/<int:participant_id>', methods=['POST'])
@login_required
def delete_participant(participant_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))

    participant = Participant.query.get_or_404(participant_id)

    # Check if participant has any evaluations
    evaluations = Evaluation.query.filter_by(participant_id=participant_id).all()
    if evaluations:
        flash('Cannot delete group with existing evaluations', 'danger')
        return redirect(url_for('participants'))

    db.session.delete(participant)
    db.session.commit()
    flash('Group removed successfully', 'success')
    return redirect(url_for('participants'))

@app.route('/participants/import', methods=['POST'])
@login_required
def import_participants():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))

    if 'csv_file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('participants'))

    file = request.files['csv_file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('participants'))

    if not file.filename.endswith('.csv'):
        flash('File must be a CSV', 'danger')
        return redirect(url_for('participants'))

    try:
        # Read the CSV file
        stream = io.StringIO(file.stream.read().decode("UTF8"))
        csv_data = csv.reader(stream)

        # Skip header row if exists
        has_header = True
        if has_header:
            next(csv_data, None)

        success_count = 0
        error_count = 0

        for row in csv_data:
            if len(row) < 3:
                error_count += 1
                continue

            try:
                group_number = int(row[0])
                name = row[1]
                project_title = row[2]

                # Check if group number already exists
                if Participant.query.filter_by(group_number=group_number).first():
                    error_count += 1
                    continue

                new_participant = Participant(
                    group_number=group_number,
                    name=name,
                    project_title=project_title
                )
                db.session.add(new_participant)
                success_count += 1
            except:
                error_count += 1

        db.session.commit()

        if success_count > 0:
            flash(f'Successfully imported {success_count} participants', 'success')
        if error_count > 0:
            flash(f'Failed to import {error_count} participants due to errors', 'warning')

    except Exception as e:
        flash(f'Error processing CSV file: {str(e)}', 'danger')

    return redirect(url_for('participants'))

@app.route('/participants/reset', methods=['POST'])
@login_required
def reset_participants():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('participants'))

    # Delete all evaluations first to avoid foreign key constraints
    Evaluation.query.delete()

    # Delete all participants
    Participant.query.delete()

    # Commit the changes
    db.session.commit()

    flash('All participants and evaluations have been reset', 'success')
    return redirect(url_for('participants'))

@app.route('/evaluations/reset', methods=['POST'])
@login_required
def reset_evaluations():
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Delete only the evaluations from the current evaluator
    Evaluation.query.filter_by(evaluator_id=current_user.id).delete()

    # Commit the changes
    db.session.commit()

    flash('All your evaluations have been reset. You can start evaluating again.', 'success')
    return redirect(url_for('select_participant'))

@app.route('/settings')
@login_required
def settings():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Get counts for statistics
    participant_count = Participant.query.count()
    evaluator_count = User.query.filter_by(role='evaluator').count()

    # Count total expected evaluations vs actual evaluations
    total_expected = participant_count * evaluator_count
    completed_evaluations = Evaluation.query.count()

    # Get admin users
    admin_users = User.query.filter_by(role='admin').all()

    # Get event details
    event_details = EventDetails.query.first()
    if not event_details:
        event_details = EventDetails(
            event_name="Arduino Innovator Challenge",
            event_description="An innovative challenge for Arduino enthusiasts"
        )
        db.session.add(event_details)
        db.session.commit()

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    return render_template(
        'settings.html',
        participant_count=participant_count,
        evaluator_count=evaluator_count,
        completed_evaluations=completed_evaluations,
        total_evaluations=total_expected,
        admin_users=admin_users,
        event_details=event_details,
        criteria=criteria
    )

@app.route('/add_admin_user', methods=['POST'])
@login_required
def add_admin_user():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    username = request.form.get('admin_username')
    password = request.form.get('admin_password')

    if not username or not password:
        flash('Please provide both username and password', 'danger')
        return redirect(url_for('settings'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'danger')
        return redirect(url_for('settings'))

    new_admin = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='admin',
        is_active=True
    )

    db.session.add(new_admin)
    db.session.commit()

    flash('Admin user added successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/delete_admin_user/<int:admin_id>', methods=['POST'])
@login_required
def delete_admin_user(admin_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Cannot delete your own account
    if admin_id == current_user.id:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('settings'))

    admin = User.query.get_or_404(admin_id)
    if admin.role != 'admin':
        flash('Invalid admin user', 'danger')
        return redirect(url_for('settings'))

    db.session.delete(admin)
    db.session.commit()

    flash('Admin user deleted successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')

    if not user_id or not new_password:
        flash('Invalid request', 'danger')
        return redirect(url_for('settings'))

    user = User.query.get_or_404(user_id)
    user.password_hash = generate_password_hash(new_password)

    # If changing password for an evaluator, update the stored password
    if user.role == 'evaluator':
        password_record = EvaluatorPassword.query.filter_by(username=user.username).first()
        if password_record:
            password_record.password = new_password
        else:
            password_record = EvaluatorPassword(
                username=user.username,
                password=new_password
            )
            db.session.add(password_record)

    db.session.commit()

    flash('Password changed successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/update_event_details', methods=['POST'])
@login_required
def update_event_details():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    event_name = request.form.get('event_name')
    event_description = request.form.get('event_description')

    if not event_name:
        flash('Event name is required', 'danger')
        return redirect(url_for('settings'))

    # Get event details or create if not exists
    event_details = EventDetails.query.first()
    if not event_details:
        event_details = EventDetails()
        db.session.add(event_details)

    # Update event details
    event_details.event_name = event_name
    event_details.event_description = event_description

    # Handle logo upload if provided
    logo_file = request.files.get('event_logo')
    if logo_file and logo_file.filename:
        # Secure the filename
        from werkzeug.utils import secure_filename
        import os

        filename = secure_filename(logo_file.filename)
        # Save in the static folder
        logo_path = os.path.join('static', filename)
        try:
            logo_file.save(logo_path)
            event_details.logo_path = filename
        except Exception as e:
            flash(f'Error saving logo: {str(e)}', 'warning')

    # Set logo path to null if no file provided to keep existing logo
    if not logo_file or not logo_file.filename:
        # Don't change the existing logo
        pass
    
    # Explicitly commit changes to database
    try:
        db.session.commit()
        flash('Event details updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating event details: {str(e)}', 'danger')

    return redirect(url_for('settings'))

@app.route('/update_evaluation_criteria', methods=['POST'])
@login_required
def update_evaluation_criteria():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    try:
        # Get weight values from form
        weight_project_design = float(request.form.get('weight_project_design', 25))
        weight_functionality = float(request.form.get('weight_functionality', 30))
        weight_presentation = float(request.form.get('weight_presentation', 15))
        weight_web_design = float(request.form.get('weight_web_design', 10))
        weight_impact = float(request.form.get('weight_impact', 20))

        # Validate weights sum to 100%
        total_weight = weight_project_design + weight_functionality + weight_presentation + weight_web_design + weight_impact
        if abs(total_weight - 100) > 0.01:
            flash('Weights must add up to 100%', 'danger')
            return redirect(url_for('settings'))

        # Get other settings
        score_precision = int(request.form.get('score_precision', 2))
        min_score = float(request.form.get('min_score', 1))
        max_score = float(request.form.get('max_score', 100))

        # Get criteria record or create if not exists
        criteria = EvaluationCriteria.query.first()
        if not criteria:
            criteria = EvaluationCriteria()
            db.session.add(criteria)

        # Update criteria
        criteria.weight_project_design = weight_project_design
        criteria.weight_functionality = weight_functionality
        criteria.weight_presentation = weight_presentation
        criteria.weight_web_design = weight_web_design
        criteria.weight_impact = weight_impact
        criteria.score_precision = score_precision
        criteria.min_score = min_score
        criteria.max_score = max_score

        db.session.commit()
        flash('Evaluation criteria updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating criteria: {str(e)}', 'danger')

    return redirect(url_for('settings'))

@app.route('/reset_all_data', methods=['POST'])
@login_required
def reset_all_data():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    try:
        # Delete all evaluations first to avoid foreign key constraints
        Evaluation.query.delete()

        # Reset scores for all participants
        for participant in Participant.query.all():
            participant.score = 0.0

        # Optionally, reset any other data if needed
        # - Keep only the admin user
        # - Reset event details to default if specified in form
        reset_event_details = request.form.get('reset_event_details') == 'on'
        if reset_event_details:
            event_details = EventDetails.query.first()
            if event_details:
                event_details.event_name = "Arduino Innovator Challenge"
                event_details.event_description = "An innovative challenge for Arduino enthusiasts"

        # Commit the changes
        db.session.commit()

        flash('All data has been reset. Evaluations deleted and scores reset to zero.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting data: {str(e)}', 'danger')

    return redirect(url_for('settings'))

@app.route('/download_report_excel')
@login_required
def download_report_excel():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Get participants data ordered by score
    participants = Participant.query.all()

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    score_precision = criteria.score_precision

    # Calculate scores for all participants
    for participant in participants:
        evaluations = Evaluation.query.filter_by(participant_id=participant.id).all()

        if evaluations:
            # Calculate weighted scores for each criterion
            weight_project_design = criteria.weight_project_design / 100
            weight_functionality = criteria.weight_functionality / 100
            weight_presentation = criteria.weight_presentation / 100
            weight_web_design = criteria.weight_web_design / 100
            weight_impact = criteria.weight_impact / 100
            weighted_project_designs = [e.project_design * weight_project_design for e in evaluations]
            weighted_functionalities = [e.functionality * weight_functionality for e in evaluations]
            weighted_presentations = [e.presentation * weight_presentation for e in evaluations]
            weighted_web_designs = [e.web_design * weight_web_design for e in evaluations]
            weighted_impacts = [e.impact * weight_impact for e in evaluations]

            # Calculate average weighted scores for each criterion with proper precision
            participant.avg_weighted_project_design = round(sum(weighted_project_designs) / len(evaluations), score_precision)
            participant.avg_weighted_functionality = round(sum(weighted_functionalities) / len(evaluations), score_precision)
            participant.avg_weighted_presentation = round(sum(weighted_presentations) / len(evaluations), score_precision)
            participant.avg_weighted_web_design = round(sum(weighted_web_designs) / len(evaluations), score_precision)
            participant.avg_weighted_impact = round(sum(weighted_impacts) / len(evaluations), score_precision)

            # Final score
            participant.score = round(
                participant.avg_weighted_project_design +
                participant.avg_weighted_functionality +
                participant.avg_weighted_presentation +
                participant.avg_weighted_web_design +
                participant.avg_weighted_impact,
                score_precision
            )
        else:
            participant.avg_weighted_project_design = 0
            participant.avg_weighted_functionality = 0
            participant.avg_weighted_presentation = 0
            participant.avg_weighted_web_design = 0
            participant.avg_weighted_impact = 0
            participant.score = 0

    # Sort participants by score
    participants = sorted(participants, key=lambda p: p.score, reverse=True)

    # Create DataFrame for Excel
    data = []
    for i, participant in enumerate(participants, 1):
        data.append({
            'Rank': i,
            'Group Number': participant.group_number,
            'Group Name': participant.name,
            'Project Title': participant.project_title,
            'Design (25%)': f"{participant.avg_weighted_project_design:.2f}",
            'Function (30%)': f"{participant.avg_weighted_functionality:.2f}",
            'Presentation (15%)': f"{participant.avg_weighted_presentation:.2f}",
            'Web Design (10%)': f"{participant.avg_weighted_web_design:.2f}",
            'Impact (20%)': f"{participant.avg_weighted_impact:.2f}",
            'Final Score': f"{participant.score:.2f}"
        })

    df = pd.DataFrame(data)

    # Create a BytesIO object
    output = io.BytesIO()

    # Create Excel writer
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Leaderboard', index=False)
        worksheet = writer.sheets['Leaderboard']

        # Set column widths
        worksheet.set_column('A:A', 5)  # Rank
        worksheet.set_column('B:B', 12)  # Group Number
        worksheet.set_column('C:C', 20)  # Group Name
        worksheet.set_column('D:D', 30)  # Project Title
        worksheet.set_column('E:I', 15)  # Scores
        worksheet.set_column('J:J', 12)  # Final Score

    output.seek(0)

    # Generate filename with current date
    date_str = datetime.now().strftime('%Y-%m-%d')
    filename = f"Arduino_Innovator_Challenge_Leaderboard_{date_str}.xlsx"

    return Response(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route('/download_report_pdf')
@login_required
def download_report_pdf():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    try:
        import pdfkit
    except ImportError:
        flash('PDF generation requires pdfkit library. Please contact the administrator.', 'warning')
        return redirect(url_for('settings'))

    # Get participants data ordered by score (reusing leaderboard logic)
    participants = Participant.query.all()
    evaluators = User.query.filter_by(role='evaluator').all()

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    score_precision = criteria.score_precision

    # Count total expected evaluations vs actual evaluations
    total_expected = len(participants) * len(evaluators)
    total_actual = Evaluation.query.count()

    # Check if all evaluations are complete
    all_evaluations_complete = total_actual >= total_expected if total_expected > 0 else False

    # Calculate scores for all participants
    for participant in participants:
        evaluations = Evaluation.query.filter_by(participant_id=participant.id).all()

        if evaluations:
            weight_project_design = criteria.weight_project_design / 100
            weight_functionality = criteria.weight_functionality / 100
            weight_presentation = criteria.weight_presentation / 100
            weight_web_design = criteria.weight_web_design / 100
            weight_impact = criteria.weight_impact / 100
            # Calculate weighted scores for each criterion
            weighted_project_designs = [e.project_design * weight_project_design for e in evaluations]
            weighted_functionalities = [e.functionality * weight_functionality for e in evaluations]
            weighted_presentations = [e.presentation * weight_presentation for e in evaluations]
            weighted_web_designs = [e.web_design * weight_web_design for e in evaluations]
            weighted_impacts = [e.impact * weight_impact for e in evaluations]

            # Calculate average weighted scores for each criterion with proper precision
            participant.avg_weighted_project_design = round(sum(weighted_project_designs) / len(evaluations), score_precision)
            participant.avg_weighted_functionality = round(sum(weighted_functionalities) / len(evaluations), score_precision)
            participant.avg_weighted_presentation = round(sum(weighted_presentations) / len(evaluations), score_precision)
            participant.avg_weighted_web_design = round(sum(weighted_web_designs) / len(evaluations), score_precision)
            participant.avg_weighted_impact = round(sum(weighted_impacts) / len(evaluations), score_precision)

            # Store evaluator data for display
            participant.evaluator_scores = []
            for evaluation in evaluations:
                evaluator = User.query.get(evaluation.evaluator_id)
                weighted_score = (
                    (evaluation.project_design * weight_project_design) +
                    (evaluation.functionality * weight_functionality) +
                    (evaluation.presentation * weight_presentation) +
                    (evaluation.web_design * weight_web_design) +
                    (evaluation.impact * weight_impact)
                )
                participant.evaluator_scores.append({
                    'evaluator_name': evaluator.username,
                    'weighted_score': weighted_score,
                    'weighted_project_design': evaluation.project_design * weight_project_design,
                    'weighted_functionality': evaluation.functionality * weight_functionality,
                    'weighted_presentation': evaluation.presentation * weight_presentation,
                    'weighted_web_design': evaluation.web_design * weight_web_design,
                    'weighted_impact': evaluation.impact * weight_impact
                })

            # Final score is the sum of average weighted criterion scores with proper precision
            participant.score = round(
                participant.avg_weighted_project_design +
                participant.avg_weighted_functionality +
                participant.avg_weighted_presentation +
                participant.avg_weighted_web_design +
                participant.avg_weighted_impact,
                score_precision
            )
        else:
            participant.avg_project_design = 0
            participant.avg_functionality = 0
            participant.avg_presentation = 0
            participant.avg_web_design = 0
            participant.avg_impact = 0
            participant.score = 0

    # Sort participants by score
    participants = sorted(participants, key=lambda p: p.score, reverse=True)

    # Render the HTML content for the PDF
    html_content = render_template(
        'pdf_report.html',
        participants=participants,
        completed_evaluations=total_actual,
        total_evaluations=total_expected,
        all_evaluations_complete=all_evaluations_complete,
        date=datetime.now().strftime('%Y-%m-%d'),
        time=datetime.now().strftime('%H:%M:%S')
    )

    # Create PDF file
    try:
        # Create a temporary HTML file
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_html:
            temp_html.write(html_content.encode('utf-8'))
            temp_html_path = temp_html.name

        # Convert HTML to PDF using pdfkit
        options = {
            'page-size': 'A4',
            'margin-top': '1cm',
            'margin-right': '1cm',
            'margin-bottom': '1cm',
            'margin-left': '1cm',
            'encoding': 'UTF-8',
        }

        pdf_data = pdfkit.from_file(temp_html_path, False, options=options)

        # Clean up temporary file
        os.unlink(temp_html_path)

        # Generate filename with current date
        date_str = datetime.now().strftime('%Y-%m-%d')
        filename = f"Arduino_Innovator_Challenge_Report_{date_str}.pdf"

        # Return PDF as a downloadable file
        return Response(
            pdf_data,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )

    except Exception as e:
        # If pdfkit fails, offer CSV export as fallback
        flash(f'PDF generation failed. Providing CSV export instead. Error: {str(e)}', 'warning')

        # Create CSV file
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['Rank', 'Group', 'Project', 'Design (25%)', 'Function (30%)', 
                         'Present (15%)', 'Web (10%)', 'Impact (20%)', 'Final Score'])

        # Write data
        for i, participant in enumerate(participants, 1):
            writer.writerow([
                i,
                f"Group {participant.group_number}: {participant.name}",
                participant.project_title,
                f"{participant.avg_weighted_project_design:.2f}",
                f"{participant.avg_weighted_functionality:.2f}",
                f"{participant.avg_weighted_presentation:.2f}",
                f"{participant.avg_weighted_web_design:.2f}",
                f"{participant.avg_weighted_impact:.2f}",
                f"{participant.score:.2f}"
            ])

        # Return CSV as a downloadable file
        date_str = datetime.now().strftime('%Y-%m-%d')
        filename = f"Arduino_Innovator_Challenge_Report_{date_str}.csv"

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )

@app.route('/select_participant')
@login_required
def select_participant():
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Get all participants
    all_participants = Participant.query.all()

    # Get IDs and evaluations of participants that have been evaluated by current evaluator
    evaluations = Evaluation.query.filter_by(evaluator_id=current_user.id).all()
    evaluated_participant_ids = [eval.participant_id for eval in evaluations]

    # Create a dictionary to store evaluation IDs for each participant
    evaluation_ids = {eval.participant_id: eval.id for eval in evaluations}

    return render_template(
        'select_participant.html', 
        all_participants=all_participants,
        evaluated_participant_ids=evaluated_participant_ids,
        evaluation_ids=evaluation_ids,
        show_leaderboard=False
    )

@app.route('/rate_participant/<int:participant_id>', methods=['GET', 'POST'])
@login_required
def rate_participant(participant_id):
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    participant = Participant.query.get_or_404(participant_id)

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    # Check if already rated
    existing_evaluation = Evaluation.query.filter_by(
        evaluator_id=current_user.id,
        participant_id=participant_id
    ).first()

    if existing_evaluation:
        flash('You have already evaluated this participant. Please use the edit option.', 'warning')
        return redirect(url_for('select_participant'))

    if request.method == 'POST':
        try:
            # Validate that input values are between 1 and 100
            project_design = float(request.form['project_design'])
            functionality = float(request.form['functionality'])
            presentation = float(request.form['presentation'])
            web_design = float(request.form['web_design'])
            impact = float(request.form['impact'])

            # Ensure all scores are between 1 and 100
            if not all(1 <= score <= 100 for score in [project_design, functionality, presentation, web_design, impact]):
                flash('All scores must be between 1 and 100', 'danger')
                return render_template('rate_participant.html', participant=participant, criteria=criteria)

            evaluation = Evaluation(
                participant_id=participant_id,
                evaluator_id=current_user.id,
                project_design=project_design,
                functionality=functionality,
                presentation=presentation,
                web_design=web_design,
                impact=impact,
                comments=request.form.get('comments', '')
            )

            db.session.add(evaluation)
            db.session.commit()
            flash('Evaluation submitted successfully', 'success')

            return redirect(url_for('select_participant'))

        except (ValueError, KeyError):
            flash('Invalid evaluation data submitted', 'danger')
            return render_template('rate_participant.html', participant=participant, criteria=criteria)

    return render_template('rate_participant.html', participant=participant, criteria=criteria)

@app.route('/edit_evaluation/<int:evaluation_id>', methods=['GET', 'POST'])
@login_required
def edit_evaluation(evaluation_id):
    if current_user.role != 'evaluator':
        flash('Access denied', 'danger')
        return redirect(url_for('leaderboard'))

    # Get the evaluation
    evaluation = Evaluation.query.get_or_404(evaluation_id)

    # Get evaluation criteria
    criteria = EvaluationCriteria.query.first()
    if not criteria:
        criteria = EvaluationCriteria()
        db.session.add(criteria)
        db.session.commit()

    # Check if the evaluation belongs to the current user
    if evaluation.evaluator_id != current_user.id:
        flash('You can only edit your own evaluations', 'danger')
        return redirect(url_for('select_participant'))

    participant = Participant.query.get_or_404(evaluation.participant_id)

    if request.method == 'POST':
        try:
            # Validate that input values are between 1 and 100
            project_design = float(request.form['project_design'])
            functionality = float(request.form['functionality'])
            presentation = float(request.form['presentation'])
            web_design = float(request.form['web_design'])
            impact = float(request.form['impact'])

            # Ensure all scores are between 1 and 100
            if not all(1 <= score <= 100 for score in [project_design, functionality, presentation, web_design, impact]):
                flash('All scores must be between 1 and 100', 'danger')
                return render_template('edit_evaluation.html', evaluation=evaluation, participant=participant, criteria=criteria)

            # Update the evaluation
            evaluation.project_design = project_design
            evaluation.functionality = functionality
            evaluation.presentation = presentation
            evaluation.web_design = web_design
            evaluation.impact = impact
            evaluation.comments = request.form.get('comments', '')

            db.session.commit()
            flash('Evaluation updated successfully', 'success')
            return redirect(url_for('select_participant'))

        except (ValueError, KeyError):
            flash('Invalid evaluation data submitted', 'danger')
            return render_template('edit_evaluation.html', evaluation=evaluation, participant=participant, criteria=criteria)

    return render_template('edit_evaluation.html', evaluation=evaluation, participant=participant, criteria=criteria)


# Speed test routes removed