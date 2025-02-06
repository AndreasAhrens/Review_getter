# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dateutil.parser import parse as parse_date
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///disgusting_reviews.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------------------
# Database Models
# ---------------------------
class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_password_hash = db.Column(db.String(255), nullable=True)
    tripadvisor_api_key = db.Column(db.String(255), nullable=True)
    google_api_key = db.Column(db.String(255), nullable=True)

class ReviewSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pair_index = db.Column(db.Integer, nullable=False)  # Values 1 to 4
    platform = db.Column(db.String(50), nullable=False)   # 'TripAdvisor' or 'Google'
    title = db.Column(db.String(100), nullable=False)
    identifier = db.Column(db.String(500), nullable=False)

# ---------------------------
# Helper Functions
# ---------------------------
def get_setting():
    """Return the singleton Setting record; create one if it doesn't exist."""
    setting = Setting.query.first()
    if not setting:
        setting = Setting()
        db.session.add(setting)
        db.session.commit()
    return setting

def login_required(f):
    """Decorator to enforce admin login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------
# Admin Routes
# ---------------------------
@app.route('/admin/setup', methods=['GET', 'POST'])
def admin_setup():
    """
    Setup route – if no admin password is set, force the user to create one.
    Once set, the user must log in via the login page.
    """
    setting = get_setting()
    if setting.admin_password_hash:
        flash("Admin password already set. Please log in.", "error")
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if not password or not confirm:
            flash("Please fill in all fields.", "error")
            return render_template('setup.html')
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template('setup.html')
        setting.admin_password_hash = generate_password_hash(password)
        db.session.commit()
        flash("Admin password set successfully. Please log in.", "success")
        return redirect(url_for('admin_login'))
    return render_template('setup.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Simple login page for the admin area."""
    setting = get_setting()
    if not setting.admin_password_hash:
        return redirect(url_for('admin_setup'))
    if request.method == 'POST':
        password = request.form.get('password')
        if check_password_hash(setting.admin_password_hash, password):
            session['admin_logged_in'] = True
            flash("Logged in successfully.", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Invalid password.", "error")
            return render_template('login.html')
    return render_template('login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    """Logs out the admin user."""
    session.pop('admin_logged_in', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('admin_login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    """
    The admin panel allows the user to set:
      - Global API keys for TripAdvisor and Google.
      - Up to 4 pairs of review sources. For each pair:
          * TripAdvisor identifier and title.
          * Google identifier and title.
    """
    setting = get_setting()
    if request.method == 'POST':
        # Update API keys
        setting.tripadvisor_api_key = request.form.get('tripadvisor_api_key').strip()
        setting.google_api_key = request.form.get('google_api_key').strip()
        db.session.commit()
        # Clear existing review sources
        ReviewSource.query.delete()
        db.session.commit()
        # Loop through 4 pairs
        for i in range(1, 5):
            ta_identifier = request.form.get(f'ta_identifier_{i}')
            ta_title = request.form.get(f'ta_title_{i}')
            google_identifier = request.form.get(f'google_identifier_{i}')
            google_title = request.form.get(f'google_title_{i}')
            if ta_identifier and ta_title:
                source = ReviewSource(pair_index=i, platform='TripAdvisor',
                                      title=ta_title.strip(), identifier=ta_identifier.strip())
                db.session.add(source)
            if google_identifier and google_title:
                source = ReviewSource(pair_index=i, platform='Google',
                                      title=google_title.strip(), identifier=google_identifier.strip())
                db.session.add(source)
        db.session.commit()
        flash("Settings updated successfully!", "success")
        return redirect(url_for('admin_panel'))
    else:
        # Load existing sources, organized by pair index.
        sources = ReviewSource.query.all()
        pairs = {i: {} for i in range(1, 5)}
        for source in sources:
            pairs[source.pair_index][source.platform] = source
        return render_template('admin.html', setting=setting, pairs=pairs)

# ---------------------------
# Public Route
# ---------------------------
@app.route('/')
def public():
    """
    The public-facing page calls the TripAdvisor and Google APIs (using your API keys and identifiers)
    to count the number of 5‑star reviews created during the current month for each attraction.
    The layout adjusts based on the number of sources defined.
    """
    setting = get_setting()
    sources = ReviewSource.query.all()
    # Sort sources by pair index and platform for consistency.
    sources_sorted = sorted(sources, key=lambda x: (x.pair_index, x.platform))
    total_sources = len(sources_sorted)
    
    results = []
    for source in sources_sorted:
        if source.platform == 'TripAdvisor':
            count = get_tripadvisor_review_count(setting.tripadvisor_api_key, source.identifier)
        elif source.platform == 'Google':
            count = get_google_review_count(setting.google_api_key, source.identifier)
        else:
            count = "N/A"
        results.append({'title': source.title, 'count': count, 'platform': source.platform})
    
    return render_template('public.html', results=results, total_sources=total_sources)

# ---------------------------
# API Call Functions
# ---------------------------
def get_tripadvisor_review_count(api_key, attraction_id):
    """
    Call the TripAdvisor API to retrieve reviews for a given attraction (by its identifier)
    and count the 5‑star reviews created during the current month.
    (Adjust the endpoint and parsing logic per TripAdvisor’s actual API documentation.)
    """
    try:
        # Hypothetical API endpoint – update according to real documentation.
        url = f"https://api.tripadvisor.com/api/attraction/{attraction_id}/reviews"
        params = {"api_key": api_key}
        response = requests.get(url, params=params)
        if response.status_code != 200:
            return "Error"
        data = response.json()
        reviews = data.get("reviews", [])
        now = datetime.now()
        count = 0
        for review in reviews:
            if review.get("rating") == 5:
                # Assume the review date is in a parseable string format.
                review_date = parse_date(review.get("date"))
                if review_date.month == now.month and review_date.year == now.year:
                    count += 1
        return count
    except Exception as e:
        print(f"Error in TripAdvisor API call: {e}")
        return "Error"

def get_google_review_count(api_key, place_id):
    """
    Call the Google Places API to retrieve reviews for a given place (by its identifier)
    and count the 5‑star reviews created during the current month.
    (Adjust according to the current Google Places API documentation.)
    """
    try:
        url = "https://maps.googleapis.com/maps/api/place/details/json"
        params = {"placeid": place_id, "key": api_key}
        response = requests.get(url, params=params)
        if response.status_code != 200:
            return "Error"
        data = response.json()
        reviews = data.get("result", {}).get("reviews", [])
        now = datetime.now()
        count = 0
        for review in reviews:
            if review.get("rating") == 5:
                # Google reviews usually have a Unix timestamp in the "time" field.
                review_date = datetime.fromtimestamp(review.get("time"))
                if review_date.month == now.month and review_date.year == now.year:
                    count += 1
        return count
    except Exception as e:
        print(f"Error in Google API call: {e}")
        return "Error"

# ---------------------------
# Run the App
# ---------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)