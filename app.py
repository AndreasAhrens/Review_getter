# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dateutil.parser import parse as parse_date
from datetime import datetime
from functools import wraps
import os
import json

# Try to import OAuth modules; if not available, set a flag.
try:
    from google_auth_oauthlib.flow import Flow
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    OAUTH_ENABLED = True
except ImportError:
    OAUTH_ENABLED = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Replace with your strong secret key!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///disgusting_reviews.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Flask-Migrate initialization

# ---------------------------
# Database Models
# ---------------------------
class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_password_hash = db.Column(db.String(255), nullable=True)
    tripadvisor_api_key = db.Column(db.String(255), nullable=True)
    # Retain google_api_key if needed, though OAuth is used.
    google_api_key = db.Column(db.String(255), nullable=True)
    # New field to store OAuth credentials as JSON.
    google_credentials = db.Column(db.Text, nullable=True)

class ReviewSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pair_index = db.Column(db.Integer, nullable=False)  # Values 1 to 4
    platform = db.Column(db.String(50), nullable=False)   # 'TripAdvisor' or 'Google'
    title = db.Column(db.String(100), nullable=False)
    # For Google, enter the full resource name (e.g., "accounts/123456789/locations/987654321")
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
    If OAuth is enabled, a link to authorize Google OAuth is provided.
    """
    setting = get_setting()
    if request.method == 'POST':
        # Update API keys.
        setting.tripadvisor_api_key = request.form.get('tripadvisor_api_key').strip()
        setting.google_api_key = request.form.get('google_api_key').strip()
        db.session.commit()
        # Clear existing review sources.
        ReviewSource.query.delete()
        db.session.commit()
        # Loop through 4 pairs.
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
        return render_template('admin.html', setting=setting, pairs=pairs, oauth_enabled=OAUTH_ENABLED)

# ---------------------------
# Google OAuth Routes
# ---------------------------
if OAUTH_ENABLED:
    @app.route('/google/oauth')
    @login_required
    def google_oauth():
        """
        Initiates the OAuth 2.0 flow for Google.
        Requires a valid client_secrets.json in the project directory.
        """
        flow = Flow.from_client_secrets_file(
            'client_secrets.json',
            scopes=["https://www.googleapis.com/auth/business.manage"],
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        session['state'] = state
        return redirect(authorization_url)

    @app.route('/oauth2callback')
    @login_required
    def oauth2callback():
        """
        Handles the OAuth 2.0 callback and stores the credentials.
        """
        state = session.get('state')
        flow = Flow.from_client_secrets_file(
            'client_secrets.json',
            scopes=["https://www.googleapis.com/auth/business.manage"],
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        creds_dict = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': list(credentials.scopes)
        }
        setting = get_setting()
        setting.google_credentials = json.dumps(creds_dict)
        db.session.commit()
        flash("Google OAuth credentials saved successfully.", "success")
        return redirect(url_for('admin_panel'))
else:
    @app.route('/google/oauth')
    @login_required
    def google_oauth():
        flash("Google OAuth functionality is not enabled because the required modules are missing.", "error")
        return redirect(url_for('admin_panel'))

# ---------------------------
# Public Route
# ---------------------------
@app.route('/')
def public():
    """
    The public-facing page calls the TripAdvisor and Google APIs (using your API keys and credentials)
    to count the number of 5‑star reviews created during the current month and last month for each attraction.
    """
    setting = get_setting()
    sources = ReviewSource.query.all()
    # Sort sources by pair index and platform.
    sources_sorted = sorted(sources, key=lambda x: (x.pair_index, x.platform))
    
    results = []
    for source in sources_sorted:
        if source.platform == 'TripAdvisor':
            current_count, last_count = get_tripadvisor_review_count(setting.tripadvisor_api_key, source.identifier)
        elif source.platform == 'Google':
            # Expect the Google identifier to be the full resource name.
            current_count, last_count = get_google_review_count(source.identifier)
        else:
            current_count, last_count = ("N/A", "N/A")
        results.append({
            'title': source.title,
            'platform': source.platform,
            'current_count': current_count,
            'last_count': last_count
        })
    
    return render_template('public.html', results=results)

# ---------------------------
# API Call Functions
# ---------------------------
def get_tripadvisor_review_count(api_key, location_id):
    """
    Uses the TripAdvisor Content API to retrieve reviews for a given location and
    counts the 5‑star reviews created during the current month and last month.
    """
    try:
        url = f"https://api.content.tripadvisor.com/api/v1/location/{location_id}/reviews"
        params = {"key": api_key}
        headers = {"accept": "application/json"}
        response = requests.get(url, params=params, headers=headers)
        if response.status_code != 200:
            print("TripAdvisor API returned status code:", response.status_code)
            return ("Error", "Error")
        
        data = response.json()
        reviews = data.get("data", [])
        
        now = datetime.now()
        current_month = now.month
        current_year = now.year
        if current_month == 1:
            last_month = 12
            last_year = current_year - 1
        else:
            last_month = current_month - 1
            last_year = current_year
        
        current_count = 0
        last_count = 0
        for review in reviews:
            if review.get("rating") == 5:
                review_date_str = review.get("published_date", "")
                if review_date_str:
                    review_date = parse_date(review_date_str, fuzzy=True)
                    if review_date.month == current_month and review_date.year == current_year:
                        current_count += 1
                    elif review_date.month == last_month and review_date.year == last_year:
                        last_count += 1
        return current_count, last_count
    except Exception as e:
        print(f"Error in TripAdvisor API call: {e}")
        return ("Error", "Error")

def get_google_review_count(resource_name):
    """
    Uses the Google Business Profile API to retrieve reviews for a given location and
    counts the 5‑star reviews for the current month and last month.
    Parameters:
      - resource_name: Full resource name (e.g., "accounts/123456789/locations/987654321").
    This function uses OAuth 2.0 credentials stored in the database.
    """
    if not OAUTH_ENABLED:
        return ("OAuth Not Configured", "OAuth Not Configured")
    try:
        setting = get_setting()
        if not setting.google_credentials:
            print("No Google OAuth credentials found.")
            return ("OAuth Not Enabled", "OAuth Not Enabled")
        creds_dict = json.loads(setting.google_credentials)
        credentials = Credentials(
            token=creds_dict['token'],
            refresh_token=creds_dict.get('refresh_token'),
            token_uri=creds_dict['token_uri'],
            client_id=creds_dict['client_id'],
            client_secret=creds_dict['client_secret'],
            scopes=creds_dict['scopes']
        )
        service = build('mybusinessbusinessinformation', 'v1', credentials=credentials)
        response = service.locations().reviews().list(
            parent=resource_name,
            pageSize=100
        ).execute()
        reviews = response.get("reviews", [])
        
        now = datetime.now()
        current_month = now.month
        current_year = now.year
        if current_month == 1:
            last_month = 12
            last_year = current_year - 1
        else:
            last_month = current_month - 1
            last_year = current_year
        
        current_count = 0
        last_count = 0
        for review in reviews:
            if review.get("starRating") == "FIVE":
                review_date_str = review.get("createTime", "")
                if review_date_str:
                    review_date = parse_date(review_date_str, fuzzy=True)
                    if review_date.month == current_month and review_date.year == current_year:
                        current_count += 1
                    elif review_date.month == last_month and review_date.year == last_year:
                        last_count += 1
        return current_count, last_count
    except Exception as e:
        print(f"Error in Google Business Profile API call: {e}")
        return ("Error", "Error")

# ---------------------------
# Run the App
# ---------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
