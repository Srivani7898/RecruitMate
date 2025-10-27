# # RecruitMate - Modules 1 to 7: Auth + HR Dashboard + Resume Parser + Analysis + Job Seeker + Notifications + Recommendations

# from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from flask_dance.contrib.google import make_google_blueprint, google
# from werkzeug.utils import secure_filename
# from datetime import timedelta
# import os
# import json
# import google.generativeai as genai
# from collections import Counter
# from flask import flash


# # Gemini API setup
# genai.configure(api_key="")

# app = Flask(__name__)
# app.secret_key = "super-secret-key"
# app.config["JWT_SECRET_KEY"] = "jwt-secret-key"
# app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
# app.config['UPLOAD_FOLDER'] = "uploads/resumes"
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# # Google OAuth setup
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# app.config["GOOGLE_OAUTH_CLIENT_ID"] = ""
# app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = ""
# google_bp = make_google_blueprint(scope=["profile", "email"])
# app.register_blueprint(google_bp, url_prefix="/login")

# jwt = JWTManager(app)

# # In-memory DB simulation
# users_db = {
#     "hr@example.com": {"password": "hr123", "role": "hr"},
#     "user@example.com": {"password": "user123", "role": "user"}
# }
# jobs_db = []
# resumes_db = []
# parsed_results = []
# user_applications = []  # [{email, job_title, filename, status}]
# notifications = []  # [{message, target: 'all' or email}]

# @app.route('/')
# def home():
#     return redirect(url_for('login'))

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
#         user = users_db.get(email)
#         if user and user['password'] == password:
#             access_token = create_access_token(identity={"email": email, "role": user['role']})
#             session['access_token'] = access_token
#             session['role'] = user['role']
#             session['email'] = email
#             return redirect(url_for(f"{user['role']}_dashboard"))
#         return "Invalid credentials"
#     return render_template('login.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
#         role = request.form['role']
#         if email in users_db:
#             return "User already exists"
#         users_db[email] = {"password": password, "role": role}
#         return redirect(url_for('login'))
#     return render_template('register.html')

# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('login'))

# @app.route('/google_login')
# def google_login():
#     if not google.authorized:
#         return redirect(url_for("google.login"))
#     resp = google.get("/oauth2/v2/userinfo")
#     user_info = resp.json()
#     email = user_info["email"]
#     if email not in users_db:
#         users_db[email] = {"password": "", "role": "user"}
#     session['access_token'] = create_access_token(identity={"email": email, "role": users_db[email]['role']})
#     session['role'] = users_db[email]['role']
#     session['email'] = email
#     return redirect(url_for(f"{users_db[email]['role']}_dashboard"))

# @app.route('/hr_dashboard', methods=['GET', 'POST'])
# @jwt_required(optional=True)
# def hr_dashboard():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     return render_template('hr_dashboard.html', jobs=jobs_db, parsed=parsed_results)

# @app.route('/post_job', methods=['POST'])
# @jwt_required(optional=True)
# def post_job():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     title = request.form['title']
#     description = request.form['description']
#     requirements = request.form['requirements']
#     last_date = request.form['last_date']
#     jobs_db.append({"title": title, "description": description, "requirements": requirements, "last_date": last_date})
#     flash("Job posted successfully!")
#     return redirect(url_for('hr_dashboard'))

# @app.route('/upload_resumes', methods=['POST'])
# @jwt_required(optional=True)
# def upload_resumes():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     job_title = request.form['job_title']
#     files = request.files.getlist("resumes")
#     for file in files:
#         filename = secure_filename(file.filename)
#         path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         file.save(path)
#         resumes_db.append({"filename": filename, "job_title": job_title})
#     flash(f"Uploaded {len(files)} resumes for job: {job_title}")
#     return redirect(url_for('hr_dashboard'))

# @app.route('/broadcast', methods=['POST'])
# @jwt_required(optional=True)
# def broadcast():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     msg = request.form['message']
#     notifications.append({"message": msg, "target": "all"})
#     flash("Notification sent to all job seekers.")
#     return redirect(url_for('hr_dashboard'))

# @app.route('/parse_resumes', methods=['POST'])
# @jwt_required(optional=True)
# def parse_resumes():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     parsed_results.clear()
#     for resume in resumes_db:
#         path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
#         with open(path, "rb") as f:
#             content = f.read()
#         prompt = f"""
#         Extract the following from the resume:
#         - Name
#         - Gender
#         - Skills
#         - Education
#         - Work Experience (in years)

#         Resume Text:
#         {content}

#         Output as JSON
#         """
#         try:
#             model = genai.GenerativeModel("gemini-pro")
#             response = model.generate_content(prompt)
#             data = json.loads(response.text)

#             job = next((j for j in jobs_db if j['title'] == resume['job_title']), None)
#             required_skills = job['requirements'].lower().split(',') if job else []
#             candidate_skills = [s.lower().strip() for s in data.get("Skills", [])]
#             match_count = len(set(candidate_skills) & set(required_skills))
#             total_required = len(required_skills) if required_skills else 1
#             match_percent = int((match_count / total_required) * 100)
#             status = "Selected" if match_percent >= 70 else "Not Selected"

#             parsed_results.append({
#                 "filename": resume['filename'],
#                 "job_title": resume['job_title'],
#                 "name": data.get("Name"),
#                 "gender": data.get("Gender"),
#                 "skills": candidate_skills,
#                 "education": data.get("Education"),
#                 "experience": data.get("Work Experience"),
#                 "score": match_percent,
#                 "status": status
#             })
#         except Exception as e:
#             print("Error parsing resume:", resume['filename'], str(e))
#             continue
#     flash("Resumes parsed and ranked successfully.")
#     return redirect(url_for('hr_dashboard'))

# @app.route('/analysis_dashboard')
# @jwt_required(optional=True)
# def analysis_dashboard():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     selected = sum(1 for r in parsed_results if r['status'] == 'Selected')
#     rejected = sum(1 for r in parsed_results if r['status'] == 'Not Selected')
#     gender_data = Counter(r['gender'] for r in parsed_results)
#     return render_template('analysis.html', selected=selected, rejected=rejected, gender_data=gender_data)

# @app.route('/user_dashboard', methods=['GET', 'POST'])
# @jwt_required(optional=True)
# def user_dashboard():
#     if session.get('role') != 'user':
#         return "Unauthorized", 403
#     user_email = session.get('email')
#     user_apps = [a for a in user_applications if a['email'] == user_email]
#     user_notifications = [n['message'] for n in notifications if n['target'] == 'all' or n['target'] == user_email]
#     return render_template('user_dashboard.html', jobs=jobs_db, applications=user_apps, notifications=user_notifications)

# @app.route('/apply_job', methods=['POST'])
# @jwt_required(optional=True)
# def apply_job():
#     if session.get('role') != 'user':
#         return "Unauthorized", 403
#     email = session['email']
#     job_title = request.form['job_title']
#     file = request.files['resume']
#     filename = secure_filename(file.filename)
#     path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#     file.save(path)
#     user_applications.append({"email": email, "job_title": job_title, "filename": filename, "status": "Pending"})
#     flash("Resume submitted successfully.")
#     return redirect(url_for('user_dashboard'))

# @app.route('/recommend_jobs')
# @jwt_required(optional=True)
# def recommend_jobs():
#     if session.get('role') != 'user':
#         return "Unauthorized", 403
#     email = session.get('email')
#     user_resume = next((a['filename'] for a in user_applications[::-1] if a['email'] == email), None)
#     if not user_resume:
#         flash("Please apply to a job with your resume first.")
#         return redirect(url_for('user_dashboard'))

#     resume_path = os.path.join(app.config['UPLOAD_FOLDER'], user_resume)
#     with open(resume_path, 'rb') as f:
#         resume_text = f.read()

#     # Create prompt with all JDs
#     job_snippets = "\n\n".join([f"Title: {job['title']}\nDescription: {job['description']}\nRequirements: {job['requirements']}" for job in jobs_db])
#     prompt = f"""
#     Based on the following resume, recommend top 3 most suitable job roles from the list below:

#     Resume:
#     {resume_text}

#     Job Descriptions:
#     {job_snippets}

#     Output in JSON format with fields: title, match_reason
#     """
#     try:
#         model = genai.GenerativeModel("gemini-pro")
#         response = model.generate_content(prompt)
#         recommendations = json.loads(response.text)
#     except Exception as e:
#         flash("Recommendation failed. Please try again.")
#         print("Error during recommendation:", str(e))
#         recommendations = []

#     user_email = session.get('email')
#     user_apps = [a for a in user_applications if a['email'] == user_email]
#     user_notifications = [n['message'] for n in notifications if n['target'] == 'all' or n['target'] == user_email]
#     return render_template('user_dashboard.html', jobs=jobs_db, applications=user_apps, notifications=user_notifications, recommendations=recommendations)

# if __name__ == '__main__':
#     os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
#     app.run(debug=True)


# RecruitMate - Modules 1 to 7: Auth + HR Dashboard + Resume Parser + Analysis + Job Seeker + Notifications + Recommendations (Gemini Fixed)

# RecruitMate - Modules 1 to 7: Auth + HR Dashboard + Resume Parser + Analysis + Job Seeker + Notifications + Recommendations (Gemini Fixed)

# from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from flask_dance.contrib.google import make_google_blueprint, google
# from werkzeug.utils import secure_filename
# from datetime import timedelta
# from mimetypes import guess_type
# import os
# import json
# import google.generativeai as genai
# from collections import Counter

# # Gemini API setup
# genai.configure(api_key="AIzaSyB9Tkd8nrTrpMs7TZnqRu3J3ATrxgG78")

# app = Flask(__name__)
# app.secret_key = "super-secret-key"
# app.config["JWT_SECRET_KEY"] = "jwt-secret-key"
# app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
# app.config['UPLOAD_FOLDER'] = "uploads/resumes"
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# # Google OAuth setup
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# app.config["GOOGLE_OAUTH_CLIENT_ID"] = "1083025930139-e5s2msjihkrhioi7ai4kl9mhdm4goh2l.apps.googleusercontent.com"
# app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "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"
# google_bp = make_google_blueprint(scope=["profile", "email"])
# app.register_blueprint(google_bp, url_prefix="/login")

# jwt = JWTManager(app)

# # In-memory DB simulation
# users_db = {
#     "hr@example.com": {"password": "hr123", "role": "hr"},
#     "user@example.com": {"password": "user123", "role": "user"}
# }
# jobs_db = []
# resumes_db = []
# parsed_results = []
# user_applications = []
# notifications = []

# @app.route('/parse_resumes', methods=['POST'])
# @jwt_required(optional=True)
# def parse_resumes():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403
#     parsed_results.clear()

#     for resume in resumes_db:
#         path = os.path.join(app.config['UPLOAD_FOLDER'], resume['filename'])
#         with open(path, "rb") as f:
#             content = f.read()

#         mime_type, _ = guess_type(path)
#         if not mime_type:
#             flash(f"Could not detect file type for {resume['filename']}")
#             continue

#         prompt = f"""
#         Extract the following from the resume:
#         - Name
#         - Gender
#         - Skills
#         - Education
#         - Work Experience (in years)

#         Output in JSON format
#         """

#         try:
#             model = genai.GenerativeModel("models/gemini-pro-vision")
#             response = model.generate_content([
#                 {"text": prompt},
#                 {"mime_type": mime_type, "data": content}
#             ])
#             data = json.loads(response.text)

#             job = next((j for j in jobs_db if j['title'] == resume['job_title']), None)
#             required_skills = job['requirements'].lower().split(',') if job else []
#             candidate_skills = [s.lower().strip() for s in data.get("Skills", [])]
#             match_count = len(set(candidate_skills) & set(required_skills))
#             total_required = len(required_skills) if required_skills else 1
#             match_percent = int((match_count / total_required) * 100)
#             status = "Selected" if match_percent >= 70 else "Not Selected"

#             parsed_results.append({
#                 "filename": resume['filename'],
#                 "job_title": resume['job_title'],
#                 "name": data.get("Name"),
#                 "gender": data.get("Gender"),
#                 "skills": candidate_skills,
#                 "education": data.get("Education"),
#                 "experience": data.get("Work Experience"),
#                 "score": match_percent,
#                 "status": status
#             })
#         except Exception as e:
#             print(f"Error parsing resume: {resume['filename']} - {str(e)}")
#             flash(f"Failed to parse {resume['filename']}. Error: {str(e)}")
#             continue

#     flash("Resumes parsed and ranked successfully.")
#     return redirect(url_for('hr_dashboard'))


# RecruitMate - Complete main.py (Modules 1 to 7 Integrated)

# RecruitMate - Complete main.py (Grouped Applicants View)

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_dance.contrib.google import make_google_blueprint, google
from flask import session, redirect, url_for, render_template
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from werkzeug.utils import secure_filename
from datetime import timedelta
import os
import json
import google.generativeai as genai
from collections import defaultdict
from PyPDF2 import PdfReader
import docx
from flask import send_from_directory
import math
from flask import request
from collections import Counter, defaultdict
import re
import hashlib
from time import time
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import make_response, redirect, url_for, request, render_template, flash
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies,
    jwt_required, get_jwt_identity, get_jwt
)



# Gemini API setup
genai.configure(api_key="AIzaSyA4xQdYVw4pPqB6_c0NPdzQr3QX5bw8zDc")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///smarthire.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
app.secret_key = "change-this"  # needed for Flask sessions
app.permanent_session_lifetime = timedelta(days=7)  # match your "remember me"
app.config["JWT_SECRET_KEY"] = "change-me"  # set a strong secret
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # set True later and add CSRF tokens
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['UPLOAD_FOLDER'] = "uploads/resumes"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Allowed upload extensions (guard)
ALLOWED_EXTS = {'.pdf', '.docx', '.txt'}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'hr' or 'user'

    def set_password(self, plain: str) -> None:
        self.password_hash = generate_password_hash(plain)

    def check_password(self, plain: str) -> bool:
        return check_password_hash(self.password_hash, plain)

def allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTS

# Google OAuth setup
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "428381505737-lka4bude9seiikdhj5tc81bv0meiugoj.apps.googleusercontent.com"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "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"
google_bp = make_google_blueprint(scope=["profile", "email"])
app.register_blueprint(google_bp, url_prefix="/login")

jwt = JWTManager(app)

# In-memory DB simulation
users_db = {
    "hr@example.com": {"password": "hr123", "role": "hr"},
    "user@example.com": {"password": "user123", "role": "user"}
}
jobs_db = []
resumes_db = []
parsed_results = []
user_applications = []
notifications = []

# Simple in-memory caches
#skills_cache = {}  # key: resume_sig -> list[str]
#name_cache   = {}  # key: resume_sig -> str

# Cache: resume_sig -> extracted skills (from Gemini) and candidate name (local)
skills_cache = {}   # {signature: ["java", "spring", ...]}
name_cache   = {}   # {signature: "Candidate Name"}


# Gemeni budget per /parse_resumes call
MAX_GEMINI_CALLS_PER_PARSE = 5
# routes

with app.app_context():
    db.create_all()

    def ensure_user(email, password, role):
        u = User.query.filter_by(email=email).first()
        if not u:
            u = User(email=email, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()

    # Seed once; change passwords if you want
    ensure_user("hr@recruitmate.ai", "hr123", "hr")
    ensure_user("user@recruitmate.ai", "user123", "user")

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    remember = "remember" in request.form  # from your checkbox

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        flash("Invalid email or password", "error")
        return render_template("login.html"), 401

    # Access token TTL: short if not remembered, long if remembered
    access_ttl = timedelta(hours=6) if not remember else timedelta(days=7)
    refresh_ttl = timedelta(days=30)

    access_token = create_access_token(
        identity=email,
        additional_claims={"role": user.role},
        expires_delta=access_ttl
    )
    refresh_token = create_refresh_token(
        identity=email,
        expires_delta=refresh_ttl
    )

    # persist legacy session too (so old routes that use session keep working)
    session['email'] = email
    session['role']  = user.role
    session.permanent = bool(remember)

    # Redirect by role
    dest = "hr_dashboard" if user.role == "hr" else "user_dashboard"
    resp = make_response(redirect(url_for(dest)))
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")  # 'hr' or 'user'

    if not email or not password:
        flash("Email and password are required", "error")
        return render_template("register.html"), 400

    if role not in ("hr", "user"):
        flash("Invalid role", "error")
        return render_template("register.html"), 400

    if User.query.filter_by(email=email).first():
        flash("User already exists", "error")
        return render_template("register.html"), 409

    u = User(email=email, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    flash("Registration successful. Please sign in.", "success")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    unset_jwt_cookies(resp)
    return resp

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    user_info = resp.json()
    email = user_info["email"]
    if email not in users_db:
        users_db[email] = {"password": "", "role": "user"}
    session['access_token'] = create_access_token(identity={"email": email, "role": users_db[email]['role']})
    session['role'] = users_db[email]['role']
    session['email'] = email
    return redirect(url_for(f"{users_db[email]['role']}_dashboard"))

# --- NEW: HR Screening Page (separate from landing) ---
@app.route('/screening', methods=['GET'])
@jwt_required(optional=True)
def screening():
    if session.get('role') != 'hr':
        return "Unauthorized", 403

    resumes_count = len(resumes_db)
    jobs = jobs_db
    latest_results = sorted(parsed_results, key=lambda x: x['score'], reverse=True)[:10]

    # provide empty by default
    skills_preview = []

    return render_template(
        'screening.html',
        jobs=jobs,
        resumes_count=resumes_count,
        latest_results=latest_results,
        skills_preview=skills_preview
    )

@app.route('/set_status', methods=['POST'])
@jwt_required(optional=True)
def set_status():
    if session.get('role') != 'hr':
        return "Unauthorized", 403

    filename   = request.form.get('filename')
    new_status = request.form.get('status')  # "Selected" | "Rejected" | "Pending"
    if not filename or new_status not in ("Selected", "Rejected", "Pending"):
        flash("Invalid status update.")
        return redirect(url_for('screening'))

    # Update parsed rows
    row = next((r for r in parsed_results if r['filename'] == filename), None)
    if row:
        row['status'] = new_status

    # Update the applicant’s record and notify them
    app_row = next((a for a in user_applications if a.get('resume_file') == filename), None)
    if app_row:
        app_row['status'] = new_status
        notifications.append({
            "message": f"Your application for '{app_row['job_title']}' is {new_status}.",
            "target": app_row['email']
        })

    flash(f"Status set to {new_status}. Candidate notified.")
    return redirect(url_for('screening'))

from flask_jwt_extended import jwt_required, get_jwt

@app.route('/hr_dashboard')
@jwt_required(optional=True)
def hr_dashboard():
    # accept either old session or new JWT
    role = session.get('role')
    if not role:
        claims = get_jwt() or {}
        role = claims.get('role')

    if role != 'hr':
        return redirect(url_for('login'))  # or return "Unauthorized", 403

    sorted_parsed = sorted(parsed_results, key=lambda x: x['score'], reverse=True)

    # NEW: group applicants by job title
    grouped_applications = {job['title']: [] for job in jobs_db}
    for app in user_applications:
        grouped_applications.setdefault(app['job_title'], []).append(app)

    return render_template(
        'hr_dashboard.html',
        jobs=jobs_db,
        parsed=sorted_parsed,
        applications=user_applications,       # still available if you need it
        grouped_applications=grouped_applications  # <— use this in the template
    )

# --- Updated Job Posting Route ---
@app.route('/post_job', methods=['POST'])
@jwt_required(optional=True)
def post_job():
    if session.get('role') != 'hr':
        return "Unauthorized", 403
    jobs_db.append({
        "title": request.form['title'],
        "description": request.form['description'],
        "requirements": request.form['requirements'],
        "salary": request.form['salary'],
        "last_date": request.form['last_date']
    })
    flash("Job posted successfully!")
    return redirect(url_for('hr_dashboard'))

@app.route('/upload_resumes', methods=['POST'])
@jwt_required(optional=True)
def upload_resumes():
    if session.get('role') != 'hr':
        return "Unauthorized", 403

    job_title = request.form.get('job_title')
    files = request.files.getlist("resumes")
    uploaded = 0
    skipped = 0

    for file in files:
        if not file or not getattr(file, "filename", None):
            skipped += 1
            continue

        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            skipped += 1
            flash(f"Skipped {filename}: unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXTS))}")
            continue

        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # ensure upload dir
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(path)
        resumes_db.append({"filename": filename, "job_title": job_title})
        uploaded += 1

    if uploaded:
        flash(f"Uploaded {uploaded} resume(s) for job: {job_title}")
    if skipped and not uploaded:
        flash("No files uploaded. Please check file types and try again.")
    return redirect(url_for('screening'))

@app.route('/broadcast', methods=['POST'])
@jwt_required(optional=True)
def broadcast():
    if session.get('role') != 'hr':
        return "Unauthorized", 403
    msg = request.form['message']
    notifications.append({"message": msg, "target": "all"})
    flash("Notification sent to all job seekers.")
    return redirect(url_for('hr_dashboard'))


# -------- Parsing Helpers --------


# --- Add near other helpers ---
def parse_skills_with_gemini(resume_text: str):
    if not resume_text or not resume_text.strip():
        return []

    prompt = (
        "Extract ONLY the candidate's skills from the resume text as a JSON array of strings. "
        "No prose, no keys, strictly a JSON array. Example: [\"Java\", \"Spring Boot\", \"SQL\"]\n\n"
        f"Resume Text:\n{resume_text[:4000]}"
    )

    try:
        model = genai.GenerativeModel(
            model_name="models/gemini-1.5-flash-latest",
            generation_config={"temperature": 0, "top_p": 0.1, "response_mime_type": "application/json"}
        )
        resp = model.generate_content(prompt)

        raw = (getattr(resp, "text", "") or "").strip()
        if not raw:
            # Some SDK versions keep text in parts
            try:
                parts = resp.candidates[0].content.parts
                raw = "".join(getattr(p, "text", "") for p in parts).strip()
            except Exception:
                raw = ""

        if not raw:
            print("[GEMINI] Empty response (possibly safety/quota).")
            return []

        try:
            data = json.loads(raw)
        except Exception:
            import re
            m = re.search(r"\[.*\]", raw, flags=re.DOTALL)
            data = json.loads(m.group(0)) if m else []

        skills, seen = [], set()
        for s in data if isinstance(data, list) else []:
            if isinstance(s, str):
                ss = s.strip()
                if ss and ss.lower() not in seen:
                    seen.add(ss.lower()); skills.append(ss)
        return skills

    except Exception as e:
        msg = str(e)
        print(f"[GEMINI][ERROR] {msg}")
        # surface common cases nicely
        if any(x in msg.lower() for x in ["quota", "rate", "429", "exceeded", "billing"]):
            from flask import flash
            flash("Gemini quota/rate-limit hit. Using local extraction for now.")
        else:
            flash("Gemini skills extraction failed. Using local extraction for now.")
        return []

def parse_name_with_gemini(resume_text: str):
    if not resume_text: return "N/A"
    try:
        model = genai.GenerativeModel(
            model_name="models/gemini-1.5-flash-latest",
            generation_config={"temperature": 0, "response_mime_type": "text/plain"}
        )
        resp = model.generate_content("From the resume text, output ONLY the candidate's full name (no label):\n\n"+resume_text[:1500])
        name = (resp.text or "").strip().splitlines()[0].strip()
        return name if 2 <= len(name) <= 80 else "N/A"
    except Exception:
        return "N/A"


# --- NEW: Preview skills for all queued resumes (no scoring yet) ---
# @app.route('/preview_skills', methods=['POST'])
# @jwt_required(optional=True)
# def preview_skills():
#     if session.get('role') != 'hr':
#         return "Unauthorized", 403

#     skills_preview = []
#     for rec in resumes_db:
#         path = os.path.join(app.config['UPLOAD_FOLDER'], rec['filename'])
#         text = extract_text_from_resume(path)
#         sig  = resume_signature(path)

#         # Show ONLY what we have already stored (Gemini results after screening),
#         # otherwise mark as "not screened yet" to avoid API usage here.
#         skills = skills_cache.get(sig)
#         skills_preview.append({
#             "filename": rec['filename'],
#             "job_title": rec.get('job_title'),
#             "skills": skills if skills else None  # None -> not screened yet
#         })

#         print(f"[SKILLS][PREVIEW] file={rec['filename']} -> "
#               f"{skills if skills else '(not screened yet)'}")

#     flash(f"Preview ready for {len(skills_preview)} resume(s). "
#           "Skills appear after you run Start Screening.")
#     resumes_count  = len(resumes_db)
#     latest_results = list(parsed_results)  # whatever last screening produced
#     return render_template('screening.html',
#                            jobs=jobs_db,
#                            resumes_count=resumes_count,
#                            latest_results=latest_results,
#                            skills_preview=skills_preview)

# ---------------new preview------------
@app.route('/preview_skills', methods=['GET', 'POST'])
@jwt_required(optional=True)
def preview_skills():
    if session.get('role') != 'hr':
        return "Unauthorized", 403

    # Build preview from CACHE ONLY (no Gemini calls)
    skills_preview = []
    for rec in resumes_db:
        path = os.path.join(app.config['UPLOAD_FOLDER'], rec['filename'])
        sig  = resume_signature(path)
        skills = skills_cache.get(sig)  # None => not screened yet
        skills_preview.append({
            "filename": rec['filename'],
            "job_title": rec.get('job_title'),
            "skills": skills if skills else None
        })

    if request.method == 'POST':
        flash(f"Preview ready for {len(skills_preview)} resume(s). Skills appear after Start Screening.")
    # for GET we don’t flash; just render

    return render_template(
        'screening.html',
        jobs=jobs_db,
        resumes_count=len(resumes_db),
        latest_results=list(parsed_results),
        skills_preview=skills_preview
    )

def resume_signature(path: str) -> str:
    """Stable signature to invalidate cache if file changes."""
    try:
        stat = os.stat(path)
        sig = f"{os.path.basename(path)}::{stat.st_size}::{int(stat.st_mtime)}"
    except Exception:
        sig = os.path.basename(path)
    return hashlib.md5(sig.encode("utf-8")).hexdigest()

def extract_name_locally(text: str) -> str:
    if not text: return "N/A"
    m = re.search(r"(?:^|\n)\s*Name\s*[:\-]\s*(.+)", text, flags=re.I)
    if m:
        return m.group(1).strip().splitlines()[0][:80] or "N/A"
    for line in text.splitlines()[:20]:
        s = line.strip()
        if 2 <= len(s) <= 80 and re.search(r"[A-Za-z]{2,}", s) and not re.search(r"@|resume|curriculum|vitae|profile|summary|objective", s, re.I):
            return s
    return "N/A"

def extract_skills_locally(text: str):
    if not text: return []
    t = text.strip(); low = t.lower()
    anchors = ["technical skills", "skills &", "skills:", "skills -", "skills\n", "skills"]
    start = next((low.find(a) for a in anchors if low.find(a) != -1), -1)
    window = t[start:start+1200] if start != -1 else t[:1500]
    chunks = re.split(r"[\n,;•\u2022|\t]+", window)
    cleaned, seen = [], set()
    for c in chunks:
        s = c.strip().strip("-•—")
        if 1 < len(s) <= 40 and not s.lower().startswith(("experience","education","project","summary","certification","role","responsibilit","work history")):
            s = re.sub(r"\s+", " ", s)
            if re.search(r"[A-Za-z0-9]", s):
                k = s.lower()
                if k not in seen:
                    seen.add(k); cleaned.append(s)
    return cleaned[:50]


def extract_text_from_resume(path):
    if path.lower().endswith(".pdf"):
        try:
            reader = PdfReader(path)
            return "\n".join(page.extract_text() or '' for page in reader.pages)[:2000]
        except:
            return ""
    elif path.lower().endswith(".docx"):
        try:
            doc = docx.Document(path)
            return "\n".join(p.text for p in doc.paragraphs)[:2000]
        except:
            return ""
    elif path.lower().endswith(".txt"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()[:2000]
        except:
            return ""
    return ""

def normalize_skill(s: str) -> str:
    s = s.lower().strip()
    aliases = {"js":"javascript","node":"node.js","nodejs":"node.js","reactjs":"react","py":"python",
               "mysql":"sql","postgresql":"postgres","postgre sql":"postgres","ms sql":"sql"}
    return aliases.get(s, s)

def compute_score(required_csv: str, cand_skills: list[str]) -> tuple[int, list[str]]:
    req = [normalize_skill(x) for x in [r.strip() for r in (required_csv or "").split(",")] if x.strip()]
    cand = [normalize_skill(x) for x in cand_skills if isinstance(x, str) and x.strip()]
    if not req: return (0, [])
    matched = sorted(set(cand) & set(req))
    score = int(round((len(matched) / len(req)) * 100))
    return score, matched

@app.route('/parse_resumes', methods=['POST'])
@jwt_required(optional=True)
def parse_resumes():
    if session.get('role') != 'hr':
        return "Unauthorized", 403

    parsed_results.clear()

    for rec in resumes_db:
        path = os.path.join(app.config['UPLOAD_FOLDER'], rec['filename'])
        text = extract_text_from_resume(path)
        if not text.strip():
            print(f"[PARSE][WARN] Empty text for {rec['filename']}")
            continue

        sig = resume_signature(path)

        # --- NAME: use local only (no Gemini to save quota) ---
        name = name_cache.get(sig)
        if name is None:
            name = extract_name_locally(text)
            name_cache[sig] = name

        # --- SKILLS: if not cached, call Gemini ONCE here ---
        skills = skills_cache.get(sig)
        if skills is None:
            skills = parse_skills_with_gemini(text)  # <- single API call here
            # If Gemini still returns nothing, fall back to local so score isn’t empty
            if not skills:
                skills = extract_skills_locally(text)
            skills_cache[sig] = skills

        # --- SCORE vs job requirements ---
        job     = next((j for j in jobs_db if j['title'] == rec['job_title']), None)
        req_csv = job['requirements'] if job else ""
        score, matched = compute_score(req_csv, skills)

        parsed_results.append({
            "filename": rec['filename'],
            "job_title": rec['job_title'],
            "name": name or "N/A",
            "skills": skills,              # full extracted skills (Gemini result if available)
            "matched_skills": matched,     # intersection (for future column if needed)
            "score": score,                # 0..100
            "status": "Pending"            # HR sets manually
        })

        print(f"[PARSE] file={rec['filename']} name='{name}' score={score} skills={skills[:8]}...")

    # Sort desc by score for table
    parsed_results.sort(key=lambda x: x['score'], reverse=True)

    flash("Screening complete. Scores computed and skills stored.")
    return redirect(url_for('screening'))


# -------- Files --------
@app.route('/uploads/resumes/<filename>')
def download_resume(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# -------- Analysis Dashboard --------
@app.route('/analysis_dashboard', methods=['GET'])
@jwt_required(optional=True)
def analysis_dashboard():
    if session.get('role') != 'hr':
        return "Unauthorized", 403

    # All job titles for the dropdown
    job_titles = [j['title'] for j in jobs_db]
    selected_job = request.args.get('job')  # may be None or a job name

    # Filter parsed results by selected_job (if provided)
    if selected_job:
        parsed = [r for r in parsed_results if r['job_title'] == selected_job]
        apps_for_job = [a for a in user_applications if a['job_title'] == selected_job]
    else:
        parsed = list(parsed_results)
        apps_for_job = list(user_applications)

    # KPI: total applicants (from applications, not parsed list)
    total_applicants = len(apps_for_job)

    # KPI: selected / rejected from parsed
    selected_count = sum(1 for r in parsed if (r.get('status') or '').lower() == 'selected')
    rejected_count = sum(1 for r in parsed if (r.get('status') or '').lower() in ('rejected', 'not selected'))

    # Gender counts from applications (what users entered)
    gender_counts = Counter(a.get('gender', 'Unknown') or 'Unknown' for a in apps_for_job)

    # Rank distribution (1–10) from score (0–100)
    # Bin rule: 1 for 0–10, 2 for 11–20, ..., 10 for 91–100
    rank_bins = [0] * 10
    for r in parsed:
        s = max(0, min(100, int(r.get('score', 0))))
        bucket = max(1, min(10, math.ceil(s / 10.0)))
        rank_bins[bucket - 1] += 1

    return render_template(
        'analysis.html',
        job_titles=job_titles,
        selected_job=selected_job,
        total_applicants=total_applicants,
        selected_count=selected_count,
        rejected_count=rejected_count,
        gender_counts=dict(gender_counts),     # => { "Male": x, "Female": y, ... }
        rank_bins=rank_bins                    # list of 10 ints
    )

@app.route('/user_dashboard')
@jwt_required(optional=True)
def user_dashboard():
    # accept session OR JWT (and backfill session if JWT present)
    role = session.get('role')
    email = session.get('email')
    if not role:
        claims = get_jwt() or {}
        role = claims.get('role')
        if role:
            session['role'] = role
            email = email or get_jwt_identity()
            if email:
                session['email'] = email

    if role != 'user':
        return redirect(url_for('login'))

    user_email = session.get('email') or get_jwt_identity()

    # --- jobs source: use full job dicts so template can access salary/last_date/requirements
    jobs_src = list(jobs_db) if 'jobs_db' in globals() else []
    app.logger.info(f"User dash: jobs available = {len(jobs_src)}")

    # existing panels
    user_apps = [a for a in globals().get('user_applications', []) if a.get('email') == user_email]
    user_notifications = [
        n.get('message') for n in globals().get('notifications', [])
        if n.get('target') in ('all', user_email)
    ]

    return render_template(
        'user_dashboard.html',
        jobs=jobs_src,                 # <— send full objects, not just titles
        applications=user_apps,
        notifications=user_notifications
    )

@app.route('/apply_job', methods=['POST'])
@jwt_required(optional=True)
def apply_job():
    if session.get('role') != 'user':
        return "Unauthorized", 403

    email = session.get('email')

    # Get fields safely
    job_title = request.form.get('job_title')
    name = request.form.get('name')
    mobile = request.form.get('mobile')
    gender = request.form.get('gender')
    education = request.form.get('education')
    address = request.form.get('address')
    file = request.files.get('resume')

    # Basic validation
    missing = [k for k, v in {
        "Job": job_title,
        "Full name": name,
        "Mobile": mobile,
        "Gender": gender,
        "Education": education,
        "Address": address,
        "Resume file": file and file.filename
    }.items() if not v]

    if missing:
        flash("Please fill all fields: " + ", ".join(missing))
        return redirect(url_for('user_dashboard'))

    # Save resume
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    # Record application details for HR view
    user_applications.append({
        "email": email,
        "job_title": job_title,
        "name": name,
        "mobile": mobile,
        "gender": gender,
        "education": education,
        "address": address,
        "resume_file": filename
    })

    # Also add to resumes_db so HR can parse this resume for this job
    resumes_db.append({"filename": filename, "job_title": job_title})

    flash("Application submitted successfully.")
    return redirect(url_for('user_dashboard'))

@app.route('/recommend_jobs')
@jwt_required(optional=True)
def recommend_jobs():
    if session.get('role') != 'user':
        return "Unauthorized", 403
    email = session.get('email')
    user_resume = next((a['resume_file'] for a in user_applications[::-1] if a['email'] == email), None)
    if not user_resume:
        flash("Please apply to a job with your resume first.")
        return redirect(url_for('user_dashboard'))

    resume_path = os.path.join(app.config['UPLOAD_FOLDER'], user_resume)
    try:
        with open(resume_path, 'r', encoding='utf-8', errors='ignore') as f:
            resume_text = f.read()
    except:
        try:
            with open(resume_path, 'rb') as f:
                resume_text = f.read().decode('utf-8', errors='ignore')
        except:
            resume_text = ""

    job_snippets = "\n\n".join([
        f"Title: {job['title']}\nDescription: {job['description']}\nRequirements: {job['requirements']}"
        for job in jobs_db
    ])
    prompt = f"""
    Based on the following resume, recommend top 3 most suitable job roles from the list below:

    Resume:
    {resume_text}

    Job Descriptions:
    {job_snippets}

    Output in JSON format with fields: title, match_reason
    """
    try:
        model = genai.GenerativeModel("models/gemini-pro")
        response = model.generate_content(prompt)
        recommendations = json.loads(response.text)
    except Exception as e:
        flash("Recommendation failed. Please try again.")
        print("Error during recommendation:", str(e))
        recommendations = []

    user_email = session.get('email')
    user_apps = [a for a in user_applications if a['email'] == user_email]
    user_notifications = [n['message'] for n in notifications if n['target'] == 'all' or n['target'] == user_email]
    return render_template('user_dashboard.html', jobs=jobs_db, applications=user_apps, notifications=user_notifications, recommendations=recommendations)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
