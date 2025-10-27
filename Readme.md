# 📄 RecruitMate – AI-Powered Resume Screening & Job Matching System

RecruitMate is an **AI-driven recruitment automation system** built with **Flask** that enables HR teams to post jobs, upload candidate resumes, and automatically **parse, analyze, and rank** them based on the job’s requirements.  
The system uses **Google Gemini API** for NLP-powered resume parsing and skill extraction, allowing recruiters to focus on the best candidates while ensuring fairness and efficiency.

---

## 🚀 Features

### 👥 Authentication & Role-Based Login
- Secure **JWT-based** authentication
- **Google OAuth** login integration
- Separate dashboards for **HR** and **Job Seekers**

### 🏢 HR Dashboard
- **Post jobs** with title, description, skill requirements, salary, and application deadline
- **Upload multiple resumes** (PDF/DOCX) for screening
- **Screen resumes**: Gemini extracts skills → system scores candidates based on skill match
- **Manual Select/Reject/Pending** status updates with automatic **candidate notifications**
- View all applicants grouped **by job**
- Link to **Analysis Dashboard**

### 🔍 Screening & Parsing
- Gemini API extracts **only skills** from resumes
- Compares against job’s required skills (comma-separated)
- Generates **matching score** (0–100)
- **Row color coding** in results table:
  - ✅ Green: score ≥ 70
  - 🟠 Orange: 31–69
  - 🔴 Red: ≤ 30
- Caches extracted skills to avoid repeated API calls and reduce quota usage
- Displays stored skills in **Raw Skills Preview** (no extra API calls)

### 📊 Analysis Dashboard
- KPIs: Total applicants, selected, rejected
- Charts:
  - **Pie**: Selected vs Not Selected
  - **Bar**: Gender breakdown
  - **Bar**: Rank distribution (1–10)
- Job filter for focused analysis

### 👤 Job Seeker Dashboard
- View available jobs
- Apply to jobs with personal details & resume upload
- See **application status** and **HR notifications**
- **Recommended jobs** based on resume content (Gemini LLM)

### 📢 Notifications
- HR can broadcast announcements to all job seekers
- Job seekers receive:
  - Status updates
  - New job posting alerts

---

## 🗂 Project Structure

RecruitMate/
├── app/ # (future blueprints)
│ ├── auth/
│ ├── hr_dashboard/
│ ├── user_dashboard/
│ ├── resume_parser/
│ ├── job_matcher/
│ ├── analysis/
│ └── notifications/
├── uploads/resumes/ # stored resumes
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── hr_dashboard.html
│ ├── user_dashboard.html
│ ├── screening.html
│ └── analysis.html
├── static/ # css/js/images
├── main.py # main Flask app
├── requirements.txt
└── README.md


---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/recruitmate.git
cd recruitmate

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

pip install -r requirements.txt



python main.py

Open browser → http://127.0.0.1:5000

🛠 Technology Stack
Backend: Flask, Flask-JWT-Extended, Flask-Dance (Google OAuth)

NLP: Google Gemini API

Resume Reading: PyPDF2, python-docx

Database: In-memory (can be extended to SQLite/PostgreSQL)

Frontend: HTML, CSS, Chart.js

Auth: JWT + Google OAuth

File Uploads: Flask-Uploads

📌 Usage Flow
HR Side

Log in → Post a job

Upload candidate resumes for that job

Click Start Screening:

Gemini extracts skills

Match % calculated vs job requirements

Candidates sorted by score

Set status (Selected / Rejected / Pending) → Notifies candidate

View analytics in Analysis Dashboard

Job Seeker Side

Log in → View available jobs

Apply with personal details + resume

View application status & notifications

Get job recommendations

📉 API Usage Optimization
Preview Skills: no Gemini calls (local display from cache)

Start Screening: 1 Gemini call per resume (cached results)

Skills & name stored → Re-screening = no extra API usage

📷 Screenshots
(Add UI screenshots for HR Dashboard, Screening, Analysis, Job Seeker Dashboard)


👩‍💻 Author & Acknowledgements
Project implemented as part of MCA Department coursework.
NLP parsing powered by Google Gemini API.
Guided by Mr. Yashwanth Reddy V, Assistant Professor


---

Do you want me to also include **step-by-step example test cases** in the README so HR and Job Seeker flows can be verified quickly after setup? That would make QA and demos smoother.
