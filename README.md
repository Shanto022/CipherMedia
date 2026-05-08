# CipherMedia — A Secure Social Media Platform

A cryptographically secure social media web application built with Django for CSE447: Cryptography and Cryptanalysis (Spring 2026, BRAC University).

## Environment Requirements
- Python 3.11+
- Django 4.x
- SQLite (built-in, no setup needed)
- All dependencies in `requirements.txt`

## Setup Instructions

### 1. Clone the Repository
git clone https://github.com/Shanto022/CipherMedia.git
cd CipherMedia

### 2. Create Virtual Environment
python -m venv venv
venv\Scripts\activate

### 3. Install Dependencies
pip install -r requirements.txt

### 4. Configure Environment Variables
Create a .env file in the root directory and add:
SECRET_KEY=your_django_secret_key
SERVER_PRIVATE_KEY=your_server_private_key
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_email_app_password

### 5. Apply Migrations
python manage.py migrate

## How to Run Locally
python manage.py runserver

Access the app at: http://127.0.0.1:8000
Admin panel at: http://127.0.0.1:8000/admin

## Project Structure
- secureapp/ — Main application (views, models, crypto modules)
- ciphermedia/ — Django project settings
- templates/ — HTML templates
- db.sqlite3 — SQLite database
- requirements.txt — Python dependencies
