import os
from flask import Flask, redirect, url_for, session, request, render_template
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import pandas as pd
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import base64
import logging

app = Flask(__name__)

# Load secrets from environment variables for security
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID', '974601258161-23cheuut49o1k0va6tf3l9lqh9dust30.apps.googleusercontent.com')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET', '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')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Google OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={
        'scope': 'openid profile email https://www.googleapis.com/auth/gmail.send'
    },
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    session.pop('google_token', None)  
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/authorized')
def authorized():
    token = google.authorize_access_token()
    if not token:
        return 'Access denied.'
    
    session['google_token'] = token
    resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
    if resp.status_code != 200:
        logging.error(f"Failed to fetch user info: {resp.text}")
        return 'Failed to login.'
    
    user_info = resp.json()
    session['email'] = user_info.get('email')
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        excel_file = request.files['excel']
        greeting_message = request.form['greeting']
        body_content = request.form['body']
        
        if not excel_file or not excel_file.filename.endswith('.xlsx'):
            return 'Invalid file. Please upload an Excel file.'

        df = pd.read_excel(excel_file)
        
        for index, row in df.iterrows():
            try:
                name = row['Name']
                email = row['Email']
                certificate = row['Certificate']
                send_email(email, greeting_message, body_content, certificate)
            except Exception as e:
                logging.error(f"Erroe sending email to {row['Email']}: {e}")
            
        return 'Certificates sent successfully!'

    return render_template('dashboard.html', user_email=session['email'])

def send_email(recipient_email, greeting, body, certificate):
    try:
        creds = get_gmail_creds()
        if not creds:
            raise RuntimeError("Failed to get Gmail API credentials.")

        service = build('gmail', 'v1', credentials=creds)

        message = MIMEMultipart()
        message['to'] = recipient_email
        message['subject'] = "Your Certificate"
        message.attach(MIMEText(f"{greeting}\n\n{body}", 'plain'))
        
        if not os.path.exists(certificate):
            logging.error(f"Certificate file does not exist: {certificate}")
            return
    
        with open(certificate, "rb") as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(certificate)}')
            message.attach(part)


        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        send_message = {'raw': raw_message}

        service.users().messages().send(userId='me', body=send_message).execute()

    except Exception as e:
        logging.error(f"Error during email sending: {e}")
        raise RuntimeError(f"Failed to send email: {str(e)}")

# Function to get Gmail API credentials
def get_gmail_creds():
    if 'google_token' in session:
        token = session['google_token']
        creds = Credentials(
            token=token['access_token'],
            refresh_token=token.get('refresh_token'),
            token_uri='https://accounts.google.com/o/oauth2/token',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET']
        )
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            session['google_token']['access_token'] = creds.token
        return creds
    return None

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)
