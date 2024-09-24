import logging
import os
from authlib.jose import JsonWebKey
from flask import Flask, jsonify, redirect, url_for, session, request, render_template
from authlib.integrations.flask_client import OAuth
import pandas as pd
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import base64

import requests

app = Flask(__name__)

# Load secrets from environment variables for security
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID', '974601258161-23cheuut49o1k0va6tf3l9lqh9dust30.apps.googleusercontent.com')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET', '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')

oauth = OAuth(app)

# Gmail API SCOPES
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Google OAuth configuration
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/login/authorized',
    client_kwargs={
        'scope': 'openid profile email https://www.googleapis.com/auth/gmail.send'
    },
)

ALLOWED_EXCEL_EXTENSIONS = {'xlsx', 'xls'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ALLOWED_FONT_EXTENSIONS = {'ttf', 'otf'}
FONT_DIR = os.path.join(os.getcwd(), 'fonts')

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def fetch_jwk_set():
    response = requests.get('https://www.googleapis.com/oauth2/v3/certs')
    return response.json()

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle Google OAuth login
@app.route('/login')
def login():
    session.pop('google_token', None)  # Clear the token to force re-authorization
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/authorized')
def authorized():
    token = google.authorize_access_token()
    if not token:
        return 'Access denied.'
    
    session['google_token'] = token
    resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
    user_info = resp.json()

    print(user_info)  # Debugging: print user info to check for email

    # if 'email' not in user_info:
    #     return 'Email not available or permission not granted.'

    session['email'] = user_info['email']
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        excel_file = request.files['excel']
        certificate_template = request.files['certificate']
        font_file = request.files.get('font')
        font_size = int(request.form['fontsize'])
        greeting_message = request.form['greeting']
        body_content = request.form['body']

        certificate_path = os.path.join("uploads", "certificate_template.png")
        certificate_template.save(certificate_path)

        if font_file and allowed_file(font_file.filename, ALLOWED_FONT_EXTENSIONS):
            font_path = os.path.join("fonts", font_file.filename)
            font_file.save(font_path)
        else:
            font_path = None

        df = pd.read_excel(excel_file)

        for index, row in df.iterrows():
            name = row['Name']
            email = row['Email']

            img = Image.open(certificate_path)
            draw = ImageDraw.Draw(img)

            try:
                if font_path:
                    font = ImageFont.truetype(font_path, font_size)
                else:
                    font = ImageFont.truetype("arial.ttf", font_size)  # Use a default system font
            except Exception as e:
                print(f"Error loading font: {e}")
                font = ImageFont.load_default()

            underline_position = detect_underline(certificate_path)
            if underline_position:
                name_position = (underline_position[0], underline_position[1] - font_size)
            else:
                name_position = (img.width // 2, img.height // 2)

            text_width, text_height = draw.textsize(name, font=font)
            centered_position = (name_position[0] - text_width // 2, name_position[1])

            draw.text(centered_position, name, font=font, fill=(0, 0, 0))

            output_path = f"certificates/{name}_certificate.png"
            img.save(output_path)

            send_email(email, greeting_message, body_content, output_path)

        return 'Certificates generated and sent successfully!'
    
    return render_template('dashboard.html', user_email=session['email'])

def detect_underline(certificate_path):
    certificate_img = cv2.imread(certificate_path)
    gray = cv2.cvtColor(certificate_img, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 50, 150, apertureSize=3)
    lines = cv2.HoughLinesP(edges, 1, np.pi / 180, threshold=100, minLineLength=100, maxLineGap=10)

    midpoints = []
    
    if lines is not None:
        for line in lines:
            for x1, y1, x2, y2 in line:
                if abs(y2 - y1) < 5:  
                    mid_x = (x1 + x2) // 2
                    mid_y = (y1 + y2) // 2
                    midpoints.append((mid_x, mid_y))
    
    if midpoints:
        avg_x = sum(x for x, y in midpoints) // len(midpoints)
        avg_y = sum(y for x, y in midpoints) // len(midpoints)
        return (avg_x, avg_y)
    
    return None

# Function to send email using Gmail API with better error handling
def send_email(recipient_email, greeting, body, certificate_path):
    try:
        creds = get_gmail_creds()
        if not creds:
            raise RuntimeError("Failed to get Gmail API credentials.")

        service = build('gmail', 'v1', credentials=creds)

        message = MIMEMultipart()
        message['to'] = recipient_email
        message['subject'] = "Your Certificate"
        message.attach(MIMEText(f"{greeting}\n\n{body}", 'plain'))

        # Attach certificate
        with open(certificate_path, "rb") as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(certificate_path)}')
            message.attach(part)

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        send_message = {'raw': raw_message}

        # Attempt to send the email
        service.users().messages().send(userId='me', body=send_message).execute()

    except Exception as e:
        logging.error(f"Error during email sending: {e}")
        raise RuntimeError(f"Failed to send email: {str(e)}")

# Function to get Gmail API credentials
def get_gmail_creds():
    creds = None
    if 'google_token' in session:
        creds = Credentials(session['google_token']['access_token'], None, SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
    return creds

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('google_token', None)
    session.pop('email', None)
    return redirect(url_for('index'))

@app.route('/api/font-list', methods=['GET'])
def get_font_list():
    try:
        fonts = [font for font in os.listdir('fonts'   +) if font.endswith(('.ttf', '.otf'))]
        return jsonify(fonts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

if __name__ == "__main__":
    if not os.path.exists('certificates'):
        os.makedirs('certificates')
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    if not os.path.exists('fonts'):
        os.makedirs('fonts')
    app.run(debug=True)
