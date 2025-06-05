import smtplib
import random
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def generate_temporary_token():
    token_value = str(random.randint(10000, 99999))  
    timestamp = int(time.time())  
    return f"{token_value}:{timestamp}"

def verify_token(token, max_age=60):
    try:
        token_parts = token.split(':')
        if len(token_parts) != 2:
            return False  

        token_value, timestamp = token_parts
        timestamp = int(timestamp)
        current_time = int(time.time())

        if current_time - timestamp > max_age:
            return False

        return True
    except Exception as e:
        print(f"Token verification error: {e}")
        return False

def send_verification_token(user_email):
    token = generate_temporary_token()

    msg = MIMEMultipart()
    msg['From'] = "officialaccmanager1@gmail.com"
    msg['To'] = user_email.strip()
    msg['Subject'] = "Verification Code for Password Manager"
    body = f"""
    <html>
    <body>
        <p>Your verification code is: <strong>{token}</strong></p>
    </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html', 'utf-8'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login("officialaccmanager1@gmail.com", "ioqe yner dswx xlqc")
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        print("Verification token sent successfully")
        return token  
    except smtplib.SMTPException as e:
        print(f"Failed to send email: {e}")
        return None
