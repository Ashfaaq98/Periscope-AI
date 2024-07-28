import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Configure logging
logging.basicConfig(filename='/app/data2/alert.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def send_email(subject, body):
    # Email configuration
    sender_email = ''
    receiver_email = ''
    smtp_server = ''
    smtp_port = 587
    smtp_username = ''
    smtp_password = ''

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Establish a connection to the SMTP server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

def mainalert(anomalies,threshold,uc):
   
    if anomalies > threshold:
        
        # Log alert
        alert_message = f"ALERT: Number of anomalies ({anomalies}) exceeds 25% of unique connections ({uc})."
        logging.error("Alert! An Abnormal Activity is detected.")
        print(alert_message)
     
        # Send an email
        subject = "Alert !! An Intrusion is detected"
        body = f"ALERT: Number of anomalies ({anomalies}) exceeds 25% of unique connections ({uc}).Please check."
        
    else:
        print("No alert triggered.")
