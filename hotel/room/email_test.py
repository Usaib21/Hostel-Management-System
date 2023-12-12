# import smtplib
# from email.mime.text import MIMEText

# # Replace these with your email server settings
# EMAIL_HOST = 'smtp.gmail.com'
# EMAIL_PORT = 587
# EMAIL_HOST_USER = 'peerusaib111@gmail.com'
# EMAIL_HOST_PASSWORD = 'hostel777'
# EMAIL_TO = 'peerusaib16@gmail.com'

# # Create a plain text email message
# msg = MIMEText('This is a test email.')
# msg['Subject'] = 'Test Email'
# msg['From'] = EMAIL_HOST_USER
# msg['To'] = EMAIL_TO

# # Try to send the email
# try:
#     with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
#         server.starttls()
#         server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
#         server.sendmail(EMAIL_HOST_USER, EMAIL_TO, msg.as_string())
#     print('Email sent successfully.')
# except Exception as e:
#     print(f'Error sending email: {e}')
