import os
import smtplib

from email.message import EmailMessage


def send_reset_email(to_email, recipient_name, reset_url):
    """
    Send a password-reset email to an admin or company user.

    Required environment variables:
        MAIL_SERVER
        MAIL_PORT
        MAIL_USERNAME
        MAIL_PASSWORD
        MAIL_FROM
    """

    # SMTP configuration
    smtp_server = os.environ.get(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    smtp_port = int(
        os.environ.get("MAIL_PORT", "587")
    )

    sender_email = os.environ.get(
        "MAIL_FROM",
        os.environ.get("MAIL_USERNAME", "")
    )

    sender_password = os.environ.get(
        "MAIL_PASSWORD",
        ""
    )

    # Check email configuration
    if not sender_email or not sender_password:
        raise RuntimeError(
            "Email is not configured. "
            "Set MAIL_USERNAME, MAIL_PASSWORD, and MAIL_FROM."
        )

    # Create email
    message = EmailMessage()

    message["Subject"] = "LogiRoute - Password Reset"
    message["From"] = sender_email
    message["To"] = to_email

    # Plain-text email content
    message.set_content(
        f"""
Hello {recipient_name},

We received a request to reset your LogiRoute password.

Click the link below to create a new password:

{reset_url}

Important:
- This link expires in 30 minutes.
- The link can only be used once.
- If you did not request a password reset, ignore this email.

Regards,
LogiRoute Support Team
"""
    )

    # Send email using SMTP
    with smtplib.SMTP(
        smtp_server,
        smtp_port,
        timeout=20
    ) as server:

        server.ehlo()
        server.starttls()
        server.ehlo()

        server.login(
            os.environ.get("MAIL_USERNAME", ""),
            sender_password
        )

        server.send_message(message)

    print(f"Password-reset email sent to {to_email}")