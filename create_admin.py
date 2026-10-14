import sqlite3
import getpass

from werkzeug.security import generate_password_hash
from app import DATABASE, init_db


def create_admin():

    # Create database tables if they do not exist
    init_db()

    print("\n===== LogiRoute Admin Account Setup =====\n")

    # Get admin details
    name = input("Enter admin name: ").strip()
    email = input("Enter admin email: ").strip().lower()

    password = getpass.getpass(
        "Enter admin password (minimum 8 characters): "
    )

    confirm_password = getpass.getpass(
        "Confirm admin password: "
    )

    # Validate input
    if not name or not email:
        print("Error: Name and email are required.")
        return

    if len(password) < 8:
        print("Error: Password must contain at least 8 characters.")
        return

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    # Hash the password for security
    password_hash = generate_password_hash(password)

    try:
        with sqlite3.connect(DATABASE) as db:

            db.execute("""
                INSERT INTO accounts (
                    name,
                    email,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?, 'admin')
            """, (
                name,
                email,
                password_hash
            ))

        print("\nAdmin account created successfully!")
        print("Admin email:", email)
        print("You can now log in through the Admin Login page.")

    except sqlite3.IntegrityError:
        print("\nError: This email already exists in the database.")

    except sqlite3.Error as error:
        print("\nDatabase error:", error)


if __name__ == "__main__":
    create_admin()