import sqlite3
from app import DATABASE, init_db


def create_driver():
    init_db()

    print("\n===== LogiRoute Driver Setup =====\n")

    name = input("Enter driver name: ").strip()
    phone = input("Enter driver phone: ").strip()
    license_number = input("Enter license number: ").strip().upper()
    license_category = input("Enter license category: ").strip()
    current_location = input("Enter current location: ").strip()

    if not all([name, phone, license_number, license_category, current_location]):
        print("Error: Please fill in all details.")
        return

    try:
        with sqlite3.connect(DATABASE) as db:
            db.execute("""
                INSERT INTO drivers (
                    name, phone, license_number,
                    license_category, current_location, status
                )
                VALUES (?, ?, ?, ?, ?, 'Available')
            """, (
                name, phone, license_number,
                license_category, current_location
            ))

        print("\nDriver added successfully!")
        print("Status: Available")

    except sqlite3.IntegrityError:
        print("Error: This license number already exists.")

    except sqlite3.Error as error:
        print("Database error:", error)


if __name__ == "__main__":
    create_driver()