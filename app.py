import os
import sqlite3
import secrets
import hashlib
import math
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from mail import send_reset_email

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY", "change-this-secret-before-deployment"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)


def get_db():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS delivery_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                pickup_address TEXT NOT NULL,
                delivery_address TEXT NOT NULL,
                goods_description TEXT NOT NULL,
                requested_date TEXT,
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            )
        """)

        existing_columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(delivery_requests)").fetchall()
        }
        new_columns = {
            "weight_kg": "REAL NOT NULL DEFAULT 0",
            "volume_m3": "REAL NOT NULL DEFAULT 0",
            "priority": "TEXT NOT NULL DEFAULT 'Normal'",
            "assigned_vehicle_id": "INTEGER",
            "assigned_driver_id": "INTEGER",
            "warehouse_id": "INTEGER",
            "estimated_distance_km": "REAL",
            "estimated_duration_minutes": "INTEGER",
            "delivery_deadline": "TEXT",
            "rejection_reason": "TEXT",
        }
        for column_name, column_definition in new_columns.items():
            if column_name not in existing_columns:
                db.execute(
                    f"ALTER TABLE delivery_requests ADD COLUMN "
                    f"{column_name} {column_definition}"
                )

        db.execute("""
            CREATE TABLE IF NOT EXISTS vehicles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registration_number TEXT NOT NULL UNIQUE COLLATE NOCASE,
                vehicle_type TEXT NOT NULL,
                weight_capacity_kg REAL NOT NULL CHECK(weight_capacity_kg > 0),
                volume_capacity_m3 REAL NOT NULL CHECK(volume_capacity_m3 > 0),
                current_location TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available'
                    CHECK(status IN ('Available', 'Assigned', 'In Transit', 'Under Maintenance')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS drivers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                license_number TEXT NOT NULL UNIQUE COLLATE NOCASE,
                license_category TEXT NOT NULL,
                current_location TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available'
                    CHECK(status IN ('Available', 'Assigned', 'On Delivery', 'Off Duty')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS warehouses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                city TEXT NOT NULL,
                capacity_m3 REAL NOT NULL DEFAULT 0 CHECK(capacity_m3 >= 0),
                status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active', 'Inactive')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_delivery_account ON delivery_requests(account_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_delivery_status ON delivery_requests(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_vehicle_status ON vehicles(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_driver_status ON drivers(status)")

    print("LogiRoute database initialized successfully!")


def login_required(role=None):
    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            if "account_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("landing"))
            if role and session.get("role") != role:
                abort(403)
            return view_function(*args, **kwargs)
        return wrapper
    return decorator


@app.route("/")
def landing():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "user":
        return redirect(url_for("user_dashboard"))
    return render_template("landing.html")


@app.route("/company")
def user_entry():
    return render_template("user_entry.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            account = db.execute(
                "SELECT * FROM accounts WHERE email = ? AND role = 'admin'",
                (email,),
            ).fetchone()

        if account and check_password_hash(account["password_hash"], password):
            session.clear()
            session.permanent = True
            session["account_id"] = account["id"]
            session["name"] = account["name"]
            session["email"] = account["email"]
            session["role"] = "admin"
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin email or password.", "error")

    return render_template("login.html", role="admin", title="Admin Login")


@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            account = db.execute(
                "SELECT * FROM accounts WHERE email = ? AND role = 'user'",
                (email,),
            ).fetchone()

        if account and check_password_hash(account["password_hash"], password):
            session.clear()
            session.permanent = True
            session["account_id"] = account["id"]
            session["name"] = account["name"]
            session["email"] = account["email"]
            session["role"] = "user"
            flash("Login successful.", "success")
            return redirect(url_for("user_dashboard"))

        flash(
            "Invalid email or password. Please register if you do not have an account.",
            "error",
        )

    return render_template("login.html", role="user", title="Company Login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("Please fill in all required fields.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            try:
                with get_db() as db:
                    db.execute(
                        """INSERT INTO accounts (name, email, password_hash, role)
                           VALUES (?, ?, ?, 'user')""",
                        (name, email, generate_password_hash(password)),
                    )
                flash(
                    "Company account created successfully. You can now log in.",
                    "success",
                )
                return redirect(url_for("user_login"))
            except sqlite3.IntegrityError:
                flash("An account with this email already exists.", "error")

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    role = request.args.get("role", "user").lower()
    if role not in ("admin", "user"):
        role = "user"

    if request.method == "POST":
        role = request.form.get("role", "user").lower()
        if role not in ("admin", "user"):
            role = "user"
        email = request.form.get("email", "").strip().lower()

        with get_db() as db:
            account = db.execute(
                "SELECT * FROM accounts WHERE email = ? AND role = ?",
                (email, role),
            ).fetchone()

            if account:
                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(minutes=30)
                ).isoformat()
                db.execute(
                    """INSERT INTO password_resets
                       (account_id, token_hash, expires_at) VALUES (?, ?, ?)""",
                    (account["id"], token_hash, expires_at),
                )
                reset_link = url_for("reset_password", token=raw_token, _external=True)
                try:
                    send_reset_email(account["email"], account["name"], reset_link)
                except Exception:
                    app.logger.exception("Password-reset email could not be sent.")

        flash(
            "If the email matches an account, a password-reset link will be sent shortly.",
            "success",
        )
        return redirect(url_for("forgot_password", role=role))

    return render_template("forgot_password.html", role=role)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    with get_db() as db:
        reset_record = db.execute("""
            SELECT pr.id AS reset_id, pr.account_id, pr.expires_at, pr.used, a.role
            FROM password_resets pr
            JOIN accounts a ON a.id = pr.account_id
            WHERE pr.token_hash = ?
        """, (token_hash,)).fetchone()

    valid = False
    if reset_record and not reset_record["used"]:
        try:
            expiry = datetime.fromisoformat(reset_record["expires_at"])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            valid = now < expiry
        except ValueError:
            valid = False

    if not valid:
        return render_template("reset_password.html", invalid=True, token=token), 400

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            with get_db() as db:
                db.execute(
                    "UPDATE accounts SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(password), reset_record["account_id"]),
                )
                db.execute(
                    "UPDATE password_resets SET used = 1 WHERE account_id = ?",
                    (reset_record["account_id"],),
                )
            flash(
                "Password updated successfully. Please log in with your new password.",
                "success",
            )
            return redirect(
                url_for(
                    "admin_login" if reset_record["role"] == "admin" else "user_login"
                )
            )

    return render_template("reset_password.html", invalid=False, token=token)


@app.route("/admin/vehicles")
@login_required("admin")
def manage_vehicles():
    with get_db() as db:
        vehicles = db.execute("SELECT * FROM vehicles ORDER BY id DESC").fetchall()
    return render_template("admin_vehicles.html", vehicles=vehicles)


@app.route("/admin/vehicles/add", methods=["POST"])
@login_required("admin")
def add_vehicle():
    registration_number = request.form.get("registration_number", "").strip().upper()
    vehicle_type = request.form.get("vehicle_type", "").strip()
    weight_capacity = request.form.get("weight_capacity_kg", "").strip()
    volume_capacity = request.form.get("volume_capacity_m3", "").strip()
    current_location = request.form.get("current_location", "").strip()

    if not all([registration_number, vehicle_type, weight_capacity, volume_capacity, current_location]):
        flash("Please fill in all vehicle details.", "error")
        return redirect(url_for("manage_vehicles"))

    try:
        weight_capacity = float(weight_capacity)
        volume_capacity = float(volume_capacity)
        if (
            not math.isfinite(weight_capacity)
            or not math.isfinite(volume_capacity)
            or weight_capacity <= 0
            or volume_capacity <= 0
        ):
            raise ValueError
    except ValueError:
        flash("Weight and volume capacities must be positive finite numbers.", "error")
        return redirect(url_for("manage_vehicles"))

    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO vehicles (
                    registration_number, vehicle_type, weight_capacity_kg,
                    volume_capacity_m3, current_location
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                registration_number, vehicle_type, weight_capacity,
                volume_capacity, current_location
            ))
        flash("Vehicle added successfully.", "success")
    except sqlite3.IntegrityError:
        flash("This vehicle registration number already exists.", "error")

    return redirect(url_for("manage_vehicles"))


@app.route("/admin/vehicles/<int:vehicle_id>/status", methods=["POST"])
@login_required("admin")
def update_vehicle_status(vehicle_id):
    status = request.form.get("status", "")
    allowed_statuses = {"Available", "Assigned", "In Transit", "Under Maintenance"}

    if status not in allowed_statuses:
        flash("Invalid vehicle status.", "error")
        return redirect(url_for("manage_vehicles"))

    with get_db() as db:
        vehicle = db.execute(
            "SELECT id FROM vehicles WHERE id = ?", (vehicle_id,)
        ).fetchone()

        if not vehicle:
            flash("Vehicle not found.", "error")
        elif status == "Available":
            active = db.execute("""
                SELECT id FROM delivery_requests
                WHERE assigned_vehicle_id = ?
                  AND status IN ('Confirmed', 'In Transit')
                LIMIT 1
            """, (vehicle_id,)).fetchone()

            if active:
                flash(
                    "This vehicle is assigned to an active delivery and cannot be marked available.",
                    "error",
                )
            else:
                db.execute(
                    "UPDATE vehicles SET status = ? WHERE id = ?",
                    (status, vehicle_id),
                )
                flash("Vehicle status updated successfully.", "success")
        else:
            db.execute(
                "UPDATE vehicles SET status = ? WHERE id = ?",
                (status, vehicle_id),
            )
            flash("Vehicle status updated successfully.", "success")

    return redirect(url_for("manage_vehicles"))


@app.route("/admin/dashboard")
@login_required("admin")
def admin_dashboard():
    with get_db() as db:
        total_companies = db.execute(
            "SELECT COUNT(*) FROM accounts WHERE role = 'user'"
        ).fetchone()[0]
        total_requests = db.execute(
            "SELECT COUNT(*) FROM delivery_requests"
        ).fetchone()[0]
        pending = db.execute(
            "SELECT COUNT(*) FROM delivery_requests WHERE status = 'Pending'"
        ).fetchone()[0]
        in_transit = db.execute(
            "SELECT COUNT(*) FROM delivery_requests WHERE status = 'In Transit'"
        ).fetchone()[0]
        available_vehicles = db.execute(
            "SELECT COUNT(*) FROM vehicles WHERE status = 'Available'"
        ).fetchone()[0]
        available_drivers = db.execute(
            "SELECT COUNT(*) FROM drivers WHERE status = 'Available'"
        ).fetchone()[0]
        recent = db.execute("""
            SELECT d.*, a.name AS company_name, a.email AS company_email
            FROM delivery_requests d
            JOIN accounts a ON a.id = d.account_id
            ORDER BY d.id DESC LIMIT 8
        """).fetchall()

    return render_template(
        "admin_dashboard.html",
        total_companies=total_companies,
        total_requests=total_requests,
        pending=pending,
        in_transit=in_transit,
        available_vehicles=available_vehicles,
        available_drivers=available_drivers,
        recent=recent,
    )


@app.route("/admin/requests")
@login_required("admin")
def admin_requests():
    with get_db() as db:
        requests_list = db.execute("""
            SELECT d.*, a.name AS company_name, a.email AS company_email,
                   v.registration_number AS vehicle_number,
                   v.vehicle_type AS assigned_vehicle_type,
                   dr.name AS driver_name, dr.phone AS driver_phone
            FROM delivery_requests d
            JOIN accounts a ON a.id = d.account_id
            LEFT JOIN vehicles v ON v.id = d.assigned_vehicle_id
            LEFT JOIN drivers dr ON dr.id = d.assigned_driver_id
            ORDER BY d.id DESC
        """).fetchall()
        available_vehicles = db.execute("""
            SELECT * FROM vehicles
            WHERE status = 'Available'
            ORDER BY registration_number
        """).fetchall()
        available_drivers = db.execute("""
            SELECT * FROM drivers
            WHERE status = 'Available'
            ORDER BY name
        """).fetchall()

    return render_template(
        "admin_requests.html",
        requests_list=requests_list,
        available_vehicles=available_vehicles,
        available_drivers=available_drivers,
    )


@app.route("/admin/requests/<int:request_id>/accept", methods=["POST"])
@login_required("admin")
def accept_request(request_id):
    vehicle_id = request.form.get("vehicle_id", type=int)
    driver_id = request.form.get("driver_id", type=int)

    if not vehicle_id or not driver_id:
        flash("Please select both a vehicle and a driver.", "error")
        return redirect(url_for("admin_requests"))

    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        delivery = db.execute(
            "SELECT * FROM delivery_requests WHERE id = ?", (request_id,)
        ).fetchone()

        if not delivery:
            raise ValueError("Delivery request not found.")
        if delivery["status"] != "Pending":
            raise ValueError("Only pending requests can be accepted.")

        vehicle = db.execute(
            "SELECT * FROM vehicles WHERE id = ?", (vehicle_id,)
        ).fetchone()
        driver = db.execute(
            "SELECT * FROM drivers WHERE id = ?", (driver_id,)
        ).fetchone()

        if not vehicle or not driver:
            raise ValueError("Selected vehicle or driver does not exist.")
        if vehicle["status"] != "Available":
            raise ValueError("This vehicle is no longer available.")
        if driver["status"] != "Available":
            raise ValueError("This driver is no longer available.")

        weight = delivery["weight_kg"] or 0
        volume = delivery["volume_m3"] or 0
        if not math.isfinite(weight) or not math.isfinite(volume) or weight <= 0 or volume <= 0:
            raise ValueError(
                "This request has no valid goods weight or volume. "
                "Ask the company to submit valid values."
            )
        if weight > vehicle["weight_capacity_kg"]:
            raise ValueError("The selected vehicle cannot carry this goods weight.")
        if volume > vehicle["volume_capacity_m3"]:
            raise ValueError("The selected vehicle does not have enough volume capacity.")

        db.execute("""
            UPDATE delivery_requests
            SET status = 'Confirmed',
                assigned_vehicle_id = ?,
                assigned_driver_id = ?,
                rejection_reason = NULL
            WHERE id = ? AND status = 'Pending'
        """, (vehicle_id, driver_id, request_id))

        db.execute(
            "UPDATE vehicles SET status = 'Assigned' WHERE id = ? AND status = 'Available'",
            (vehicle_id,),
        )
        if db.execute("SELECT changes()").fetchone()[0] != 1:
            raise ValueError("The vehicle was assigned elsewhere. Refresh and try again.")

        db.execute(
            "UPDATE drivers SET status = 'Assigned' WHERE id = ? AND status = 'Available'",
            (driver_id,),
        )
        if db.execute("SELECT changes()").fetchone()[0] != 1:
            raise ValueError("The driver is no longer available. Refresh and try again.")

        db.commit()
        flash("Request accepted. Vehicle and driver assigned successfully.", "success")

    except ValueError as error:
        db.rollback()
        flash(str(error), "error")
    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Could not assign delivery resources.")
        flash("A database error occurred while assigning the vehicle.", "error")
    finally:
        db.close()

    return redirect(url_for("admin_requests"))


@app.route("/admin/requests/<int:request_id>/reject", methods=["POST"])
@login_required("admin")
def reject_request(request_id):
    reason = request.form.get("rejection_reason", "").strip()
    if not reason:
        flash("Please provide a reason for rejecting the request.", "error")
        return redirect(url_for("admin_requests"))

    with get_db() as db:
        delivery = db.execute(
            "SELECT id, status FROM delivery_requests WHERE id = ?",
            (request_id,),
        ).fetchone()

        if not delivery:
            flash("Delivery request not found.", "error")
        elif delivery["status"] != "Pending":
            flash("Only pending requests can be rejected.", "error")
        else:
            db.execute("""
                UPDATE delivery_requests
                SET status = 'Rejected', rejection_reason = ?
                WHERE id = ? AND status = 'Pending'
            """, (reason, request_id))
            flash("Delivery request rejected.", "success")

    return redirect(url_for("admin_requests"))


@app.route("/admin/requests/<int:request_id>/update", methods=["POST"])
@login_required("admin")
def update_request(request_id):
    status = request.form.get("status", "")
    if status not in {"In Transit", "Delivered", "Cancelled"}:
        flash("Invalid delivery status.", "error")
        return redirect(url_for("admin_requests"))

    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        delivery = db.execute(
            "SELECT * FROM delivery_requests WHERE id = ?", (request_id,)
        ).fetchone()

        if not delivery:
            raise ValueError("Delivery request not found.")
        if delivery["status"] not in {"Confirmed", "In Transit"}:
            raise ValueError(
                "Only confirmed or in-transit deliveries can be updated."
            )

        vehicle_id = delivery["assigned_vehicle_id"]
        driver_id = delivery["assigned_driver_id"]
        if not vehicle_id or not driver_id:
            raise ValueError("This delivery has no assigned vehicle and driver.")

        if status == "In Transit":
            db.execute(
                "UPDATE vehicles SET status = 'In Transit' WHERE id = ? AND status = 'Assigned'",
                (vehicle_id,),
            )
            db.execute(
                "UPDATE drivers SET status = 'On Delivery' WHERE id = ? AND status = 'Assigned'",
                (driver_id,),
            )
        else:
            db.execute(
                """UPDATE vehicles SET status = 'Available'
                   WHERE id = ? AND status IN ('Assigned', 'In Transit')""",
                (vehicle_id,),
            )
            db.execute(
                """UPDATE drivers SET status = 'Available'
                   WHERE id = ? AND status IN ('Assigned', 'On Delivery')""",
                (driver_id,),
            )

        db.execute(
            "UPDATE delivery_requests SET status = ? WHERE id = ?",
            (status, request_id),
        )
        db.commit()
        flash(f"Delivery status updated to {status}.", "success")

    except ValueError as error:
        db.rollback()
        flash(str(error), "error")
    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Could not update delivery status.")
        flash("A database error occurred while updating the delivery.", "error")
    finally:
        db.close()

    return redirect(url_for("admin_requests"))


@app.route("/user/dashboard")
@login_required("user")
def user_dashboard():
    account_id = session["account_id"]

    with get_db() as db:
        recent = db.execute(
            """SELECT * FROM delivery_requests
               WHERE account_id = ? ORDER BY id DESC LIMIT 6""",
            (account_id,),
        ).fetchall()
        total = db.execute(
            "SELECT COUNT(*) FROM delivery_requests WHERE account_id = ?",
            (account_id,),
        ).fetchone()[0]
        active = db.execute("""
            SELECT COUNT(*) FROM delivery_requests
            WHERE account_id = ?
              AND status IN ('Pending', 'Confirmed', 'In Transit')
        """, (account_id,)).fetchone()[0]
        delivered = db.execute("""
            SELECT COUNT(*) FROM delivery_requests
            WHERE account_id = ? AND status = 'Delivered'
        """, (account_id,)).fetchone()[0]

    return render_template(
        "user_dashboard.html",
        recent=recent,
        total=total,
        active=active,
        delivered=delivered,
    )


@app.route("/user/deliveries")
@login_required("user")
def user_deliveries():
    with get_db() as db:
        deliveries = db.execute("""
            SELECT d.*, v.registration_number AS vehicle_number,
                   v.vehicle_type AS assigned_vehicle_type,
                   dr.name AS driver_name, dr.phone AS driver_phone
            FROM delivery_requests d
            LEFT JOIN vehicles v ON v.id = d.assigned_vehicle_id
            LEFT JOIN drivers dr ON dr.id = d.assigned_driver_id
            WHERE d.account_id = ?
            ORDER BY d.id DESC
        """, (session["account_id"],)).fetchall()

    return render_template("user_deliveries.html", deliveries=deliveries)


@app.route("/user/deliveries/<int:delivery_id>/update", methods=["GET", "POST"])
@login_required("user")
def edit_delivery(delivery_id):
    account_id = session["account_id"]

    with get_db() as db:
        delivery = db.execute("""
            SELECT * FROM delivery_requests
            WHERE id = ? AND account_id = ?
        """, (delivery_id, account_id)).fetchone()

        if not delivery:
            flash("Delivery not found.", "error")
            return redirect(url_for("user_deliveries"))

        if delivery["status"] != "Pending":
            flash("Only pending deliveries can be updated.", "error")
            return redirect(url_for("user_deliveries"))

        if request.method == "POST":
            pickup = request.form.get("pickup_address", "").strip()
            destination = request.form.get("delivery_address", "").strip()
            goods = request.form.get("goods_description", "").strip()
            requested_date = request.form.get("requested_date", "").strip() or None
            deadline = request.form.get("delivery_deadline", "").strip() or None
            priority = request.form.get("priority", "Normal").strip()

            try:
                weight = float(request.form.get("weight_kg", ""))
                volume = float(request.form.get("volume_m3", ""))

                if not all([pickup, destination, goods]):
                    raise ValueError
                if not math.isfinite(weight) or not math.isfinite(volume):
                    raise ValueError
                if weight <= 0 or volume <= 0:
                    raise ValueError
                if priority not in {"Low", "Normal", "High", "Urgent"}:
                    raise ValueError
            except ValueError:
                flash("Enter valid delivery details, weight, and volume.", "error")
                return render_template(
                    "update_delivery.html",
                    delivery=delivery,
                    today=datetime.now().date().isoformat(),
                )

            db.execute("""
                UPDATE delivery_requests
                SET pickup_address = ?,
                    delivery_address = ?,
                    goods_description = ?,
                    requested_date = ?,
                    delivery_deadline = ?,
                    weight_kg = ?,
                    volume_m3 = ?,
                    priority = ?
                WHERE id = ? AND account_id = ? AND status = 'Pending'
            """, (
                pickup, destination, goods, requested_date, deadline,
                weight, volume, priority, delivery_id, account_id,
            ))

            flash("Delivery updated successfully.", "success")
            return redirect(url_for("user_deliveries"))

    return render_template(
        "update_delivery.html",
        delivery=delivery,
        today=datetime.now().date().isoformat(),
    )


@app.route("/user/deliveries/<int:delivery_id>/delete", methods=["POST"])
@login_required("user")
def delete_delivery(delivery_id):
    account_id = session["account_id"]

    with get_db() as db:
        delivery = db.execute("""
            SELECT id, status FROM delivery_requests
            WHERE id = ? AND account_id = ?
        """, (delivery_id, account_id)).fetchone()

        if not delivery:
            flash("Delivery not found.", "error")
        elif delivery["status"] != "Pending":
            flash("Only pending deliveries can be deleted.", "error")
        else:
            db.execute("""
                DELETE FROM delivery_requests
                WHERE id = ? AND account_id = ? AND status = 'Pending'
            """, (delivery_id, account_id))
            flash("Delivery deleted successfully.", "success")

    return redirect(url_for("user_deliveries"))


@app.route("/user/deliveries/new", methods=["GET", "POST"])
@login_required("user")
def new_delivery():
    if request.method == "POST":
        pickup = request.form.get("pickup_address", "").strip()
        destination = request.form.get("delivery_address", "").strip()
        goods = request.form.get("goods_description", "").strip()
        requested_date = request.form.get("requested_date", "").strip() or None
        deadline = request.form.get("delivery_deadline", "").strip() or None
        weight_input = request.form.get("weight_kg", "").strip()
        volume_input = request.form.get("volume_m3", "").strip()
        priority = request.form.get("priority", "Normal").strip()
        allowed_priorities = {"Low", "Normal", "High", "Urgent"}

        if not all([pickup, destination, goods, weight_input, volume_input]):
            flash(
                "Please complete all required delivery details, including weight and volume.",
                "error",
            )
        elif priority not in allowed_priorities:
            flash("Invalid delivery priority.", "error")
        else:
            try:
                weight = float(weight_input)
                volume = float(volume_input)
                if (
                    not math.isfinite(weight)
                    or not math.isfinite(volume)
                    or weight <= 0
                    or volume <= 0
                ):
                    raise ValueError
            except ValueError:
                flash("Weight and volume must be positive valid numbers.", "error")
            else:
                with get_db() as db:
                    db.execute("""
                        INSERT INTO delivery_requests (
                            account_id, pickup_address, delivery_address,
                            goods_description, requested_date, delivery_deadline,
                            weight_kg, volume_m3, priority, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
                    """, (
                        session["account_id"], pickup, destination, goods,
                        requested_date, deadline, weight, volume, priority,
                    ))

                flash(
                    "Vehicle request submitted successfully. Waiting for Admin approval.",
                    "success",
                )
                return redirect(url_for("user_deliveries"))

    return render_template(
        "new_delivery.html",
        today=datetime.now().date().isoformat(),
    )


@app.route("/user/profile")
@login_required("user")
def user_profile():
    with get_db() as db:
        account = db.execute(
            "SELECT name, email, created_at FROM accounts WHERE id = ?",
            (session["account_id"],),
        ).fetchone()

    return render_template("user_profile.html", account=account)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("landing"))


@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        code=403,
        message="You don't have permission to view this page.",
    ), 403


@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html",
        code=404,
        message="The page you requested could not be found.",
    ), 404


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1")