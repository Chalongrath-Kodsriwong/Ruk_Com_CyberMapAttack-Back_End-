from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
import requests
import json
import bcrypt
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, decode_token
import jwt

import smtplib
from email.mime.text import MIMEText

import uuid

import pyotp
import base64

import random
from psycopg2.extras import execute_values


app = Flask(__name__)
CORS(app)

# Load environment variables from .env file
load_dotenv()

# Access environment variables
ES_URL = os.getenv("ES_URL")
ES_URL2 = os.getenv("ES_URL2")
ES_USERNAME = os.getenv("ES_USERNAME")
ES_PASSWORD = os.getenv("ES_PASSWORD")

# Access environment variables
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DB_HOST = os.getenv("DB_HOST")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your_secret_key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=60)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)


jwt = JWTManager(app)

# Token expiration settings
TOKEN_EXPIRATION = {
    "SuperAdmin": timedelta(days=365 * 10),  # 10 years
    "Admin": timedelta(minutes=1),         # 1 minutes
    "Normal": timedelta(minutes=1),         # 1 minute
}

def connect_to_db():
    try:
        return psycopg2.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            host=DB_HOST
        )
    except psycopg2.OperationalError as e:
        print(f"Database connection error: {e}")
        raise


# Initial password hashing for existing users
def hash_existing_passwords():
    try:
        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch all users with plain-text passwords
        cursor.execute('SELECT "ID", "password_hash" FROM "Test2"."Production_Info_User"')
        users = cursor.fetchall()

        for user in users:
            user_id = user["ID"]
            plain_password = user["password_hash"]

            # Check if the password is already hashed
            if not plain_password.startswith("$2b$"):
                # Hash the plain-text password
                hashed_password = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

                # Update the hashed password in the database
                cursor.execute(
                    'UPDATE "Test2"."Production_Info_User" SET "password_hash" = %s WHERE "ID" = %s',
                    (hashed_password, user_id)
                )
                print(f"Updated user ID {user_id} with hashed password.")

        # Commit changes
        conn.commit()

    except Exception as e:
        print(f"Error in hash_existing_passwords: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Call this function when the application starts
hash_existing_passwords()

def generate_token(user):
    expiration_time = None
    if user.role == "SuperAdmin":
        # SuperAdmin token never expires (set expiration far in the future)
        expiration_time = datetime.utcnow() + timedelta(days=3650)  # 10 years
    else:
        # Admin and User tokens expire after 1 minutes
        expiration_time = datetime.utcnow() + timedelta(minutes=1)

    token = jwt.encode(
        {
            "sub": user.username,
            "role": user.role,
            "exp": expiration_time,
        },
        "YOUR_SECRET_KEY",
        algorithm="HS256",
    )
    return token

# Update Status Of User (Permission Of Super Admin Only)
@app.route("/api/update-status", methods=["PATCH"])
def update_status():
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # ดึงผู้ใช้ทั้งหมด
        cursor.execute('SELECT "ID", "otp_secret", "otp_setup", "status" FROM "Test2"."Production_Info_User"')
        users = cursor.fetchall()

        for user in users:
            user_id, otp_secret, otp_setup, status = user

            # ตรวจสอบเงื่อนไขและอัปเดตสถานะ
            if otp_secret and otp_setup:  # otp_secret ไม่เป็น Null และ otp_setup เป็น True
                new_status = "valid"
            else:
                new_status = "invalid"

            if status != new_status:
                cursor.execute(
                    'UPDATE "Test2"."Production_Info_User" SET "status" = %s WHERE "ID" = %s',
                    (new_status, user_id)
                )

        conn.commit()
        return jsonify({"msg": "Status updated successfully."}), 200
    except Exception as e:
        print(f"Error in update_status: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


# Search User 
@app.route("/api/search-users", methods=["GET"])
@jwt_required()
def search_users():
    try:
        search_query = request.args.get("query", "").strip()

        if not search_query:
            return jsonify({"msg": "Query is required"}), 400

        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # ค้นหาด้วย ID, username, email หรือ role
        cursor.execute(
            '''
            SELECT * FROM "Test2"."Production_Info_User"
            WHERE CAST("ID" AS TEXT) ILIKE %s 
            OR "username" ILIKE %s 
            OR "email" ILIKE %s
            OR "role" ILIKE %s
            ''',
            (f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%")
        )
        results = cursor.fetchall()

        return jsonify(results), 200

    except Exception as e:
        print(f"Error in search_users: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()





# Get Username display on Narbar Icon user
@app.route('/api/get-user-info', methods=['GET'])
@jwt_required()  # Require JWT authentication
def get_user_info():
    try:
        # ดึงข้อมูล identity จาก JWT
        current_user = get_jwt_identity()

        return jsonify({
            "username": current_user.get("username"),
            "role": current_user.get("role")
        }), 200

    except Exception as e:
        print(f"Error in /api/get-user-info: {e}")
        return jsonify({"msg": "Failed to fetch user info"}), 500




# Generate QR Code and Save OTP Secret
@app.route('/api/setup-2fa', methods=['POST'])
def setup_2fa():
    try:
        data = request.get_json()
        username = data.get("username")

        if not username:
            return jsonify({"error": "Username is required"}), 400

        secret = pyotp.random_base32()  # Generate a unique secret
        totp = pyotp.TOTP(secret)
        otpauth_url = totp.provisioning_uri(name=username, issuer_name="YourApp")

        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE "Test2"."Production_Info_User" SET "otp_secret" = %s, "otp_setup" = TRUE WHERE "username" = %s',
            (secret, username)
        )
        conn.commit()

        return jsonify({"otpauth_url": otpauth_url}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



# Verify OTP OF Login Page
@app.route('/api/validate-otp', methods=['POST'])
def validate_otp():
    try:
        data = request.get_json()
        username = data.get("username")
        otp = data.get("otp")

        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT "otp_secret", "role", "status", "otp_setup" FROM "Test2"."Production_Info_User" WHERE "username" = %s',
            (username,)
        )
        result = cursor.fetchone()

        if not result or not result[0]:
            return jsonify({"msg": "2FA not set up. Please scan the QR code first."}), 400

        secret, role, status, otp_setup = result
        totp = pyotp.TOTP(secret)

        if totp.verify(otp):
            # ตรวจสอบและอัปเดตสถานะและ otp_setup
            if status == "invalid" or not otp_setup:
                cursor.execute(
                    '''
                    UPDATE "Test2"."Production_Info_User"
                    SET "status" = %s, "otp_setup" = %s
                    WHERE "username" = %s
                    ''',
                    ("valid", True, username)
                )
                conn.commit()

            # Generate JWT Token after OTP validation
            if role == "SuperAdmin":
                expires = timedelta(days=365 * 10)  # 10 years
            elif role == "Admin":
                expires = timedelta(minutes=1)  # 1 minutes
            else:  # Normal User
                expires = timedelta(minutes=0)  # 0 minutes

            access_token = create_access_token(identity={"username": username, "role": role}, expires_delta=expires)
            
            return jsonify({
                "msg": "OTP validated successfully. Login complete.",
                "access_token": access_token
            }), 200
        else:
            # Return success response with an error flag for invalid OTP
            return jsonify({"msg": "Invalid OTP", "error": True}), 200
    except Exception as e:
        print(f"Error in validate_otp: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()












# Edite Role Of All User Normal Admin (Permission Of Super Admin User Only)
@app.route("/api/edit-role", methods=["POST"])
@jwt_required()
def edit_role():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        user_id = data.get("user_id")
        new_role = data.get("new_role")
        
        if not user_id or not new_role:
            return jsonify({"msg": "User ID and new role are required"}), 400

        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Verify current user's role
        cursor.execute(
            'SELECT * FROM "Test2"."Production_Info_User" WHERE "username" = %s',
            (current_user["username"],),
        )
        current_user_data = cursor.fetchone()

        if not current_user_data or current_user_data["role"] != "SuperAdmin":
            return jsonify({"msg": "Only Super Admins can edit roles."}), 403

        # Verify target user details
        cursor.execute(
            'SELECT * FROM "Test2"."Production_Info_User" WHERE "ID" = %s',
            (user_id,),
        )
        target_user = cursor.fetchone()

        if not target_user:
            return jsonify({"msg": "User not found."}), 404

        if target_user["role"] == "SuperAdmin":
            return jsonify({"msg": "Cannot edit roles of Super Admins."}), 403

        # Update role
        cursor.execute(
            'UPDATE "Test2"."Production_Info_User" SET "role" = %s WHERE "ID" = %s',
            (new_role, user_id),
        )
        conn.commit()

        return jsonify({"msg": "User role updated successfully."}), 200

    except Exception as e:
        print(f"Error in edit_role: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()









# Forgot password on Login Page
@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"msg": "Email is required"}), 400

        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # ตรวจสอบว่ามีอีเมลในระบบหรือไม่
        cursor.execute('SELECT * FROM "Test2"."Production_Info_User" WHERE email = %s', (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"msg": "Email not found"}), 404

        # สร้าง reset_token และ reset link
        reset_token = str(uuid.uuid4())
        reset_link = f"http://localhost:5173/reset-password?token={reset_token}"

        # บันทึก reset_token ใน Production_Info_User
        cursor.execute(
            'UPDATE "Test2"."Production_Info_User" SET "reset_token" = %s WHERE "ID" = %s',
            (reset_token, user["ID"])
        )
        conn.commit()

        # ส่งอีเมลพร้อม reset link
        msg = MIMEText(f"Click the link below to reset your password:\n\n{reset_link}")
        msg["Subject"] = "Reset Your Password"
        msg["From"] = SMTP_USER
        msg["To"] = email

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, email, msg.as_string())

        return jsonify({"msg": "Password reset email sent."}), 200

    except Exception as e:
        print(f"Error in forgot_password: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



# Change password Of Admin normal (Super Admin Can not see this function)
@app.route("/api/change-password-narbar", methods=["POST"])
@jwt_required()
def change_password_new():
    try:
        data = request.get_json()
        new_password = data.get("new_password")

        if not new_password:
            return jsonify({"msg": "New password is required"}), 400

        # ดึงข้อมูล username จาก JWT
        current_user = get_jwt_identity()
        username = current_user.get("username")

        if not username:
            return jsonify({"msg": "User not found"}), 404

        # แปลงรหัสผ่านใหม่เป็น hash
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        conn = connect_to_db()
        cursor = conn.cursor()

        # อัปเดตรหัสผ่านในฐานข้อมูล
        cursor.execute(
            'UPDATE "Test2"."Production_Info_User" SET "password_hash" = %s WHERE "username" = %s',
            (hashed_password, username)
        )
        conn.commit()

        return jsonify({"msg": "Password changed successfully."}), 200

    except Exception as e:
        print(f"Error in change_password_new: {e}")
        return jsonify({"msg": "Internal Server Error "}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()







# Permission of Super Admin (Can use only) Change password of Admin by SuperAdmin on Page User Management
@app.route("/api/change-password", methods=["POST"])
@jwt_required()
def change_password():
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        new_password = data.get("new_password")

        if not user_id or not new_password:
            return jsonify({"msg": "User ID and new password are required"}), 400

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        conn = connect_to_db()
        cursor = conn.cursor()

        # Update the password in the database
        cursor.execute(
            'UPDATE "Test2"."Production_Info_User" SET "password_hash" = %s WHERE "ID" = %s',
            (hashed_password, user_id)
        )
        conn.commit()

        return jsonify({"msg": "Password changed successfully."}), 200
    except Exception as e:
        print(f"Error in change_password: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()







# Delete User out of Database
@app.route("/api/delete-user", methods=["POST"])
@jwt_required()
def delete_user():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        user_ids = data.get("user_ids", [])  # List ของ user_ids ที่จะลบ

        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # ตรวจสอบ role ของ current user
        cursor.execute(
            'SELECT * FROM "Test2"."Production_Info_User" WHERE "username" = %s',
            (current_user["username"],)
        )
        current_user_data = cursor.fetchone()

        print(current_user)

        if not current_user_data or current_user_data["role"] != "SuperAdmin":
            return jsonify({"msg": "Only Super Admins can delete users."}), 403

        # ตรวจสอบและลบเฉพาะผู้ใช้ที่เป็น Admin และไม่ใช่ตัวเอง
        deletable_users = []
        for user_id in user_ids:
            cursor.execute(
                'SELECT * FROM "Test2"."Production_Info_User" WHERE "ID" = %s',
                (user_id,),
            )
            user = cursor.fetchone()

            if (
                user
                and user["role"] == "Admin"
                and user["ID"] != current_user_data["ID"]
            ):
                deletable_users.append(user_id)

        if not deletable_users:
            return jsonify({"msg": "No valid users to delete."}), 400

        # ลบผู้ใช้ที่ผ่านการตรวจสอบ
        cursor.execute(
            f'DELETE FROM "Test2"."Production_Info_User" WHERE "ID" IN %s',
            (tuple(deletable_users),),
        )
        conn.commit()

        return jsonify({"msg": "Selected users have been deleted."}), 200
    except Exception as e:
        print(f"Error in delete_user: {e}")
        return jsonify({"msg": "Internal Server Error", "detail":{e}}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()






# Logout system
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    current_user = get_jwt_identity()
    # คุณสามารถเพิ่ม logic เพื่อลบ Token จากระบบที่จัดการ Token เช่น Redis, Database, หรือ Blacklist
    return jsonify({"msg": "Logout successful"}), 200



# Invite user Sent to Email Target User
@app.route("/api/invite-user", methods=["POST"])
def invite_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    role = data.get("role")
    status = data.get("status")
    password = data.get("password")  # รับ plaintext password

    try:
        # เช็คว่ามี User ที่มี username หรือ email นี้อยู่ในฐานข้อมูลแล้วหรือไม่
        conn = connect_to_db()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT * FROM "Test2"."Production_Info_User" WHERE "username" = %s OR "email" = %s',
            (username, email)
        )
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"msg": "User with this username or email already exists!"}), 400

        # Hash the password เพื่อใช้เก็บใน Database
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Generate invite token
        invite_token = str(uuid.uuid4())
        invite_link = f"http://localhost:5173/accept-invite?invite_token={invite_token}"

        # Save to Production_Info_User table with `status` set to 'Invalid'
        cursor.execute(
            'INSERT INTO "Test2"."Production_Info_User" ("username", "email", "role", "status", "password_hash", "invite_token") '
            'VALUES (%s, %s, %s, %s, %s, %s)',
            (username, email, role, "invalid", hashed_password, invite_token)
        )
        conn.commit()

        # Send invitation email พร้อม Username และ plaintext Password
        msg = MIMEText(
            f"""
            Hello {username},

            You have been invited to join as {role}.
            Username: {username}
            Password: {password}

            Please verify your account using the link below:
            {invite_link}
            """
        )
        msg['Subject'] = 'Invitation to Join'
        msg['From'] = SMTP_USER
        msg['To'] = email

        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, email, msg.as_string())
                print(f"Email sent to {email}")
        except Exception as e:
            print(f"Error sending email: {e}")
            return jsonify({"msg": f"Error sending email: {str(e)}"}), 500

        return jsonify({"msg": f"Invitation sent to {email}!"}), 200

    except Exception as e:
        print(f"Database error: {e}")
        return jsonify({"msg": f"Database error: {str(e)}"}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()







    


# Accept Invite 
@app.route("/api/accept-invite", methods=["GET"])
def accept_invite():
    invite_token = request.args.get("invite_token")

    if not invite_token:
        return jsonify({"msg": "Invalid invite token!"}), 400

    try:
        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # ตรวจสอบ invite_token ใน Production_Info_User
        cursor.execute(
            'SELECT * FROM "Test2"."Production_Info_User" WHERE "invite_token" = %s',
            (invite_token,)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"msg": "Invalid or expired invitation link!"}), 400

        # อัปเดตสถานะเป็น Valid
        cursor.execute(
            'UPDATE "Test2"."Production_Info_User" SET "status" = %s WHERE "invite_token" = %s',
            ("valid", invite_token)
        )
        conn.commit()

        # คืนค่า username กลับไปยัง Frontend
        return jsonify({"msg": "Invitation accepted!", "username": user["username"]}), 200

    except Exception as e:
        print(f"Error in accept_invite: {e}")
        return jsonify({"msg": f"Error: {str(e)}"}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()




# Chage Status of OTP User
@app.route("/api/toggle-status/<int:user_id>", methods=["PATCH"])
@jwt_required()
def toggle_user_status(user_id):
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # ดึงสถานะปัจจุบันของผู้ใช้
        cursor.execute('SELECT "status" FROM "Test2"."Production_Info_User" WHERE "ID" = %s', (user_id,))
        current_status = cursor.fetchone()

        if not current_status:
            return jsonify({"msg": "User not found."}), 404

        # กำหนดสถานะใหม่
        new_status = "valid" if current_status[0] == "invalid" else "invalid"

        # อัปเดตสถานะในฐานข้อมูล
        cursor.execute('UPDATE "Test2"."Production_Info_User" SET "status" = %s WHERE "ID" = %s', (new_status, user_id))
        conn.commit()

        return jsonify({"msg": f"User status changed to {new_status}!"}), 200
    except Exception as e:
        print(f"Error in toggle_user_status: {e}")
        return jsonify({"msg": f"Error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


# Reset Token OTP
@app.route("/api/reset-2fa/<int:user_id>", methods=["PATCH"])
@jwt_required()
def reset_2fa(user_id):
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # รีเซ็ต otp_secret และ otp_setup
        cursor.execute(
            '''
            UPDATE "Test2"."Production_Info_User"
            SET "otp_secret" = NULL, "otp_setup" = FALSE, "status" = 'invalid'
            WHERE "ID" = %s
            ''',
            (user_id,)
        )
        conn.commit()

        return jsonify({"msg": "2FA reset successfully. User marked as Invalid."}), 200

    except Exception as e:
        print(f"Error in reset_2fa: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()









            
# Fetch check Verify OTP User
@app.route("/api/getpending_users", methods=["GET"])
@jwt_required()
def get_Production_Info_Users():
    try:
        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # แก้ไข Query ให้ดึงข้อมูลที่เกี่ยวข้องกับ Pending Invite
        cursor.execute("""
            SELECT "ID", "username", "email", "role", "status", "invite_token"
            FROM "Test2"."Production_Info_User"
            ORDER BY "ID" ASC
        """)
        pending_users = cursor.fetchall()

        return jsonify(pending_users), 200

    except Exception as e:
        print(f"Error in /api/getpending_users: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



@app.route("/api/users", methods=["GET"])
@jwt_required()
def get_users():
    try:
        current_user = get_jwt_identity()
        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM "Test2"."Production_Info_User" ORDER BY "ID" ASC')
        users = cursor.fetchall()
        return jsonify(users), 200
    except Exception as e:
        print(f"Error in get_users: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


# Login
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"msg": "Username and password are required"}), 400

        conn = connect_to_db()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM "Test2"."Production_Info_User" WHERE username = %s', (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"msg": "Invalid username or password"}), 401

        # Verify password
        stored_password = user["password_hash"]
        is_valid = bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8"))

        if not is_valid:
            return jsonify({"msg": "Invalid username or password"}), 401

        # Check if 2FA is set up
        otp_setup = user["otp_setup"]
        role = user["role"]

        if not otp_setup:
            # ส่ง username และ role พร้อมแจ้งว่ายังไม่ได้ตั้งค่า 2FA
            return jsonify({
                "setup_2fa": True,
                "username": username,
                "role": role
            }), 200

        # Set expiration time based on role
        if role == "SuperAdmin":
            expires = timedelta(days=365 * 10)  # 10 years
        elif role == "Admin":
            expires = timedelta(minutes=1)  # 1 minutes
        else:  # Normal User
            expires = timedelta(minutes=0)  # 0 minutes

        # Create JWT Token
        access_token = create_access_token(identity={"username": username, "role": role}, expires_delta=expires)

        # Return JWT Token and role
        return jsonify({
            "role": role,
            "username": username
        }), 200
    except Exception as e:
        print(f"Error in /api/login: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()







# Refresh Token JWT And Set clock access user
@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user = get_jwt_identity()
        role = current_user["role"]

        # กำหนดเวลาตาม Role
        if role == "SuperAdmin":
            expires = timedelta(days=365 * 10)  # 10 years
        elif role == "Admin":
            expires = timedelta(minutes=1)  # 1 hour
        else:  # Normal User
            expires = timedelta(minutes=0)  # 0 minutes

        new_access_token = create_access_token(identity=current_user, expires_delta=expires)
        return jsonify({"access_token": new_access_token}), 200
    except Exception as e:
        print(f"Error in /api/refresh: {e}")
        return jsonify({"msg": "Internal Server Error"}), 500




@app.route("/api/alerts", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_alerts():
    """
    ดึงข้อมูล Alerts จาก Elasticsearch
    """
    try:
        # ดึงข้อมูล User จาก JWT
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        # Elasticsearch Query
        query = {
            "query": {
                "term": {
                    "rule.groups": "attack"
                }
            }
        }

        # ส่งคำขอไปยัง Elasticsearch
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        # ตรวจสอบสถานะ HTTP
        response.raise_for_status()

        # ดึงข้อมูล JSON จาก Elasticsearch
        data = response.json()
        hits = data.get("hits", {}).get("hits", [])

        # ส่งข้อมูลกลับในรูปแบบ JSON
        return jsonify(hits), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching alerts: {e}"}), 500





@app.route("/api/top-mitre-techniques", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_top_mitre_techniques():
    """
    Fetch Top 10 MITRE ATT&CK Techniques
    """
    try:
        # ดึงข้อมูล User จาก JWT
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")
        # Elasticsearch Query (from your provided JSON)
        query = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 10
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "data.aws.createdAt", "format": "date_time"},
                {"field": "data.aws.end", "format": "date_time"},
                {"field": "data.aws.resource.instanceDetails.launchTime", "format": "date_time"},
                {"field": "data.aws.service.eventFirstSeen", "format": "date_time"},
                {"field": "data.aws.service.eventLastSeen", "format": "date_time"},
                {"field": "data.aws.start", "format": "date_time"},
                {"field": "data.aws.updatedAt", "format": "date_time"},
                {"field": "data.ms-graph.createdDateTime", "format": "date_time"},
                {"field": "data.ms-graph.firstActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastUpdateDateTime", "format": "date_time"},
                {"field": "data.ms-graph.resolvedDateTime", "format": "date_time"},
                {"field": "data.timestamp", "format": "date_time"},
                {"field": "data.vulnerability.published", "format": "date_time"},
                {"field": "data.vulnerability.updated", "format": "date_time"},
                {"field": "syscheck.mtime_after", "format": "date_time"},
                {"field": "syscheck.mtime_before", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"}
            ],
            "_source": {"excludes": ["@timestamp"]},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {"match_phrase": {"cluster.name": {"query": "wazuh"}}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-200d/d",
                                    "lte": "now",   #ถึงเวลาปัจจุบัน
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }

        # Send Elasticsearch request
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False  # Disable SSL verification (for development only)
        )

        # Raise an exception if the request fails
        response.raise_for_status()

        # Extract the response data
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

        # Format the results
        results = [{"technique": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets]

        return jsonify(results)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching data from Elasticsearch: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/top-agents", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_top_agents():
    """
    ดึงข้อมูล Top 5 Agent Names ที่มีการโจมตีมากที่สุด
    """
    try:
        # ดึงข้อมูล User จาก JWT
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        # Elasticsearch Query
        query = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "agent.name",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 5
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "docvalue_fields": [
                {"field": "data.aws.createdAt", "format": "date_time"},
                {"field": "data.aws.end", "format": "date_time"},
                {"field": "data.aws.resource.instanceDetails.launchTime", "format": "date_time"},
                {"field": "data.aws.service.eventFirstSeen", "format": "date_time"},
                {"field": "data.aws.service.eventLastSeen", "format": "date_time"},
                {"field": "data.aws.start", "format": "date_time"},
                {"field": "data.aws.updatedAt", "format": "date_time"},
                {"field": "data.ms-graph.createdDateTime", "format": "date_time"},
                {"field": "data.ms-graph.firstActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastUpdateDateTime", "format": "date_time"},
                {"field": "data.ms-graph.resolvedDateTime", "format": "date_time"},
                {"field": "data.timestamp", "format": "date_time"},
                {"field": "data.vulnerability.published", "format": "date_time"},
                {"field": "data.vulnerability.updated", "format": "date_time"},
                {"field": "syscheck.mtime_after", "format": "date_time"},
                {"field": "syscheck.mtime_before", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"}
            ],
            "_source": {"excludes": ["@timestamp"]},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {"match_phrase": {"cluster.name": {"query": "wazuh"}}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-200d/d",
                                    "lte": "now",
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }

        # ส่งคำขอไปยัง Elasticsearch
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        # ตรวจสอบสถานะ HTTP
        response.raise_for_status()

        # ดึงข้อมูล JSON จาก Elasticsearch
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

        # แปลงข้อมูลสำหรับการตอบกลับ
        results = [{"agent_name": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets]

        return jsonify(results)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching top agents: {e}"}), 500






@app.route("/api/top-countries", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_top_countries():
    """
    ดึงข้อมูล 10 ประเทศที่มีการโจมตีมากที่สุด
    """
    try:
        # ดึงข้อมูล User จาก JWT
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        # Elasticsearch Query
        query = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "GeoLocation.country_name",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 10
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "data.aws.createdAt", "format": "date_time"},
                {"field": "data.aws.end", "format": "date_time"},
                {"field": "data.aws.resource.instanceDetails.launchTime", "format": "date_time"},
                {"field": "data.aws.service.eventFirstSeen", "format": "date_time"},
                {"field": "data.aws.service.eventLastSeen", "format": "date_time"},
                {"field": "data.aws.start", "format": "date_time"},
                {"field": "data.aws.updatedAt", "format": "date_time"},
                {"field": "data.ms-graph.createdDateTime", "format": "date_time"},
                {"field": "data.ms-graph.firstActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastUpdateDateTime", "format": "date_time"},
                {"field": "data.ms-graph.resolvedDateTime", "format": "date_time"},
                {"field": "data.timestamp", "format": "date_time"},
                {"field": "data.vulnerability.published", "format": "date_time"},
                {"field": "data.vulnerability.updated", "format": "date_time"},
                {"field": "syscheck.mtime_after", "format": "date_time"},
                {"field": "syscheck.mtime_before", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"}
            ],
            "_source": {"excludes": ["@timestamp"]},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-200d/d",
                                    "lte": "now",
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ]
                }
            }
        }

        # ส่งคำขอไปยัง Elasticsearch
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        # ตรวจสอบสถานะ HTTP
        response.raise_for_status()

        # ดึงข้อมูล JSON จาก Elasticsearch
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

        # แปลงข้อมูลสำหรับการตอบกลับ
        results = [{"country": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets]

        return jsonify(results)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching top countries: {e}"}), 500




@app.route("/api/top-techniques", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_top_techniques():
    """
    Fetches the top MITRE techniques with historical attack data broken down by 30-minute intervals.
    """
    try:
        # ดึงข้อมูล User จาก JWT
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")
        # Elasticsearch Query for top MITRE techniques within a specific date range
        query = {
            "aggs": {
                "3": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 5
                    },
                    "aggs": {
                        "2": {
                            "date_histogram": {
                                "field": "timestamp",
                                "fixed_interval": "30m",  # 30-minute intervals
                                "time_zone": "Asia/Bangkok",  # Adjust to local timezone
                                "min_doc_count": 1
                            }
                        }
                    }
                }
            },
            "size": 0,  # We only want aggregation results, no hits
            "query": {
                "bool": {
                    "filter": [
                        {"match_all": {}},
                        {"match_phrase": {"cluster.name": {"query": "wazuh"}}},  # Only data from 'wazuh' cluster
                        {"exists": {"field": "rule.mitre.id"}},  # Only documents with a MITRE ID
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now-7d/d",
                                    "lte": "now",
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ]
                }
            }
        }

        # Send the request to Elasticsearch
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False  # Disable SSL verification if using self-signed certificates
        )

        # Check if the request was successful
        response.raise_for_status()

        # Parse the response JSON
        data = response.json()
        techniques_buckets = data.get("aggregations", {}).get("3", {}).get("buckets", [])

        # Prepare results for the response
        results = []
        for technique_bucket in techniques_buckets:
            technique_name = technique_bucket["key"]
            technique_data = {
                "technique": technique_name,
                "histogram": []
            }

            # For each 30-minute interval, get the count of events for the technique
            for interval_bucket in technique_bucket.get("2", {}).get("buckets", []):
                technique_data["histogram"].append({
                    "timestamp": interval_bucket["key_as_string"],  # Timestamp of the 30-minute interval
                    "count": interval_bucket["doc_count"]  # Number of events in this interval
                })

            results.append(technique_data)

        return jsonify(results)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching top techniques: {e}"}), 500






# @app.route("/api/peak-attack-periods", methods=["GET"])
# @jwt_required()
# def get_peak_attack_periods():
#     """
#     ดึงข้อมูลช่วงเวลาที่มีการโจมตีมากที่สุด ตั้งแต่ 12:00 น. ของวันนี้จนถึง 12:00 น. ของวันพรุ่งนี้
#     รองรับการดึงข้อมูลย้อนหลัง 7 วัน
#     """
#     try:
#         current_user = get_jwt_identity()
#         print(f"Request made by: {current_user}")

#         query = {
#             "aggs": {
#                 "2": {
#                     "date_histogram": {
#                         "field": "timestamp",
#                         "fixed_interval": "1h",
#                         "time_zone": "Asia/Bangkok",
#                         "min_doc_count": 1
#                     }
#                 }
#             },
#             "size": 0,
#             "query": {
#                 "bool": {
#                     "filter": [
#                         {"match_all": {}},
#                         {
#                             "range": {
#                                 "timestamp": {
#                                     "gte": "now-7d/d+12h",  # ดึงข้อมูลย้อนหลัง 7 วัน
#                                     "lte": "now/d+36h",  # ถึงเที่ยงของวันพรุ่งนี้
#                                     "format": "strict_date_optional_time"
#                                 }
#                             }
#                         }
#                     ]
#                 }
#             }
#         }

#         response = requests.post(
#             ES_URL,
#             auth=(ES_USERNAME, ES_PASSWORD),
#             headers={"Content-Type": "application/json"},
#             data=json.dumps(query),
#             verify=False
#         )

#         response.raise_for_status()
#         data = response.json()
#         buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

#         results = [{"timestamp": bucket["key_as_string"], "count": bucket["doc_count"]} for bucket in buckets]

#         return jsonify(results)

#     except requests.exceptions.RequestException as e:
#         return jsonify({"error": f"Error fetching peak attack periods: {e}"}), 500



@app.route("/api/peak-attack-periods", methods=["GET"])
@jwt_required()
def get_peak_attack_periods():
    """
    ดึงข้อมูลช่วงเวลาที่มีการโจมตีมากที่สุด รายวันของแต่ละวันโดยเริ่มจากเที่ยงคืนของวันนี้จนถึงเวลาปัจจุบัน
    และรีเซ็ตข้อมูลเมื่อเริ่มวันใหม่
    """
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        query = {
            "aggs": {
                "2": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "1h",
                        "time_zone": "Asia/Bangkok",
                        "min_doc_count": 1
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now/d-7h",  # ดึงข้อมูลย้อนหลัง 6 ชั่วโมงก่อนเที่ยงคืน
                                    "lte": "now",  # ถึงเวลาปัจจุบัน
                                    "format": "strict_date_optional_time"
                                }
                            }

                        }
                    ]
                }
            }
        }

        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        response.raise_for_status()
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

        results = [{"timestamp": bucket["key_as_string"], "count": bucket["doc_count"]} for bucket in buckets]

        return jsonify(results)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching peak attack periods: {e}"}), 500









@app.route('/api/vulnerabilities', methods=['GET'])
@jwt_required()  # Require JWT authentication
def get_vulnerabilities():
    current_user = get_jwt_identity()
    print(f"Request made by: {current_user}")
    """
    ดึงข้อมูล vulnerability severity จาก Elasticsearch โดยใช้โครงสร้าง JSON Query ที่ระบุ
    """
    # Elasticsearch Query
    query = {
        "aggs": {
            "2": {
                "filters": {
                    "filters": {
                        "Critical": {
                            "bool": {
                                "must": [],
                                "filter": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match_phrase": {
                                                        "vulnerability.severity": "Critical"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "should": [],
                                "must_not": []
                            }
                        },
                        "High": {
                            "bool": {
                                "must": [],
                                "filter": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match_phrase": {
                                                        "vulnerability.severity": "High"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "should": [],
                                "must_not": []
                            }
                        },
                        "Medium": {
                            "bool": {
                                "must": [],
                                "filter": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match_phrase": {
                                                        "vulnerability.severity": "Medium"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "should": [],
                                "must_not": []
                            }
                        },
                        "Low": {
                            "bool": {
                                "must": [],
                                "filter": [
                                    {
                                        "bool": {
                                            "should": [
                                                {
                                                    "match_phrase": {
                                                        "vulnerability.severity": "Low"
                                                    }
                                                }
                                            ],
                                            "minimum_should_match": 1
                                        }
                                    }
                                ],
                                "should": [],
                                "must_not": []
                            }
                        }
                    }
                }
            }
        },
        "size": 0,
        "stored_fields": ["*"],
        "script_fields": {},
        "docvalue_fields": [
            {"field": "package.installed", "format": "date_time"},
            {"field": "vulnerability.detected_at", "format": "date_time"},
            {"field": "vulnerability.published_at", "format": "date_time"}
        ],
        "_source": {"excludes": []},
        "query": {
            "bool": {
                "must": [],
                "filter": [
                    {"match_all": {}},
                    {
                        "match_phrase": {
                            "wazuh.cluster.name": {"query": "wazuh"}
                        }
                    }
                ],
                "should": [],
                "must_not": []
            }
        }
    }

    try:
        # ส่งคำขอไปยัง Elasticsearch
        response = requests.post(
            ES_URL2,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False  # ปิดการตรวจสอบ SSL หากใช้ self-signed certificates
        )

        # ตรวจสอบสถานะ HTTP
        response.raise_for_status()

        # แปลงผลลัพธ์จาก Elasticsearch
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", {})

        # สร้างผลลัพธ์ที่ตอบกลับ
        results = [{"severity": key, "count": value["doc_count"]} for key, value in buckets.items()]
        return jsonify(results), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error querying Elasticsearch: {e}"}), 500
    




def generate_unique_color(existing_colors):
    """
    สุ่มสีใหม่ที่ไม่ซ้ำกับสีที่มีอยู่ในฐานข้อมูล
    """
    while True:
        new_color = "#{:06X}".format(random.randint(0, 0xFFFFFF))  # สุ่มสี HEX
        if new_color not in existing_colors:
            return new_color

def insert_rule_descriptions_batch(descriptions):
    """
    แทรก rule.descriptions ลงในฐานข้อมูลถ้าไม่มีอยู่แล้ว (แบบ batch) พร้อมกำหนดสีที่ไม่ซ้ำกัน
    """
    if not descriptions:
        return

    try:
        with connect_to_db() as conn:
            with conn.cursor() as cur:
                # ดึงเฉพาะ description ที่ยังไม่มีในฐานข้อมูล
                cur.execute('SELECT description, color FROM "Test2"."rule_descriptions";')
                existing_data = cur.fetchall()
                
                # แยก descriptions และ colors ที่มีอยู่แล้ว
                existing_descriptions = {row[0] for row in existing_data}
                existing_colors = {row[1] for row in existing_data if row[1]}

                # คัดกรองเฉพาะ descriptions ที่ยังไม่มีในฐานข้อมูล
                new_descriptions = [desc for desc in descriptions if desc not in existing_descriptions]

                if new_descriptions:
                    # กำหนดสีที่ไม่ซ้ำกันสำหรับรายการใหม่
                    new_entries = [(desc, generate_unique_color(existing_colors)) for desc in new_descriptions]

                    query = """
                    INSERT INTO "Test2"."rule_descriptions" (description, color)
                    VALUES %s
                    ON CONFLICT (description) DO NOTHING;
                    """
                    execute_values(cur, query, new_entries)
                    conn.commit()

    except Exception as e:
        print(f"Error inserting rule.descriptions: {e}")



@app.route("/api/latest_alert", methods=["GET"])
@jwt_required()
def get_latest_alert():
    """
    ดึงข้อมูลการแจ้งเตือนล่าสุดจาก Elasticsearch และบันทึก rule.description ลงฐานข้อมูล
    """
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        response.raise_for_status()
        data = response.json()
        hits = data.get("hits", {}).get("hits", [])

        # รวบรวม rule.description ทั้งหมดในลูป
        rule_descriptions = [
            hit.get("_source", {}).get("rule", {}).get("description")
            for hit in hits
            if hit.get("_source", {}).get("rule", {}).get("description")
        ]

        # บันทึก rule.description ลงฐานข้อมูล (Batch Insert)
        if rule_descriptions:
            insert_rule_descriptions_batch(rule_descriptions)

        return jsonify(hits), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching latest alert: {e}"}), 500



@app.route("/api/mitre_alert", methods=["GET"])
@jwt_required()
def get_mitre_alert():
    """
    ดึงข้อมูล MITRE Alert ล่าสุดจาก Elasticsearch และบันทึก rule.description ลงฐานข้อมูล
    """
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [{"exists": {"field": "rule.mitre.id"}}]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        response.raise_for_status()
        data = response.json()
        hits = data.get("hits", {}).get("hits", [])

        # รวบรวม rule.description ทั้งหมดในลูป
        rule_descriptions = [
            hit.get("_source", {}).get("rule", {}).get("description")
            for hit in hits
            if hit.get("_source", {}).get("rule", {}).get("description")
        ]

        # บันทึก rule.description ลงฐานข้อมูล (Batch Insert)
        if rule_descriptions:
            insert_rule_descriptions_batch(rule_descriptions)

        return jsonify(hits), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching MITRE alert: {e}"}), 500



@app.route("/api/stored_rule_descriptions", methods=["GET"])
@jwt_required()
def get_stored_rule_descriptions():
    """
    ดึงข้อมูล rule.description และสีจากฐานข้อมูล
    """
    try:
        with connect_to_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """SELECT description, color FROM "Test2"."rule_descriptions";"""
                cur.execute(query)
                descriptions = cur.fetchall()

        return jsonify(descriptions), 200

    except Exception as e:
        return jsonify({"error": f"Error fetching stored rule descriptions: {e}"}), 500













# Count log
@app.route("/api/mitre_techniques", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_mitre_techniques():
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")
        query = {
            "size": 0,
            "aggs": {
                "mitre_techniques": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "size": 20
                    }
                }
            }
        }

        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        response.raise_for_status()

        data = response.json()
        aggregations = data.get("aggregations", {}).get("mitre_techniques", {}).get("buckets", [])

        # Return the aggregated data
        return jsonify(aggregations)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching MITRE techniques: {e}"}), 500




@app.route("/api/today-attacks", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_today_attacks():
    """
    ดึงข้อมูลการโจมตีของทุกประเทศที่เกิดขึ้นในวันนี้
    """
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")
        # Elasticsearch Query
        query = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "GeoLocation.country_name",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 100  # ขยายขนาดเพื่อรวมทุกประเทศ
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "timestamp", "format": "date_time"}
            ],
            "_source": {"excludes": ["@timestamp"]},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now/d",  # เริ่มต้นวันนี้
                                    "lte": "now",   # จนถึงตอนนี้
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ]
                }
            }
        }

        # ส่งคำขอไปยัง Elasticsearch
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        # ตรวจสอบสถานะ HTTP
        response.raise_for_status()

        # ดึงข้อมูล JSON จาก Elasticsearch
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

        # แปลงข้อมูลสำหรับการตอบกลับ
        results = [{"country": bucket["key"], "count": bucket["doc_count"]} for bucket in buckets]

        return jsonify(results)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching today attacks: {e}"}), 500





@app.route("/api/today_mitre_techniques", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_mitre_techniques_today():
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")
        

        # Elasticsearch query with date range
        query = {
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {  # ปรับฟิลด์ให้ตรงกับที่ใช้ใน Elasticsearch
                        "gte": "now/d",  # เริ่มต้นวันนี้
                        "lte": "now", 
                        "format": "strict_date_optional_time"
                    }
                }
            },
            "aggs": {
                "mitre_techniques": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "size": 100
                    }
                }
            }
        }

        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False
        )

        response.raise_for_status()

        data = response.json()
        aggregations = data.get("aggregations", {}).get("mitre_techniques", {}).get("buckets", [])

        # Return the aggregated data
        return jsonify(aggregations)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching MITRE techniques: {e}"}), 500




@app.route("/api/top_rule_descriptions", methods=["GET"])
@jwt_required()  # Require JWT authentication
def get_top_rule_descriptions():
    try:
        current_user = get_jwt_identity()
        print(f"Request made by: {current_user}")

        # Elasticsearch Query
        query = {
            "aggs": {
                "2": {
                    "terms": {
                        "field": "rule.description",
                        "order": {
                            "_count": "desc"
                        },
                        "size": 100  # ดึง 5 อันดับแรก
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "docvalue_fields": [
                {"field": "timestamp", "format": "date_time"}
            ],
            "_source": {
                "excludes": ["@timestamp"]
            },
            "query": {
                "bool": {
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "now/d",  # เริ่มต้นวันนี้
                                    "lte": "now", 
                                    "format": "strict_date_optional_time"
                                }
                            }
                        }
                    ]
                }
            }
        }

        # ส่งคำขอไปยัง Elasticsearch
        response = requests.post(
            ES_URL,
            auth=(ES_USERNAME, ES_PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False  # ปิด SSL Verification หากจำเป็น
        )

        response.raise_for_status()

        # แยกผลลัพธ์จาก Elasticsearch
        data = response.json()
        buckets = data.get("aggregations", {}).get("2", {}).get("buckets", [])

        # จัดข้อมูลสำหรับการส่งกลับ
        top_descriptions = [
            {"rule_description": bucket["key"], "count": bucket["doc_count"]}
            for bucket in buckets
        ]

        return jsonify(top_descriptions)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching top rule descriptions: {e}"}), 500




if __name__ == "__main__":
    app.run(debug=True)
