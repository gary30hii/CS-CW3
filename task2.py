import json
import hashlib
import getpass
import random
import os

USER_DATA_FILE = "users.json"  # New file to keep SHA-1 version separate


def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)


def hash_password(password, salt):
    return hashlib.sha1(password.encode() + salt).hexdigest()


def generate_otp():
    return str(random.randint(100000, 999999))


def mfa_login():
    users = load_users()

    while True:
        print("\nMulti-Factor Authentication Login")
        username = input("Enter your username (or type 'exit' to quit): ").strip()
        if username.lower() == "exit":
            print("Exiting MFA system.")
            break

        if username not in users:
            print("Username not found.")
            continue

        user = users[username]
        if user["login_attempts"] >= 3:
            print("Account locked due to too many failed attempts.")
            continue

        password = input("Enter your password: ")

        salt = bytes.fromhex(user["salt"])
        hashed_input = hash_password(password, salt)

        if hashed_input == user["hash"]:
            print("Password correct.")

            # Simulate OTP delivery
            otp = generate_otp()
            print(
                f"OTP sent to {user.get('email', 'your registered email')} (simulated): {otp}"
            )

            entered_otp = input("Enter the OTP: ").strip()
            if entered_otp == otp:
                print("Multi-Factor Authentication Successful. Access granted.")
                user["login_attempts"] = 0
            else:
                print("Incorrect OTP. Access denied.")
                user["login_attempts"] += 1
        else:
            print("Incorrect password.")
            user["login_attempts"] += 1

        save_users(users)


if __name__ == "__main__":
    print("Multi-Factor Authentication Login")
    mfa_login()
