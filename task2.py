import json
import hashlib
import getpass
import random
import os

USER_DATA_FILE = "users.json"


def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)


# Modified hash function
def hash_password(password, salt=None):
    if salt:
        return hashlib.sha1(password.encode() + salt).hexdigest()
    else:
        return hashlib.sha1(password.encode()).hexdigest()


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

        if user["salted"]:
            salt = bytes.fromhex(user["salt"])
            hashed_input = hash_password(password, salt)
        else:
            hashed_input = hash_password(password)

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


# Optional: Simple register function for testing
def register_user():
    users = load_users()
    username = input("Set username: ").strip()
    if username in users:
        print("Username already exists.")
        return

    password = getpass.getpass("Set password: ")

    use_salt = input("Use salted hashing? (y/n): ").strip().lower() == "y"

    if use_salt:
        salt = os.urandom(16)
        hashed = hash_password(password, salt)
        users[username] = {
            "salted": True,
            "salt": salt.hex(),
            "hash": hashed,
            "login_attempts": 0,
            "email": "user@example.com",
        }
    else:
        hashed = hash_password(password)
        users[username] = {
            "salted": False,
            "salt": "",
            "hash": hashed,
            "login_attempts": 0,
            "email": "user@example.com",
        }

    save_users(users)
    print("User registered successfully!")


if __name__ == "__main__":
    print("1. Register User")
    print("2. Login with MFA")
    choice = input("Choose option: ").strip()

    if choice == "1":
        register_user()
    elif choice == "2":
        mfa_login()
    else:
        print("Invalid option.")
