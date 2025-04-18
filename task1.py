import hashlib
import os
import json
import getpass

# File to store user data
USER_DATA_FILE = "users.json"


# Load or initialize user database
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as file:
            return json.load(file)
    return {}


def save_users(users):
    with open(USER_DATA_FILE, "w") as file:
        json.dump(users, file)


# Generate random salt
def generate_salt():
    return os.urandom(16)


# Hash password with salt using SHA-256
def hash_password(password, salt):
    return hashlib.sha256(salt + password.encode()).hexdigest()


# Register a new user
def register_user(users):
    username = input("Enter new username: ").strip()
    if username in users:
        print("Username already exists. Try logging in.")
        return

    password = getpass.getpass("Set a password: ")
    if not check_password_complexity(password):
        print(
            "Password too weak. Must be at least 8 characters with upper, lower, digit and symbol."
        )
        return

    salt = generate_salt()
    hashed = hash_password(password, salt)

    users[username] = {"salt": salt.hex(), "hash": hashed, "login_attempts": 0}
    save_users(users)
    print("Registration successful!")


# Check password complexity
def check_password_complexity(pw):
    return (
        len(pw) >= 8
        and any(c.islower() for c in pw)
        and any(c.isupper() for c in pw)
        and any(c.isdigit() for c in pw)
        and any(not c.isalnum() for c in pw)
    )


# Login user
def login_user(users):
    username = input("Username: ").strip()
    if username not in users:
        print("Username not found.")
        return

    user = users[username]
    if user["login_attempts"] >= 3:
        print("Account locked due to too many failed login attempts.")
        return

    # password = getpass.getpass("Password: ")
    password = input("Password: ")
    salt = bytes.fromhex(user["salt"])
    hashed_input = hash_password(password, salt)

    if hashed_input == user["hash"]:
        print("Login successful!")
        user["login_attempts"] = 0
    else:
        user["login_attempts"] += 1
        print(f"Incorrect password. Attempts left: {3 - user['login_attempts']}")

    save_users(users)


# Main menu
def main():
    users = load_users()
    while True:
        print("\nSecure Auth System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Select option: ")

        if choice == "1":
            register_user(users)
        elif choice == "2":
            login_user(users)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
