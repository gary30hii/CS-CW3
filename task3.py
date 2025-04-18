import json
import hashlib
import time
import os
import itertools
import string

USER_DATA_FILE = "users.json"


# ---------------------------
# Common Functions
# ---------------------------
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    return {}


def hash_password(password, salt):
    return hashlib.sha256(salt + password.encode()).hexdigest()


def get_user_info(username):
    users = load_users()
    return users.get(username, None)


# ---------------------------
# Method 1: Dictionary Attack
# ---------------------------
def dictionary_attack(username, wordlist):
    user = get_user_info(username)
    if not user:
        print("Username not found.")
        return

    salt = bytes.fromhex(user["salt"])
    real_hash = user["hash"]

    print("\nDictionary Attack Started")
    start = time.time()
    for attempt, password in enumerate(wordlist, start=1):
        hashed = hash_password(password, salt)
        if hashed == real_hash:
            print(f"Password found: '{password}' in {attempt} attempts.")
            print(f"Time: {time.time() - start:.2f} seconds")
            return
    print(f"Dictionary attack failed. ({attempt} attempts)")
    print(f"Time: {time.time() - start:.2f} seconds")


# ---------------------------
# Method 2: Brute Force Attack (Time-limited)
# ---------------------------
def brute_force_attack(username, charset, max_time=60, max_length=10):
    user = get_user_info(username)
    if not user:
        print("Username not found.")
        return

    salt = bytes.fromhex(user["salt"])
    real_hash = user["hash"]

    print(f"\nBrute Force Attack Started (≥8 characters, time-limited to {max_time}s)")
    start = time.time()
    attempt = 0

    for length in range(8, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempt += 1
            password = "".join(combo)
            hashed = hash_password(password, salt)

            if hashed == real_hash:
                print(f"Password cracked! Password is '{password}'")
                print(f"Attempts: {attempt}")
                print(f"Time taken: {time.time() - start:.2f} seconds")
                return

            if time.time() - start > max_time:
                print(f"Time limit of {max_time}s reached. Stopping brute force.")
                print(f"Attempts tried: {attempt}")
                return

    print("Brute-force failed (not found).")


# ---------------------------
# Method 3: Offline Hash Access
# ---------------------------
def show_offline_hash(username):
    user = get_user_info(username)
    if not user:
        print("Username not found.")
        return
    print("\nOffline Access to Stored Hash:")
    print(f"Username: {username}")
    print(f"Salt (hex): {user['salt']}")
    print(f"Hashed Password: {user['hash']}")


# ---------------------------
# Dictionary (Slide 9 + extras)
# ---------------------------
common_passwords = [
    "123456",
    "123456789",
    "qwerty",
    "password",
    "12345678",
    "12345",
    "111111",
    "1234567",
    "sunshine",
    "iloveyou",
    "princess",
    "admin",
    "welcome",
    "football",
    "123123",
    "abc123",
    "1234567890",
    "letmein",
    "1234",
    "baseball",
    "password1",
    "monkey",
    "dragon",
    "shadow",
    "superman",
    "trustno1",
    "whatever",
    "000000",
    "1q2w3e4r",
    "master",
    "qwerty123",
    "login",
    "hello",
    "freedom",
    "starwars",
    "555555",
    "lovely",
    "7777777",
    "123qwe",
    "Test@1234",
    "michael",
    "batman",
    "jesus",
    "hottie",
    "ashley",
    "bailey",
    "charlie",
    "donald",
    "flower",
    "mustang",
    "passw0rd",
    "ninja",
]

# ---------------------------
# Main Interface
# ---------------------------
if __name__ == "__main__":
    print("Task 3: Password Cracking Simulation")
    username = input("Enter username to test: ").strip()
    user = get_user_info(username)

    if not user:
        print("User not found in users.json")
        exit()

    while True:
        print("\n Choose attack method:")
        print("1. Dictionary Attack")
        print("2. Brute Force Attack (8-char, 60s limit)")
        print("3. View Stored Hash (Offline Access)")
        print("4. Exit")
        choice = input("Enter choice (1–4): ").strip()

        if choice == "1":
            dictionary_attack(username, common_passwords)
        elif choice == "2":
            charset = string.ascii_lowercase + string.digits
            brute_force_attack(username, charset, max_time=60)
        elif choice == "3":
            show_offline_hash(username)
        elif choice == "4":
            print("Exiting simulation.")
            break
        else:
            print("Invalid choice. Try again.")
