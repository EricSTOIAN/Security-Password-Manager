import os
import base64
import json
from cryptography.fernet import Fernet
from getpass import getpass

# File to store encrypted passwords
PASSWORD_FILE = "passwords.json"

# Generate a Fernet encryption key based on the master password
def generate_key(master_password: str) -> bytes:
    return base64.urlsafe_b64encode(master_password.ljust(32).encode()[:32])

# Load existing passwords from file
def load_passwords() -> dict:
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as file:
            return json.load(file)
    return {}

# Save passwords to file
def save_passwords(passwords: dict):
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file)

# Add a new password
def add_password(key: bytes, service: str, password: str):
    passwords = load_passwords()
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(password.encode()).decode()
    passwords[service] = encrypted_password
    save_passwords(passwords)
    print(f"Password for {service} has been saved.")

# Retrieve a password
def retrieve_password(key: bytes, service: str):
    passwords = load_passwords()
    if service not in passwords:
        print(f"No password found for {service}.")
        return
    cipher = Fernet(key)
    encrypted_password = passwords[service].encode()
    try:
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        print(f"Password for {service}: {decrypted_password}")
    except Exception as e:
        print("Failed to decrypt the password. Is the master password correct?")

# List all stored services
def list_services():
    passwords = load_passwords()
    if not passwords:
        print("No services found.")
        return
    print("Stored services:")
    for service in passwords.keys():
        print(f"- {service}")

# Main menu
def main():
    master_password = getpass("Enter the master password: ")
    key = generate_key(master_password)

    while True:
        print("\nPassword Manager")
        print("1. Add a password")
        print("2. Retrieve a password")
        print("3. List stored services")
        print("4. Exit")
        choice = input("Please choose an option: ")

        if choice == "1":
            service = input("Enter the service name: ")
            password = getpass("Enter the password: ")
            add_password(key, service, password)
        elif choice == "2":
            service = input("Enter the service name: ")
            retrieve_password(key, service)
        elif choice == "3":
            list_services()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
