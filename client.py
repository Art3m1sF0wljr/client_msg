import requests
import json
import os
import time
import sys
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from websocket import create_connection

# === Configuration ===
SERVER_IP_URL = "enlighttheworld.altervista.org/ip/ip.txt"  # Placeholder for actual server IP source
SERVER_PORT = 5002
LOCAL_DATA_FILE = "client_data.json"

# Verbosity level (default is 0, for no verbosity)
VERBOSITY_LEVEL = 0

def set_verbosity_level():
    global VERBOSITY_LEVEL
    if len(sys.argv) > 1 and sys.argv[1] == "-v":
        VERBOSITY_LEVEL = 1
    if len(sys.argv) > 2 and sys.argv[2] == "-v":
        VERBOSITY_LEVEL = 2

# === Logging Function ===
def log(message, level=1):
    """Logs messages based on verbosity level"""
    if VERBOSITY_LEVEL >= level:
        print(message)

# === RSA Key Management ===
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def load_keys():
    if os.path.exists(LOCAL_DATA_FILE):
        with open(LOCAL_DATA_FILE, "r") as file:
            data = json.load(file)
        return data["phone_number"], RSA.import_key(data["private_key"]), RSA.import_key(data["public_key"])
    return None, None, None

def save_keys(phone_number, private_key, public_key):
    data = {
        "phone_number": phone_number,
        "private_key": private_key.decode(),
        "public_key": public_key.decode()
    }
    with open(LOCAL_DATA_FILE, "w") as file:
        json.dump(data, file)

# === Server Communication ===
def get_server_ip():
    try:
        response = requests.get(SERVER_IP_URL)
        return response.text.strip()
    except:
        return "127.0.0.1"  # Fallback for local testing

SERVER_IP = get_server_ip()
BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

# === Registration ===
def register(phone_number):
    private_key, public_key = generate_rsa_keypair()
    payload = {
        "phone_number": phone_number,
        "public_key": public_key.decode()
    }
    log(f"[*] Registering with phone number {phone_number}", level=2)
    response = requests.post(f"{BASE_URL}/register", json=payload)
    if response.status_code == 200:
        save_keys(phone_number, private_key, public_key)
        log(f"[✔] Registration successful for {phone_number}.", level=1)
    else:
        log(f"[!] Registration failed: {response.json()['message']}", level=1)

# === Login (Challenge-Response Authentication) ===
def login(phone_number, private_key, public_key):
    log(f"[*] Attempting login for {phone_number}...", level=2)
    response = requests.post(f"{BASE_URL}/login", json={"phone_number": phone_number})
    if response.status_code != 200:
        log(f"[!] Login failed: {response.json()['message']}", level=1)
        return False

    data = response.json()
    encrypted_challenge = b64decode(data["challenge"])
    server_signature = b64decode(data["signature"])

    # Verify server's signature
    h = SHA256.new(encrypted_challenge)
    try:
        pkcs1_15.new(SERVER_PUBLIC_KEY).verify(h, server_signature)
        log("[✔] Server signature verified.", level=2)
    except (ValueError, TypeError):
        log("[!] Server signature verification failed.", level=1)
        return False

    # Decrypt challenge
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_challenge = cipher.decrypt(encrypted_challenge)

    # Re-encrypt the challenge with the server's public key
    cipher_server = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
    encrypted_response = cipher_server.encrypt(decrypted_challenge)

    # Sign the response
    h_response = SHA256.new(decrypted_challenge)
    signature = pkcs1_15.new(private_key).sign(h_response)

    # Send response back to the server
    verify_payload = {
        "phone_number": phone_number,
        "encrypted_response": b64encode(encrypted_response).decode(),
        "signature": b64encode(signature).decode()
    }

    verify_response = requests.post(f"{BASE_URL}/verify", json=verify_payload)
    if verify_response.status_code == 200:
        log(f"[✔] Authentication successful for {phone_number}.", level=1)
        return True
    else:
        log(f"[!] Authentication failed: {verify_response.json()['message']}", level=1)
        return False

# === Messaging ===
def get_recipient_public_key(recipient_phone):
    log(f"[*] Requesting public key for {recipient_phone}", level=2)
    response = requests.post(f"{BASE_URL}/get-public-key", json={"phone_number": recipient_phone})
    if response.status_code == 200:
        return RSA.import_key(response.json()["public_key"])
    else:
        log(f"[!] Recipient public key not found for {recipient_phone}.", level=1)
        return None

def send_message(sender_phone, recipient_phone, message, private_key):
    recipient_public_key = get_recipient_public_key(recipient_phone)
    if not recipient_public_key:
        return

    # Encrypt the message
    cipher = PKCS1_OAEP.new(recipient_public_key)
    encrypted_message = cipher.encrypt(message.encode())

    # Sign the message
    h = SHA256.new(encrypted_message)
    signature = pkcs1_15.new(private_key).sign(h)

    payload = {
        "sender_phone": sender_phone,
        "recipient_phone": recipient_phone,
        "encrypted_message": b64encode(encrypted_message).decode(),
        "signature": b64encode(signature).decode()
    }

    log(f"[*] Sending message to {recipient_phone}", level=2)
    response = requests.post(f"{BASE_URL}/send-message", json=payload)
    if response.status_code == 200:
        log("[✔] Message sent successfully.", level=1)
    else:
        log(f"[!] Failed to send message: {response.json()['message']}", level=1)

# === Receiving Messages ===
def receive_messages(phone_number, private_key):
    log("[*] Checking for new messages...", level=2)
    response = requests.post(f"{BASE_URL}/get-messages", json={"phone_number": phone_number})
    if response.status_code == 200:
        messages = response.json().get("messages", [])
        for sender, encrypted_message, signature in messages:
            encrypted_message = b64decode(encrypted_message)
            signature = b64decode(signature)

            # Verify message signature
            sender_public_key = get_recipient_public_key(sender)
            h = SHA256.new(encrypted_message)
            try:
                pkcs1_15.new(sender_public_key).verify(h, signature)
                log(f"[✔] Message from {sender} verified.", level=2)
            except (ValueError, TypeError):
                log(f"[!] Message from {sender} failed verification.", level=1)
                continue

            # Decrypt the message
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_message = cipher.decrypt(encrypted_message)
            log(f"[📩] Message from {sender}: {decrypted_message.decode()}", level=1)

# === Main Client Workflow ===
def main():
    set_verbosity_level()

    phone_number, private_key, public_key = load_keys()

    if not phone_number:
        phone_number = input("Enter your phone number: ")
        register(phone_number)
        phone_number, private_key, public_key = load_keys()

    if login(phone_number, private_key, public_key):
        while True:
            print("\n1. Send Message\n2. Check Messages\n3. Exit")
            choice = input("Choose an option: ")

            if choice == "1":
                recipient = input("Recipient's phone number: ")
                message = input("Message: ")
                send_message(phone_number, recipient, message, private_key)
            elif choice == "2":
                receive_messages(phone_number, private_key)
            elif choice == "3":
                break
            else:
                log("[!] Invalid choice.", level=1)

if __name__ == "__main__":
    main()
