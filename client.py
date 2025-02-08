import requests
import json
import os
import time
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from websocket import create_connection

# === Configuration ===
SERVER_IP_URL = "http://enlighttheworld.altervista.org/ip/ip.txt"  # Placeholder for actual server IP source
SERVER_PORT = 81
LOCAL_DATA_FILE = "client_data.json"

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
    response = requests.post(f"{BASE_URL}/register", json=payload)
    if response.status_code == 200:
        save_keys(phone_number, private_key, public_key)
        print("[✔] Registration successful.")
    else:
        print("[!] Registration failed:", response.json()["message"])

# === Login (Challenge-Response Authentication) ===
def login(phone_number, private_key, public_key):
    print("[*] Attempting login...")
    response = requests.post(f"{BASE_URL}/login", json={"phone_number": phone_number})
    if response.status_code != 200:
        print("[!] Login failed:", response.json()["message"])
        return False

    data = response.json()
    encrypted_challenge = b64decode(data["challenge"])
    server_signature = b64decode(data["signature"])

    # Verify server's signature
    h = SHA256.new(encrypted_challenge)
    try:
        pkcs1_15.new(SERVER_PUBLIC_KEY).verify(h, server_signature)
    except (ValueError, TypeError):
        print("[!] Server signature verification failed.")
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
        print("[✔] Authentication successful!")
        return True
    else:
        print("[!] Authentication failed:", verify_response.json()["message"])
        return False

# === Messaging ===
def get_recipient_public_key(recipient_phone):
    response = requests.post(f"{BASE_URL}/get-public-key", json={"phone_number": recipient_phone})
    if response.status_code == 200:
        return RSA.import_key(response.json()["public_key"])
    else:
        print("[!] Recipient public key not found.")
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

    response = requests.post(f"{BASE_URL}/send-message", json=payload)
    if response.status_code == 200:
        print("[✔] Message sent successfully.")
    else:
        print("[!] Failed to send message.")

# === Receiving Messages ===
def receive_messages(phone_number, private_key):
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
                print(f"[✔] Message from {sender} verified.")
            except (ValueError, TypeError):
                print(f"[!] Message from {sender} failed verification.")
                continue

            # Decrypt the message
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_message = cipher.decrypt(encrypted_message)
            print(f"[📩] Message from {sender}: {decrypted_message.decode()}")

# === Main Client Workflow ===
def main():
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
                print("[!] Invalid choice.")

if __name__ == "__main__":
    main()
