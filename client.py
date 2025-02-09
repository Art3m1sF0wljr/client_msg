import requests
import json
import os
import sys
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# === Configuration ===
SERVER_IP_URL = "https://enlighttheworld.altervista.org/ip/ip.txt"
SERVER_PORT = 21
LOCAL_DATA_FILE = "client_data.json"

# Verbosity Level
VERBOSITY_LEVEL = 0

def set_verbosity_level():
    global VERBOSITY_LEVEL
    if "-v" in sys.argv:
        VERBOSITY_LEVEL = sys.argv.count("-v")

def log(message, level=1):
    if VERBOSITY_LEVEL >= level:
        print(message)

# === RSA Key Management ===
def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

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
        return "127.0.0.1"

SERVER_IP = get_server_ip()
BASE_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

def get_server_public_key():
    try:
        response = requests.get(f"{BASE_URL}/get-public-key")
        if response.status_code == 200:
            return RSA.import_key(response.json()["public_key"])
        else:
            log("[!] Failed to retrieve server's public key.", level=1)
            return None
    except Exception as e:
        log(f"[!] Error retrieving server's public key: {e}", level=1)
        return None

SERVER_PUBLIC_KEY = get_server_public_key()
if SERVER_PUBLIC_KEY is None:
    log("[!] Could not retrieve the server's public key. Exiting.", level=1)
    sys.exit(1)

# === Helper Functions ===
def hash_data(data):
    """Returns SHA-256 hash of the provided data."""
    if isinstance(data, str):
        data = data.encode()  # Encode only if the data is a string
    h = SHA256.new(data)
    return b64encode(h.digest()).decode()

# === Registration ===
def register(phone_number):
    private_key, public_key = generate_rsa_keypair()

    # Encrypt phone number using server’s public key (only once)
    cipher_server = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
    encrypted_phone = cipher_server.encrypt(phone_number.encode())

    # Hash for integrity
    message_hash = hash_data(encrypted_phone)

    payload = {
        "public_key": public_key.decode(),
        "encrypted_phone": b64encode(encrypted_phone).decode(),
        "hash": message_hash
    }

    log("[*] Sending registration data...", level=2)
    response = requests.post(f"{BASE_URL}/register", json=payload)
    if response.status_code == 200:
        save_keys(phone_number, private_key, public_key)
        log(f"[✔] Registration successful for {phone_number}.", level=1)
    else:
        log(f"[!] Registration failed: {response.text}", level=1)

# === Login (Challenge-Response) ===
def login(phone_number, private_key):
    log(f"[*] Attempting login for {phone_number}...", level=2)

    # Encrypt phone number using server’s public key (only once)
    cipher_server = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
    encrypted_phone = cipher_server.encrypt(phone_number.encode())

    payload = {
        "phone_number": b64encode(encrypted_phone).decode(),
        "hash": hash_data(encrypted_phone)
    }

    response = requests.post(f"{BASE_URL}/login", json=payload)
    if response.status_code != 200:
        log(f"[!] Login failed: {response.json().get('message', 'Unknown error')}", level=1)
        return False

    data = response.json()
    encrypted_challenge = b64decode(data["challenge"])
    received_hash = data.get("hash")

    # Verify challenge integrity
    if received_hash != hash_data(encrypted_challenge):
        log("[!] Challenge hash mismatch! Possible tampering detected.", level=1)
        return False

    # Decrypt challenge with client’s private key
    cipher_client = PKCS1_OAEP.new(private_key)
    decrypted_challenge = cipher_client.decrypt(encrypted_challenge)

    # Re-encrypt with server’s public key
    encrypted_response = cipher_server.encrypt(decrypted_challenge)

    # Sign the decrypted challenge
    hash_challenge = SHA256.new(decrypted_challenge)
    signature = pkcs1_15.new(private_key).sign(hash_challenge)

    # Add hash for integrity check
    response_hash = hash_data(encrypted_response)

    payload = {
		"phone_number": b64encode(phone_number.encode()).decode(),  # Base64-encode the phone number
		"encrypted_response": b64encode(encrypted_response).decode(),
		"signature": b64encode(signature).decode(),
		"hash": response_hash
	}

    log("[*] Sending challenge response...", level=2)
    verify_response = requests.post(f"{BASE_URL}/verify", json=payload)
    if verify_response.status_code == 200:
        log(f"[✔] Authentication successful for {phone_number}.", level=1)
        return True
    else:
        log(f"[!] Authentication failed: {verify_response.text}", level=1)
        return False

# === Messaging (Send/Receive) ===
def send_message(sender_phone, recipient_phone, message, private_key):
    log(f"[*] Sending message from {sender_phone} to {recipient_phone}...", level=2)

    # Encrypt the message
    cipher = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
    encrypted_message = cipher.encrypt(message.encode())

    # Log the encrypted message and its hash
    log(f"[*] Encrypted message: {b64encode(encrypted_message).decode()}", level=2)
    log(f"[*] Computed hash: {hash_data(encrypted_message)}", level=2)

    # Sign the encrypted message
    message_hash = SHA256.new(encrypted_message)
    signature = pkcs1_15.new(private_key).sign(message_hash)

    payload = {
        "sender_phone": b64encode(sender_phone.encode()).decode(),
        "recipient_phone": b64encode(recipient_phone.encode()).decode(),
        "encrypted_message": b64encode(encrypted_message).decode(),
        "signature": b64encode(signature).decode(),
        "hash": hash_data(encrypted_message)
    }

    response = requests.post(f"{BASE_URL}/send-message", json=payload)
    if response.status_code == 200:
        log("[✔] Message sent successfully.", level=1)
    else:
        log(f"[!] Failed to send message: {response.text}", level=1)

def receive_messages(phone_number, private_key):
    log("[*] Checking for new messages...", level=2)
    response = requests.post(f"{BASE_URL}/get-messages", json={"phone_number": phone_number})

    if response.status_code == 200:
        messages = response.json().get("messages", [])
        for msg in messages:
            encrypted_message = b64decode(msg["encrypted_message"])
            signature = b64decode(msg["signature"])
            received_hash = msg.get("hash")

            # Verify message integrity
            if received_hash != hash_data(encrypted_message):
                log("[!] Message hash mismatch. Possible tampering!", level=1)
                continue

            # Verify signature
            try:
                pkcs1_15.new(SERVER_PUBLIC_KEY).verify(SHA256.new(encrypted_message), signature)
                log("[✔] Message signature verified.", level=2)
            except (ValueError, TypeError):
                log("[!] Signature verification failed.", level=1)
                continue

            # Decrypt message
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_message = cipher.decrypt(encrypted_message)
            log(f"[📩] New message: {decrypted_message.decode()}", level=1)
    else:
        log(f"[!] Failed to retrieve messages: {response.text}", level=1)

# === Main Client Workflow ===
def main():
    set_verbosity_level()
    phone_number, private_key, public_key = load_keys()

    if not phone_number:
        phone_number = input("Enter your phone number: ")
        register(phone_number)
        phone_number, private_key, public_key = load_keys()

    if login(phone_number, private_key):
        log("[✔] You are now logged in.", level=1)

        while True:
            print("\n1. Send Message\n2. Check Messages\n3. Exit")
            choice = input("Choose an option: ")

            if choice == "1":
                recipient = input("Recipient's phone number: ")
                message = input("Enter your message: ")
                send_message(phone_number, recipient, message, private_key)  # Pass phone_number as the sender
            elif choice == "2":
                receive_messages(phone_number, private_key)
            elif choice == "3":
                log("[*] Exiting application.", level=1)
                break
            else:
                log("[!] Invalid option selected.", level=1)
    else:
        log("[!] Login failed.", level=1)
		
if __name__ == "__main__":
    main()
