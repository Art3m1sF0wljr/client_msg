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

def get_recipient_public_key(recipient_phone):
    log(f"[*] Requesting public key for {recipient_phone}", level=2)
    payload = {"phone_number": recipient_phone}
    log(f"[*] Sending payload: {payload}", level=2)
    response = requests.post(f"{BASE_URL}/get-public-key", json=payload)
    log(f"[*] Response status code: {response.status_code}", level=2)
    log(f"[*] Response content: {response.text}", level=2)
    if response.status_code == 200:
        try:
            return RSA.import_key(response.json()["public_key"])
        except (KeyError, ValueError) as e:
            log(f"[!] Error importing public key: {e}", level=1)
            return None
    else:
        target = recipient_phone if recipient_phone else "server"
        log(f"[!] Public key not found for {target}.", level=1)
        return None
		
def get_server_public_key():
    try:
        response = requests.get(f"{BASE_URL}/get-public-key")  # No phone_number argument
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
        "phone_number": b64encode(phone_number.encode()).decode(),
        "encrypted_response": b64encode(encrypted_response).decode(),
        "signature": b64encode(signature).decode(),
        "hash": response_hash
    }

    log("[*] Sending challenge response...", level=2)
    verify_response = requests.post(f"{BASE_URL}/verify", json=payload)
    if verify_response.status_code == 200:
        response_data = verify_response.json()
        log(f"[✔] Authentication successful for {phone_number}.", level=1)
        if response_data.get("undelivered_count", 0) > 0:
            log(f"[📩] You have {response_data['undelivered_count']} new messages.", level=1)
        return True
    else:
        log(f"[!] Authentication failed: {verify_response.text}", level=1)
        return False

# === Messaging (Send/Receive) ===
def send_message(sender_phone, recipient_phone, message, private_key):
    log(f"[*] Sending message from {sender_phone} to {recipient_phone}...", level=2)

    # Get the recipient's public key
    recipient_public_key = get_recipient_public_key(recipient_phone)
    if not recipient_public_key:
        log(f"[!] Recipient public key not found for {recipient_phone}.", level=1)
        return

    # Encrypt the message using the recipient's public key
    cipher = PKCS1_OAEP.new(recipient_public_key)
    encrypted_message = cipher.encrypt(message.encode())

    # Log the encrypted message and its hash
    log(f"[*] Encrypted message: {b64encode(encrypted_message).decode()}", level=2)
    log(f"[*] Computed hash: {hash_data(encrypted_message)}", level=2)

    # Sign the encrypted message using the sender's private key
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
            # Unpack the tuple
            sender, encrypted_message, signature, msg_hash = msg

            # Decode Base64 fields
            encrypted_message = b64decode(encrypted_message)
            signature = b64decode(signature)

            # Verify message integrity
            computed_hash = hash_data(encrypted_message)
            if msg_hash != computed_hash:
                log("[!] Message hash mismatch. Possible tampering!", level=1)
                continue

            # Verify signature
            sender_public_key = get_recipient_public_key(sender)
            if not sender_public_key:
                log(f"[!] Sender public key not found for {sender}.", level=1)
                continue

            try:
                pkcs1_15.new(sender_public_key).verify(SHA256.new(encrypted_message), signature)
                log("[✔] Message signature verified.", level=2)
            except (ValueError, TypeError):
                log("[!] Signature verification failed.", level=1)
                continue

            # Decrypt message using the recipient's private key
            cipher = PKCS1_OAEP.new(private_key)
            try:
                decrypted_message = cipher.decrypt(encrypted_message).decode()
                log(f"[📩] New message from {sender}: {decrypted_message}", level=1)
            except Exception as e:
                log(f"[!] Decryption failed: {e}", level=1)
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
