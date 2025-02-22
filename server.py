import os
import socket
import select
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VPNServer:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.clients = {}
        self.tun = self.create_tun_interface()

    def create_tun_interface(self):
        # ... (Same TUN creation as before) ...
        os.system('ip link set tun0 up')
        os.system('ip addr add 10.8.0.1/24 dev tun0')
        return tun

    def handle_client(self, sock):
        # Key exchange and session setup
        peer_public = x25519.X25519PublicKey.from_public_bytes(sock.recv(32))
        shared_key = self.private_key.exchange(peer_public)
        
        # Derive encryption keys
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'vpn-key')
        aes_key = hkdf.derive(shared_key)
        
        session = {
            'aesgcm': AESGCM(aes_key),
            'addr': None
        }
        
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                session['addr'] = addr
                nonce, ciphertext = data[:12], data[12:]
                plaintext = session['aesgcm'].decrypt(nonce, ciphertext, None)
                os.write(self.tun, plaintext)
            except Exception as e:
                print(f"Decryption error: {e}")
                break

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 1194))
        
        print(f"Server public key: {self.public_key.public_bytes_raw().hex()}")
        
        while True:
            data, addr = sock.recvfrom(256)
            if data == b'INIT':
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_sock.connect(addr)
                threading.Thread(target=self.handle_client, args=(client_sock,)).start()

if __name__ == "__main__":
    VPNServer().run()
