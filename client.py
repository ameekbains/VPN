import os
import socket
import select
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VPNClient:
    def __init__(self, server_ip):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.server_ip = server_ip
        self.tun = self.create_tun_interface()
        
    def create_tun_interface(self):
        # ... (Same TUN creation as before) ...
        os.system('ip addr add 10.8.0.2/24 dev tun0')
        return tun

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'INIT', (self.server_ip, 1194))
        
        # Receive server public key
        server_pub = x25519.X25519PublicKey.from_public_bytes(sock.recv(32))
        shared_key = self.private_key.exchange(server_pub)
        
        # Derive keys
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'vpn-key')
        aes_key = hkdf.derive(shared_key)
        aesgcm = AESGCM(aes_key)
        
        while True:
            ready, _, _ = select.select([self.tun, sock], [], [])
            for fd in ready:
                if fd == self.tun:
                    data = os.read(self.tun, 1500)
                    nonce = os.urandom(12)
                    ciphertext = aesgcm.encrypt(nonce, data, None)
                    sock.sendto(nonce + ciphertext, (self.server_ip, 1194))
                else:
                    data = sock.recv(2048)
                    nonce, ciphertext = data[:12], data[12:]
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    os.write(self.tun, plaintext)

if __name__ == "__main__":
    client = VPNClient('SERVER_IP')
    client.connect()
