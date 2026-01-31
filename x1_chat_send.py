#!/usr/bin/env python3
"""
X1 Encrypted Chat - Send Messages

Send end-to-end encrypted messages via X1 Chat from the command line.
"""

import os
import sys
import json
import hashlib
import hmac
import secrets
import requests
from nacl.signing import SigningKey
from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey
from nacl.bindings import crypto_scalarmult
import base58
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Config
API_BASE = "https://staging-vero.x1.xyz/xchat"
DOMAIN_SEPARATOR = "x1-msg-v1"
SIGN_MESSAGE = "X1 Encrypted Messaging - Sign to generate your encryption keys"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 key derivation"""
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b''
    okm = b''
    for i in range(1, (length // 32) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def load_wallet():
    """Load Solana wallet from environment"""
    private_key_b58 = os.environ.get('SOLANA_PRIVATE_KEY')
    if not private_key_b58:
        env_path = os.path.join(os.path.dirname(__file__), '..', 'skills', 'solana-skills', '.env')
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.startswith('SOLANA_PRIVATE_KEY='):
                        private_key_b58 = line.split('=', 1)[1].strip()
                        break
    if not private_key_b58:
        raise ValueError("SOLANA_PRIVATE_KEY not set")
    
    private_key_bytes = base58.b58decode(private_key_b58)
    signing_key = SigningKey(private_key_bytes[:32])
    address = base58.b58encode(bytes(signing_key.verify_key)).decode()
    return signing_key, address


def sign_message(signing_key: SigningKey, message: str) -> bytes:
    """Sign a message"""
    return signing_key.sign(message.encode('utf-8')).signature


def derive_x25519_keypair(signature: bytes) -> tuple:
    """Derive X25519 keypair from signature"""
    info = (DOMAIN_SEPARATOR + '-x25519').encode('utf-8')
    private_key_bytes = hkdf_sha256(signature, b'', info, 32)
    private_key = X25519PrivateKey(private_key_bytes)
    public_key = private_key.public_key
    return private_key_bytes, bytes(public_key)


def compute_shared_secret(our_private: bytes, their_public: bytes) -> bytes:
    """Compute shared secret using X25519 + HKDF"""
    shared = crypto_scalarmult(our_private, their_public)
    info = (DOMAIN_SEPARATOR + '-session').encode('utf-8')
    return hkdf_sha256(shared, b'', info, 32)


def encrypt_message(key: bytes, plaintext: bytes) -> tuple:
    """Encrypt with AES-GCM"""
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def lookup_public_key(address: str) -> bytes | None:
    """Look up X25519 public key for an address"""
    response = requests.get(f"{API_BASE}/api/keys/{address}")
    if response.ok:
        data = response.json()
        return base58.b58decode(data['x25519PublicKey'])
    return None


def send_message(from_addr: str, to_addr: str, nonce: bytes, ciphertext: bytes) -> dict | None:
    """Send encrypted message to server"""
    response = requests.post(
        f"{API_BASE}/api/messages",
        json={
            "from": from_addr,
            "to": to_addr,
            "nonce": base58.b58encode(nonce).decode(),
            "ciphertext": base58.b58encode(ciphertext).decode()
        }
    )
    if response.ok:
        return response.json()
    print(f"Send failed: {response.status_code} - {response.text}")
    return None


def main():
    if len(sys.argv) < 3:
        print("Usage: python x1_chat_send.py <recipient_address> <message>")
        sys.exit(1)
    
    recipient = sys.argv[1]
    message = ' '.join(sys.argv[2:])
    
    print(f"◎ X1 Encrypted Chat - Send Message\n")
    
    # Load wallet and derive keys
    signing_key, address = load_wallet()
    print(f"✓ From: {address}")
    print(f"→ To: {recipient}")
    
    # Get our X25519 keys
    initial_sig = sign_message(signing_key, SIGN_MESSAGE)
    our_private, our_public = derive_x25519_keypair(initial_sig)
    
    # Look up recipient's public key
    their_public = lookup_public_key(recipient)
    if not their_public:
        print(f"✗ Recipient not registered on X1 Chat")
        sys.exit(1)
    print(f"✓ Recipient key found")
    
    # Compute shared secret
    shared_secret = compute_shared_secret(our_private, their_public)
    
    # Encrypt message
    plaintext = json.dumps({"text": message, "timestamp": int(__import__('time').time() * 1000)}).encode()
    nonce, ciphertext = encrypt_message(shared_secret, plaintext)
    print(f"✓ Message encrypted ({len(ciphertext)} bytes)")
    
    # Send
    result = send_message(address, recipient, nonce, ciphertext)
    if result:
        print(f"✓ Message sent! ID: {result.get('id', 'unknown')}")
        print(f"\n  Message: {message}")
    else:
        print(f"✗ Failed to send message")
        sys.exit(1)


if __name__ == '__main__':
    main()
