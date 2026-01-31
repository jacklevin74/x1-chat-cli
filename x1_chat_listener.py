#!/usr/bin/env python3
"""
X1 Encrypted Chat - SSE Listener Service

Continuously listens for incoming messages and prints them in real-time.
Can be run as a background service.
"""

import os
import sys
import json
import hashlib
import hmac
import requests
from nacl.signing import SigningKey
from nacl.public import PrivateKey as X25519PrivateKey
from nacl.bindings import crypto_scalarmult
import base58
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Config
API_BASE = "https://staging-vero.x1.xyz/xchat"
DOMAIN_SEPARATOR = "x1-msg-v1"
SIGN_MESSAGE = "X1 Encrypted Messaging - Sign to generate your encryption keys"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
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
    private_key_b58 = os.environ.get('SOLANA_PRIVATE_KEY')
    if not private_key_b58:
        # Try loading from .env in script directory
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if line.startswith('SOLANA_PRIVATE_KEY='):
                        private_key_b58 = line.split('=', 1)[1].strip()
                        break
        # Also try skills directory
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
    return signing_key.sign(message.encode('utf-8')).signature


def derive_x25519_keypair(signature: bytes) -> tuple:
    info = (DOMAIN_SEPARATOR + '-x25519').encode('utf-8')
    private_key_bytes = hkdf_sha256(signature, b'', info, 32)
    private_key = X25519PrivateKey(private_key_bytes)
    public_key = private_key.public_key
    return private_key_bytes, bytes(public_key)


def compute_shared_secret(our_private: bytes, their_public: bytes) -> bytes:
    shared = crypto_scalarmult(our_private, their_public)
    info = (DOMAIN_SEPARATOR + '-session').encode('utf-8')
    return hkdf_sha256(shared, b'', info, 32)


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def lookup_public_key(address: str) -> bytes | None:
    try:
        response = requests.get(f"{API_BASE}/api/keys/{address}", timeout=10)
        if response.ok:
            data = response.json()
            return base58.b58decode(data['x25519PublicKey'])
    except:
        pass
    return None


def listen_sse(wallet: str, our_private: bytes, callback=None):
    """Listen to SSE stream for incoming messages"""
    
    url = f"{API_BASE}/api/stream/{wallet}?since=0"
    print(f"🔊 Listening for messages on {wallet[:8]}...{wallet[-4:]}")
    print(f"   Press Ctrl+C to stop\n")
    
    key_cache = {}
    seen_ids = set()
    
    while True:
        try:
            response = requests.get(url, stream=True, headers={'Accept': 'text/event-stream'}, timeout=30)
            
            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith('data:'):
                    try:
                        data = json.loads(line[5:].strip())
                        
                        if data.get('type') == 'message':
                            msg = data.get('message', {})
                            msg_id = msg.get('id')
                            
                            # Skip already seen messages
                            if msg_id in seen_ids:
                                continue
                            seen_ids.add(msg_id)
                            
                            sender = msg.get('from')
                            
                            # Skip our own messages
                            if sender == wallet:
                                continue
                            
                            # Get sender's public key for decryption
                            if sender not in key_cache:
                                their_public = lookup_public_key(sender)
                                if their_public:
                                    key_cache[sender] = compute_shared_secret(our_private, their_public)
                            
                            if sender in key_cache:
                                try:
                                    nonce = base58.b58decode(msg['nonce'])
                                    ciphertext = base58.b58decode(msg['ciphertext'])
                                    plaintext = decrypt_message(key_cache[sender], nonce, ciphertext)
                                    content = plaintext.decode('utf-8')
                                    
                                    short_addr = f"{sender[:8]}...{sender[-4:]}"
                                    timestamp = msg.get('timestamp', '')
                                    
                                    print(f"📨 [{short_addr}]: {content}")
                                    
                                    # Call callback if provided
                                    if callback:
                                        callback(sender, content, msg)
                                        
                                except Exception as e:
                                    print(f"⚠️ Failed to decrypt message from {sender[:8]}...: {e}")
                                    
                    except json.JSONDecodeError:
                        pass
                        
        except requests.exceptions.Timeout:
            print("⟳ Reconnecting...")
            continue
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Connection error: {e}")
            import time
            time.sleep(5)
            print("⟳ Reconnecting...")
            continue
        except KeyboardInterrupt:
            print("\n👋 Listener stopped")
            break


def main():
    import sys
    print("◎ X1 Encrypted Chat - SSE Listener\n", flush=True)
    
    # Load wallet and derive keys
    signing_key, address = load_wallet()
    print(f"✓ Wallet: {address}", flush=True)
    
    initial_sig = sign_message(signing_key, SIGN_MESSAGE)
    our_private, our_public = derive_x25519_keypair(initial_sig)
    print(f"✓ Keys derived\n")
    
    # Start listening
    listen_sse(address, our_private)


if __name__ == '__main__':
    main()
