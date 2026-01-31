#!/usr/bin/env python3
"""
X1 Encrypted Chat - Receive Messages

Listen for and decrypt incoming messages via X1 Chat.
"""

import os
import sys
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
    response = requests.get(f"{API_BASE}/api/keys/{address}")
    if response.ok:
        data = response.json()
        return base58.b58decode(data['x25519PublicKey'])
    return None


def listen_sse(wallet: str, our_private: bytes):
    """Listen to SSE stream for incoming messages"""
    import sseclient
    
    url = f"{API_BASE}/api/stream/{wallet}?since=0"
    print(f"→ Connecting to SSE stream...")
    
    response = requests.get(url, stream=True, headers={'Accept': 'text/event-stream'})
    client = sseclient.SSEClient(response)
    
    key_cache = {}
    
    for event in client.events():
        if event.data:
            import json
            try:
                data = json.loads(event.data)
                if data.get('type') == 'message':
                    msg = data.get('message', {})
                    sender = msg.get('from')
                    
                    if sender == wallet:
                        continue  # Skip our own messages
                    
                    # Get sender's public key
                    if sender not in key_cache:
                        their_public = lookup_public_key(sender)
                        if their_public:
                            key_cache[sender] = compute_shared_secret(our_private, their_public)
                    
                    if sender in key_cache:
                        nonce = base58.b58decode(msg['nonce'])
                        ciphertext = base58.b58decode(msg['ciphertext'])
                        plaintext = decrypt_message(key_cache[sender], nonce, ciphertext)
                        content = plaintext.decode('utf-8')
                        print(f"\n📨 From {sender[:8]}...{sender[-4:]}:")
                        print(f"   {content}")
            except Exception as e:
                pass


def poll_messages(wallet: str, our_private: bytes, contact: str = None):
    """One-shot poll for recent messages"""
    print(f"→ Polling for messages...")
    
    # Use SSE with a short timeout to get recent messages
    url = f"{API_BASE}/api/stream/{wallet}?since=0"
    
    try:
        response = requests.get(url, stream=True, headers={'Accept': 'text/event-stream'}, timeout=3)
        
        key_cache = {}
        messages = []
        
        for line in response.iter_lines(decode_unicode=True):
            if line and line.startswith('data:'):
                import json
                try:
                    data = json.loads(line[5:].strip())
                    if data.get('type') == 'message':
                        msg = data.get('message', {})
                        sender = msg.get('from')
                        
                        if contact and sender != contact:
                            continue
                        
                        if sender == wallet:
                            direction = "→ Sent"
                        else:
                            direction = "← Received"
                            
                            # Get sender's public key for decryption
                            if sender not in key_cache:
                                their_public = lookup_public_key(sender)
                                if their_public:
                                    key_cache[sender] = compute_shared_secret(our_private, their_public)
                        
                        if sender != wallet and sender in key_cache:
                            nonce = base58.b58decode(msg['nonce'])
                            ciphertext = base58.b58decode(msg['ciphertext'])
                            plaintext = decrypt_message(key_cache[sender], nonce, ciphertext)
                            content = plaintext.decode('utf-8')
                            messages.append((direction, sender, content, msg.get('timestamp')))
                        elif sender == wallet:
                            # Can't decrypt our own messages without recipient's key context
                            messages.append((direction, msg.get('to'), "(sent message)", msg.get('timestamp')))
                except:
                    pass
    except requests.exceptions.Timeout:
        pass
    except Exception as e:
        print(f"Error: {e}")
    
    return messages


def main():
    print(f"◎ X1 Encrypted Chat - Receive Messages\n")
    
    signing_key, address = load_wallet()
    print(f"✓ Wallet: {address}")
    
    initial_sig = sign_message(signing_key, SIGN_MESSAGE)
    our_private, our_public = derive_x25519_keypair(initial_sig)
    
    contact = sys.argv[1] if len(sys.argv) > 1 else None
    if contact:
        print(f"→ Filtering for: {contact}")
    
    messages = poll_messages(address, our_private, contact)
    
    if messages:
        print(f"\n{'='*50}")
        for direction, addr, content, ts in messages:
            short_addr = f"{addr[:8]}...{addr[-4:]}" if addr else "unknown"
            print(f"{direction} [{short_addr}]: {content}")
        print(f"{'='*50}")
    else:
        print("No messages found")


if __name__ == '__main__':
    main()
