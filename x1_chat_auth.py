#!/usr/bin/env python3
"""
X1 Encrypted Chat - CLI Authentication

Authenticate with X1 Encrypted Chat using a Solana wallet from the command line.
Bypasses browser wallet extensions by signing messages directly.

Usage:
    export SOLANA_PRIVATE_KEY="your_base58_private_key"
    python x1_chat_auth.py
"""

import os
import sys
import json
import hashlib
import hmac
import requests
from nacl.signing import SigningKey
from nacl.public import PrivateKey as X25519PrivateKey
import base58

# Config
API_BASE = "https://staging-vero.x1.xyz/xchat"
DOMAIN_SEPARATOR = "x1-msg-v1"
SIGN_MESSAGE = "X1 Encrypted Messaging - Sign to generate your encryption keys"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 key derivation (RFC 5869)"""
    if not salt:
        salt = b'\x00' * 32
    
    # Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    
    # Expand
    t = b''
    okm = b''
    for i in range(1, (length // 32) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    
    return okm[:length]


def load_wallet(private_key_b58: str = None):
    """Load Solana wallet from environment or argument"""
    if not private_key_b58:
        private_key_b58 = os.environ.get('SOLANA_PRIVATE_KEY')
    
    if not private_key_b58:
        raise ValueError("SOLANA_PRIVATE_KEY not set. Export it or pass as argument.")
    
    private_key_bytes = base58.b58decode(private_key_b58)
    # Solana keypair is 64 bytes: first 32 are seed, last 32 are public key
    signing_key = SigningKey(private_key_bytes[:32])
    public_key = signing_key.verify_key
    address = base58.b58encode(bytes(public_key)).decode()
    
    return signing_key, address


def sign_message(signing_key: SigningKey, message: str) -> bytes:
    """Sign a message and return the signature"""
    message_bytes = message.encode('utf-8')
    signed = signing_key.sign(message_bytes)
    return signed.signature


def derive_x25519_keypair(signature: bytes) -> tuple:
    """Derive X25519 keypair from signature using HKDF (matches browser implementation)"""
    info = (DOMAIN_SEPARATOR + '-x25519').encode('utf-8')
    private_key_bytes = hkdf_sha256(signature, b'', info, 32)
    
    # Create X25519 private key and derive public key
    private_key = X25519PrivateKey(private_key_bytes)
    public_key = private_key.public_key
    
    return private_key_bytes, bytes(public_key)


def register_key(address: str, x25519_public_key: bytes, signing_key: SigningKey) -> requests.Response:
    """Register X25519 public key with the X1 Chat server"""
    public_key_b58 = base58.b58encode(x25519_public_key).decode()
    
    # Sign registration message
    reg_message = f"X1 Messaging: Register encryption key {public_key_b58}"
    signature = sign_message(signing_key, reg_message)
    signature_b58 = base58.b58encode(signature).decode()
    
    # POST to API
    response = requests.post(
        f"{API_BASE}/api/keys",
        json={
            "address": address,
            "x25519PublicKey": public_key_b58,
            "signature": signature_b58
        }
    )
    
    return response


def check_existing_key(address: str) -> dict | None:
    """Check if wallet already has a registered key"""
    response = requests.get(f"{API_BASE}/api/keys/{address}")
    if response.ok:
        return response.json()
    return None


def authenticate(private_key_b58: str = None, force: bool = False) -> dict:
    """
    Authenticate with X1 Chat and return credentials.
    
    Args:
        private_key_b58: Base58-encoded Solana private key (or set SOLANA_PRIVATE_KEY env)
        force: Re-register even if already registered
    
    Returns:
        dict with address, x25519PublicKey, signature (for caching)
    """
    # Load wallet
    signing_key, address = load_wallet(private_key_b58)
    
    # Check existing registration
    if not force:
        existing = check_existing_key(address)
        if existing:
            return {
                "address": address,
                "x25519PublicKey": existing.get("x25519PublicKey"),
                "already_registered": True
            }
    
    # Sign initial message to derive keys
    initial_signature = sign_message(signing_key, SIGN_MESSAGE)
    
    # Derive X25519 keypair
    x25519_private, x25519_public = derive_x25519_keypair(initial_signature)
    x25519_public_b58 = base58.b58encode(x25519_public).decode()
    
    # Register with server
    response = register_key(address, x25519_public, signing_key)
    
    if response.ok:
        return {
            "address": address,
            "x25519PublicKey": x25519_public_b58,
            "signature": base58.b58encode(initial_signature).decode(),
            "already_registered": False
        }
    else:
        raise Exception(f"Registration failed: {response.status_code} - {response.text}")


def main():
    print("◎ X1 Encrypted Chat CLI Authentication\n")
    
    # Load wallet
    try:
        signing_key, address = load_wallet()
        print(f"✓ Wallet: {address}")
    except Exception as e:
        print(f"✗ Failed to load wallet: {e}")
        sys.exit(1)
    
    # Check existing registration
    existing = check_existing_key(address)
    if existing:
        print(f"✓ Already registered!")
        print(f"  Address: {address}")
        print(f"  X25519 Key: {existing.get('x25519PublicKey')}")
        return
    
    # Sign initial message to derive keys
    print(f"\n→ Signing: {SIGN_MESSAGE}")
    initial_signature = sign_message(signing_key, SIGN_MESSAGE)
    print(f"✓ Signature: {base58.b58encode(initial_signature).decode()[:20]}...")
    
    # Derive X25519 keypair
    x25519_private, x25519_public = derive_x25519_keypair(initial_signature)
    x25519_public_b58 = base58.b58encode(x25519_public).decode()
    print(f"✓ X25519 Public Key: {x25519_public_b58[:20]}...")
    
    # Register with server
    print(f"\n→ Registering key with X1 Chat...")
    response = register_key(address, x25519_public, signing_key)
    
    if response.ok:
        print(f"✓ Successfully registered!")
        print(f"\n  Address: {address}")
        print(f"  X25519 Key: {x25519_public_b58}")
    else:
        print(f"✗ Registration failed: {response.status_code}")
        print(f"  Response: {response.text}")
        sys.exit(1)


if __name__ == '__main__':
    main()
