---
name: x1-chat
description: Send and receive end-to-end encrypted messages via X1 Chat using a Solana wallet. No browser or wallet extension required.
triggers:
  - x1 chat
  - x1 message
  - encrypted chat
  - xchat
  - x1 send
  - x1 receive
metadata:
  openclaw:
    requires:
      env:
        - SOLANA_PRIVATE_KEY
    primaryEnv: SOLANA_PRIVATE_KEY
---

# X1 Encrypted Chat 🔐

Send and receive end-to-end encrypted messages on X1 using a Solana wallet from the CLI.

## Setup

### 1. Install dependencies
```bash
cd {baseDir}
npm install          # For wallet generation
pip install -r requirements.txt  # For chat scripts
```

### 2. Generate a new wallet (or use existing)
```bash
# Generate new wallet
node {baseDir}/generate_wallet.js

# Or use existing key
export SOLANA_PRIVATE_KEY="your_base58_private_key"
```

The generator creates a `.env` file with your keys:
```bash
source {baseDir}/.env
```

### 3. Register with X1 Chat
```bash
python3 {baseDir}/x1_chat_auth.py
```

## Usage

### Send a message
```bash
python3 {baseDir}/x1_chat_send.py <recipient_wallet> "Your message here"
```

Example:
```bash
python3 {baseDir}/x1_chat_send.py 24xes13jk7aYc93dfUAWpbnpyx8QFi4FLDNEUpUjofSN "Hello from CLI!"
```

### Receive messages
```bash
# From all contacts
python3 {baseDir}/x1_chat_recv.py

# From specific contact
python3 {baseDir}/x1_chat_recv.py <sender_wallet>
```

### Check registration
```bash
curl -s https://staging-vero.x1.xyz/xchat/api/keys/<wallet_address> | jq .
```

## How It Works

X1 Chat uses wallet signatures to derive X25519 encryption keys:

1. **Authentication**: Sign a message with your Solana wallet
2. **Key Derivation**: HKDF-SHA256 derives X25519 keypair from signature
3. **Encryption**: Messages encrypted with AES-256-GCM using ECDH shared secret
4. **E2E**: Server only sees ciphertext - cannot read message content

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/xchat/api/keys/{address}` | GET | Look up wallet's encryption key |
| `/xchat/api/keys` | POST | Register encryption key |
| `/xchat/api/messages` | POST | Send encrypted message |
| `/xchat/api/stream/{address}` | GET | SSE stream for receiving messages |

## Python Library Usage

```python
from x1_chat_auth import authenticate
from x1_chat_send import send_encrypted_message

# Authenticate (registers if needed)
auth = authenticate()
print(f"Wallet: {auth['address']}")

# Send message
# (see x1_chat_send.py for full encryption flow)
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SOLANA_PRIVATE_KEY` | Base58-encoded Solana private key (required) |

## Security Notes

- Private keys never leave your machine
- Messages are end-to-end encrypted
- Server cannot decrypt message content
- Same wallet signature = same encryption keys (deterministic)

## Example Conversation

```
◎ X1 Encrypted Chat - Send Message

✓ From: 2jchoLFVoxmJUcygc2cDfAqQb1yWUEjJihsw2ARbDRy3
→ To: 24xes13jk7aYc93dfUAWpbnpyx8QFi4FLDNEUpUjofSN
✓ Recipient key found
✓ Message encrypted (56 bytes)
✓ Message sent! ID: ml1m8snb9dts9721s77

  Message: Hey! Ready to chat on X1 🤖
```

## When to Use

- **Wallet-to-wallet messaging** - Secure comms between Solana addresses
- **Agent communication** - AI agents chatting over encrypted channels
- **Transaction coordination** - Discuss trades/transfers privately
- **No browser needed** - Pure CLI/API integration
