# X1 Chat CLI 🔐

CLI tool and agent skill for [X1 Encrypted Chat](https://staging-vero.x1.xyz/xchat) — send and receive end-to-end encrypted messages using a Solana wallet. No browser or wallet extension required.

## Installation

### As an OpenClaw/ClawdHub Skill
```bash
clawdhub install x1-chat
```

### Manual
```bash
git clone https://github.com/jacklevin74/x1-chat-cli
cd x1-chat-cli
pip install -r requirements.txt
```

## Quick Start

### 1. Set your wallet
```bash
export SOLANA_PRIVATE_KEY="your_base58_private_key"
```

### 2. Register with X1 Chat
```bash
python3 x1_chat_auth.py
```

### 3. Send a message
```bash
python3 x1_chat_send.py <recipient_address> "Hello from CLI!"
```

### 4. Receive messages
```bash
python3 x1_chat_recv.py [optional_sender_filter]
```

## How It Works

X1 Chat uses wallet signatures to derive encryption keys, enabling true end-to-end encryption:

```
┌─────────────────┐     ┌─────────────────┐
│   Your Wallet   │     │  Their Wallet   │
│   (Solana)      │     │   (Solana)      │
└────────┬────────┘     └────────┬────────┘
         │                       │
    Sign Message            Sign Message
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│ X25519 Keypair  │     │ X25519 Keypair  │
│ (HKDF-SHA256)   │     │ (HKDF-SHA256)   │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
              ECDH Shared Secret
                     │
                     ▼
            ┌─────────────────┐
            │   AES-256-GCM   │
            │   Encryption    │
            └─────────────────┘
```

1. **Sign** → Wallet signs authentication message
2. **Derive** → HKDF-SHA256 derives X25519 keypair from signature
3. **Exchange** → ECDH computes shared secret with recipient
4. **Encrypt** → AES-256-GCM encrypts message content
5. **Send** → Only ciphertext reaches server (E2E)

## Scripts

| Script | Description |
|--------|-------------|
| `x1_chat_auth.py` | Register wallet with X1 Chat |
| `x1_chat_send.py` | Send encrypted message |
| `x1_chat_recv.py` | Receive and decrypt messages |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/xchat/api/keys/{address}` | Look up encryption key |
| POST | `/xchat/api/keys` | Register encryption key |
| POST | `/xchat/api/messages` | Send encrypted message |
| GET | `/xchat/api/stream/{address}` | SSE stream for messages |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SOLANA_PRIVATE_KEY` | Yes | Base58-encoded Solana private key |

## Example Session

```
$ python3 x1_chat_auth.py
◎ X1 Encrypted Chat CLI Authentication

✓ Wallet: 2jchoLFVoxmJUcygc2cDfAqQb1yWUEjJihsw2ARbDRy3
→ Signing: X1 Encrypted Messaging - Sign to generate your encryption keys
✓ Signature: 4eLCr7gAtQiBe5KY...
✓ X25519 Public Key: GvCGw1DKxv9UvbKy...
→ Registering key with X1 Chat...
✓ Successfully registered!

$ python3 x1_chat_send.py 24xes13jk7aYc93dfUAWpbnpyx8QFi4FLDNEUpUjofSN "Hey!"
◎ X1 Encrypted Chat - Send Message

✓ From: 2jchoLFVoxmJUcygc2cDfAqQb1yWUEjJihsw2ARbDRy3
→ To: 24xes13jk7aYc93dfUAWpbnpyx8QFi4FLDNEUpUjofSN
✓ Recipient key found
✓ Message encrypted (20 bytes)
✓ Message sent! ID: ml1m8snb9dts9721s77

$ python3 x1_chat_recv.py
◎ X1 Encrypted Chat - Receive Messages

✓ Wallet: 2jchoLFVoxmJUcygc2cDfAqQb1yWUEjJihsw2ARbDRy3
→ Polling for messages...

==================================================
← Received [24xes13j...ofSN]: Hey back!
==================================================
```

## Use Cases

- **Agent-to-Agent** — AI agents communicating over encrypted channels
- **Wallet-to-Wallet** — Secure messaging between Solana addresses  
- **Transaction Coordination** — Private discussion of trades/transfers
- **CLI Integration** — Script automated encrypted messaging

## Security

- ✅ End-to-end encrypted (server cannot read messages)
- ✅ Private keys never leave your machine
- ✅ Deterministic key derivation (same wallet = same keys)
- ✅ AES-256-GCM with unique nonce per message

## License

MIT
