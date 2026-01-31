# X1 Chat CLI

CLI tool to authenticate with [X1 Encrypted Chat](https://staging-vero.x1.xyz/xchat) using a Solana wallet — no browser or wallet extension required.

## How It Works

X1 Encrypted Chat uses wallet signatures to derive X25519 encryption keys for end-to-end encrypted messaging. This tool replicates the browser's authentication flow:

1. **Sign** a message with your Solana wallet
2. **Derive** X25519 keypair using HKDF-SHA256 (same algorithm as the browser)
3. **Register** your encryption public key with the X1 Chat server

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Set your wallet key

```bash
export SOLANA_PRIVATE_KEY="your_base58_private_key"
```

### Authenticate

```bash
python x1_chat_auth.py
```

Example output:
```
◎ X1 Encrypted Chat CLI Authentication

✓ Wallet: 2jchoLFVoxmJUcygc2cDfAqQb1yWUEjJihsw2ARbDRy3

→ Signing: X1 Encrypted Messaging - Sign to generate your encryption keys
✓ Signature: 4eLCr7gAtQiBe5KY...
✓ X25519 Public Key: GvCGw1DKxv9UvbKy...

→ Registering key with X1 Chat...
✓ Successfully registered!

  Address: 2jchoLFVoxmJUcygc2cDfAqQb1yWUEjJihsw2ARbDRy3
  X25519 Key: GvCGw1DKxv9UvbKyMBQvUCWiPJzrVxJo447JUeCdgEVW
```

### As a library

```python
from x1_chat_auth import authenticate

# Using environment variable
result = authenticate()

# Or pass key directly
result = authenticate(private_key_b58="your_key_here")

print(result)
# {
#     "address": "2jcho...",
#     "x25519PublicKey": "GvCGw...",
#     "already_registered": False
# }
```

## API Endpoints

The tool interacts with these X1 Chat API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/xchat/api/keys/{address}` | Check if wallet is registered |
| POST | `/xchat/api/keys` | Register encryption key |

## Security Notes

- **Never share your private key** — it controls your wallet and chat identity
- The X25519 keypair is deterministically derived from your wallet signature
- Same wallet + same message = same encryption keys (this is by design)

## Technical Details

- **Key Derivation**: HKDF-SHA256 with domain separator `x1-msg-v1-x25519`
- **Signing**: Ed25519 (Solana native)
- **Encryption Keys**: X25519 (Curve25519)

## License

MIT
