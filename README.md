# 🔒 Privacy-Preserving E-Commerce System

A Python implementation of a **privacy-preserving e-commerce protocol** that enables secure transactions between a customer and merchant without either party directly revealing sensitive information to the other. A trusted **broker** intermediary handles authentication, key exchange, and payment settlement — ensuring neither the customer's identity nor the merchant's pricing is exposed to the other party directly.

## ✨ Features

- **Mutual RSA authentication** — all three parties (customer, broker, merchant) perform mutual challenge-response authentication using 1024-bit RSA public/private key pairs; each party generates its own keys and exchanges public keys via `.pem` files
- **Diffie-Hellman key exchange** — the broker negotiates DH parameters (prime `p` and generator `q`) and facilitates public key exchange between customer and merchant, establishing a shared session key without either party transmitting it directly
- **Session key verification** — merchant challenges customer by encrypting a test message with the DH session key; customer must decrypt and return it correctly to confirm key agreement
- **Product order encryption** — customer's product selections are encoded using a custom character-to-number mapping and multiplied by the DH session key before transmission, preventing the broker from reading the order content
- **Broker-mediated payment** — the broker adds its service fee (broker receives amount + $20 from customer, forwards the base amount to merchant), keeping the two payment legs separate
- **Socket-based networking** — all parties communicate over raw TCP sockets; broker acts as both a TCP server (for the customer) and a TCP client (to the merchant)

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Asymmetric Cryptography | `rsa` library (PKCS#1, 1024-bit keys) |
| Key Exchange | Diffie-Hellman (manual implementation) |
| Transport | Python `socket` (TCP) |
| Encoding | Custom character → 3-digit numeric mapping |

## 🚀 Setup & Installation

**Prerequisites:** Python 3.8+, all three processes must be on the same network (or localhost)

```bash
# 1. Clone the repository
git clone https://github.com/moksh555/Privacy-Preserving-E-commerce-System.git
cd Privacy-Preserving-E-commerce-System

# 2. Install dependencies
pip install rsa

# 3. Update the IP address in all three scripts
#    Change ip_address = "192.168.1.123" to your actual IP or "127.0.0.1"
```

## ▶️ Usage

Run each script in a separate terminal **in this order**:

```bash
# Terminal 1 — Start the merchant server (listens on port 12020)
python merchant.py

# Terminal 2 — Start the broker (listens on port 12016 for customer, connects to merchant)
python broker.py

# Terminal 3 — Start the customer client
python customer.py
```

Follow the interactive prompts for challenge-response inputs and Diffie-Hellman private key selection.

## 🏗️ Protocol Flow

```
Customer                    Broker                    Merchant
   │                           │                          │
   │── credentials ──────────► │                          │
   │ ◄── RSA challenge ──────  │                          │
   │── decrypt & return ──────►│                          │
   │── RSA challenge ─────────►│                          │
   │ ◄── decrypted response ── │                          │
   │                           │── RSA challenge ────────►│
   │                           │ ◄── decrypted response ──│
   │                           │── RSA challenge ─────────│
   │                           │ ◄── decrypted response ──│
   │                           │                          │
   │ ◄── DH params (p, q) ─── │ ──DH params (p, q) ─────►│
   │── DH public key ─────────►│ ──────────────────────── ►│
   │ ◄── merchant DH public ── │ ◄── merchant DH public ──│
   │                           │                          │
   │     [session key established independently]          │
   │                           │                          │
   │ ◄── product list ──────── │ ◄── product list ────────│
   │── encrypted order ───────►│── encrypted order ──────►│
   │ ◄── total amount ──────── │ ◄── total amount ─────── │
   │── payment (amount+$20) ──►│── payment (amount) ─────►│
   │ ◄── tx confirmation ───── │ ◄── tx confirmation ──── │
```

## 🔐 Security Design Notes

- **RSA key exchange** uses `.pem` files pre-shared between parties; each challenge is encrypted with the recipient's public key so only the intended recipient can decrypt it
- **DH session key** is computed independently by both customer and merchant: `session_key = (other_public ^ own_private) mod p`; the broker never learns the session key
- **Order privacy** — the product selection is encoded and multiplied by `session_key` before transmission; the broker relays the ciphertext without being able to decode it
- **Payment separation** — the broker collects `amount + $20` from the customer and sends `amount` to the merchant, monetizing without exposing either party's exact transaction to the other
