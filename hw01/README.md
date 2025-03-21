# ECDSA from Scratch (secp256k1)

This project provides a basic implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA) using the secp256k1 curve—**from scratch in Python**. No external cryptographic libraries are used; instead, all underlying elliptic curve arithmetic (point addition, doubling, and scalar multiplication), key generation, signing, and signature verification are implemented manually.

## Features

- **Elliptic Curve Arithmetic**:
  - Point addition and doubling over a finite field.
  - Scalar multiplication using the double-and-add algorithm.

- **Key Generation**:
  - Generate a private key (a random integer in [1, n-1]).
  - Derive the corresponding public key (a point on the curve) by multiplying the private key with the generator point.

- **Message Signing**:
  - Hash the message using SHA-256.
  - Create an ECDSA signature `(r, s)` using a random ephemeral key.

- **Signature Verification**:
  - Verify that a signature is valid for a given message and public key.

## Files

- **`ecdsa.py`**: Contains the full Python implementation along with basic examples and tests.
- **`README.md`**: This file, which provides an overview of the project and instructions for use.

## How to Run

1. Ensure you have Python 3 installed on your system.
2. Run the `ecdsa.py` script:

   ```bash
   python3 ecdsa.py
   ```

When executed, the script will:

- Generate an ECDSA key pair (private and public keys).
- Sign a sample message.
- Verify the generated signature.
- Run several tests, including:
  - Confirming that the signature is valid for the original message.
  - Checking that a tampered message fails the signature verification.
  - Verifying that multiplying the generator by its order results in the identity element.

## Testing

The implementation includes basic tests:

- Key Generation and Signing: A key pair is generated, a message is signed, and the signature is verified.
- Tampered Message Check: Ensures that modifying the message causes signature verification to fail.
- Elliptic Curve Property Check: Verifies that $n \times G$ yields the identity element (represented as None).
