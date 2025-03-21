import ecdsa

n = ecdsa.n
G = ecdsa.G


# Basic example and tests
def run_tests():
    print("Running basic tests for our ECDSA (secp256k1) implementation...\n")

    print("\n---> Running Test 1 <---")
    # Test 1: Key generation, signing, and verification
    priv, pub = ecdsa.generate_key_pair()
    assert pub is not None, "Pub is empty"

    message = b"Hello, ECDSA!"
    signature = ecdsa.sign_message(message, priv)
    print("Message:", message)
    print("Private key:", priv)
    print("Public key:", pub)
    print("Signature (r, s):", signature)

    valid = ecdsa.verify_signature(message, pub, signature)
    print("Verification result (should be True):", valid)
    assert valid, "Signature should be valid for the correct message and key."

    # Test 2: Signature should fail if the message is altered
    print("\n---> Running Test 2 <---")
    tampered_message = b"Hello, ECDSA?"
    valid_tampered = ecdsa.verify_signature(tampered_message, pub, signature)
    print("Verification for tampered message (should be False):", valid_tampered)
    assert not valid_tampered, "Signature should be invalid for a tampered message."

    # Test 3: n * G should be the identity (None)
    print("\n---> Running Test 3 <---")
    identity = ecdsa.scalar_mul(n, G)
    print("n * G (should be identity / None):", identity)
    assert identity is None, "n * G should be the identity element (None)."

    print("\nAll tests passed successfully.")


if __name__ == "__main__":
    run_tests()
