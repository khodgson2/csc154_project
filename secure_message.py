"""
Secure message functions used by client.py.

Requires:  pip install cryptography
Run:       python secure_message.py

Modifications to this file:
    functions return error messages rather than printing them out.
    print() lines are commented out. 
    After creating the package, sender_encrypt_and_sign encodes all fields of the package
        with base64 and utf-8 so that the package can be sent as a JSON string.
    sender_encrypt_and_sign signs the hash of a string containing the sender and recipient usernames,
        timestamp, encrypted AES key, nonce, and message.

    Before decrypting and verifying the message, sender_decrypt_and_verify decodes all fields
    of the package from utf-8 and base64 to bytes.

    I deleted the main and tamper_tests functions. 

"""

import os
import base64
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


# ---------- helpers ----------
def b64(data: bytes) -> str:
    """Show bytes as readable base64 text (shortened if long)."""
    s = base64.b64encode(data).decode()
    return s if len(s) <= 60 else s[:60] + "..."


OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


# ---------- key setup ----------
def generate_keypair(name: str, password: bytes):
    """Create an RSA key pair, save it to PEM files, return (private, public)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ))
    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"  Created {name}_private.pem and {name}_public.pem")
    return private_key, public_key




def sender_encrypt_and_sign(message: str, sender_username: str, recipient_username: str,
                            receiver_public_key, sender_private_key):
    #print("\n========== SENDER (User A) ==========")
    data = message.encode("utf-8")

    # 1. AES key + encrypt message
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)

    # 2. Encrypt AES key with receiver's public key
    encrypted_aes_key = receiver_public_key.encrypt(aes_key, OAEP)

    #calculate timestamp
    timestamp = str(time.time())

    #SHA-256 hash of the sender, recipient, message number, timestamp, 
    # encrypted key, nonce and ciphertext, joined in that order with a separator character 
    sep = "|"      # separator character
    sep = sep.encode("utf-8")
    data_to_sign = sender_username.encode("utf-8") + sep + recipient_username.encode("utf-8") + sep 
    data_to_sign += timestamp.encode("utf-8") + sep
    data_to_sign += encrypted_aes_key + sep + nonce + sep + data

    # 3. hash the message details
    digest = hashlib.sha256(data_to_sign).digest()
    #print(f"[4] SHA-256 hash of message: {digest.hex()}")

    # 4. Sign the hash with sender's private key
    signature = sender_private_key.sign(
        digest, PSS, utils.Prehashed(hashes.SHA256())
    )
    #print(f"[5] Signature (User A's private key): {b64(signature)}")

    # This bundle is what would be "sent" to User B
    # encode data so that it can be sent as a JSON string
    # encode each field except for timestamp with base64

    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "timestamp": timestamp,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
    }



def receiver_decrypt_and_verify(package, sender_username:str, recipient_username:str, 
                                receiver_private_key, sender_public_key):
    """
    returns decrypted message or error message
    """

    # restore the fields of pkg to their original values
    # decode all fields from utf-8, then decode all fields from base64

    decoded_pkg = {
        "encrypted_aes_key": base64.decodebytes(bytes(package["encrypted_aes_key"], "utf-8")),
        "nonce": base64.decodebytes(bytes(package["nonce"], "utf-8")),
        "timestamp": package["timestamp"],
        "ciphertext": base64.decodebytes(bytes(package["ciphertext"], "utf-8")),
        "signature": base64.decodebytes(bytes(package["signature"], "utf-8")),

    }

    # 1. Recover AES key with receiver's private key
    try:
        aes_key = receiver_private_key.decrypt(decoded_pkg["encrypted_aes_key"], OAEP)
    except ValueError:
        return("[X] Could not decrypt the AES key (wrong key or corrupted).")

    # 2. Decrypt the message (GCM also checks it wasn't modified)
    try:
        data = AESGCM(aes_key).decrypt(decoded_pkg["nonce"], decoded_pkg["ciphertext"], None)
    except InvalidTag:
        return("[X] Decryption failed: ciphertext was tampered with.")
    
    message = data.decode("utf-8")

    #SHA-256 hash of the sender, recipient, message number, timestamp, 
        # encrypted key, nonce and ciphertext, joined in that order with a separator character 
    sep = "|"      # separator character
    sep = sep.encode("utf-8")
    data_to_hash = sender_username.encode("utf-8") + sep + recipient_username.encode("utf-8")
    data_to_hash += sep + package["timestamp"].encode("utf-8") + sep
    data_to_hash += decoded_pkg["encrypted_aes_key"] + sep
    data_to_hash += decoded_pkg["nonce"] + sep + data

    # 3. Hash the decrypted message and usernames
    digest = hashlib.sha256(data_to_hash).digest()

    # 4. Verify signature with sender's public key
    try:
        sender_public_key.verify(
            decoded_pkg["signature"], digest, PSS, utils.Prehashed(hashes.SHA256())
        )
    except InvalidSignature:
        return("[X] Signature INVALID: not from " + sender_username + 
               ", or message was altered.")

    return message
