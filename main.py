import binascii
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

app = FastAPI()

symmetric_key = None
asymmetric_public_key = None
asymmetric_private_key = None

@app.get("/symmetric/key")
def get_symmetric_key():
    """
    Generates a new symmetric key.

    Returns:
        dict: A dictionary containing the generated symmetric key.
    """
    global symmetric_key
    symmetric_key = Fernet.generate_key()
    return {"key": symmetric_key.decode()}

@app.post("/symmetric/key")
def set_symmetric_key(key: str):
    """
    Sets the symmetric key.

    Args:
        key (str): The symmetric key to set.

    Returns:
        dict: A message indicating the success of the key setting.
    """
    global symmetric_key
    symmetric_key = key.encode()
    return {"message": "Key is set successfully"}

@app.post("/symmetric/encode")
def encode_message(message: str):
    """
    Encrypts a message using the symmetric key.

    Args:
        message (str): The message to encrypt.

    Returns:
        dict: A dictionary containing the encrypted message.
    """
    global symmetric_key
    if not symmetric_key:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    cipher = Fernet(symmetric_key)
    encrypted_message = cipher.encrypt(message.encode())
    return {"encrypted_message": encrypted_message.decode()}

@app.post("/symmetric/decode")
def decode_message(encrypted_message: str):
    """
    Decrypts an encrypted message using the symmetric key.

    Args:
        encrypted_message (str): The encrypted message to decrypt.

    Returns:
        dict: A dictionary containing the decrypted message.
    """
    global symmetric_key
    if not symmetric_key:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    cipher = Fernet(symmetric_key)
    decrypted_message = cipher.decrypt(encrypted_message.encode())
    return {"decrypted_message": decrypted_message.decode()}

@app.get("/asymmetric/key")
def get_asymmetric_key():
    """
    Generates a new asymmetric key pair.

    Returns:
        dict: A dictionary containing the generated public and private keys.
    """
    global asymmetric_public_key, asymmetric_private_key
    asymmetric_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    asymmetric_public_key = asymmetric_private_key.public_key()
    public_key = asymmetric_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    private_key = asymmetric_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    return {"public_key": public_key, "private_key": private_key}

@app.get("/asymmetric/key/ssh")
def get_ssh_key():
    """
    Retrieves the SSH format public key.

    Returns:
        dict: A dictionary containing the SSH format public key.
    """
    global asymmetric_public_key, asymmetric_private_key
    if not asymmetric_public_key or not asymmetric_private_key:
        raise HTTPException(status_code=400, detail="Asymmetric keys not set")
    public_key_ssh = asymmetric_public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    return {"public_key": public_key_ssh, "private_key": "SSH format not supported for private key"}

@app.post("/asymmetric/key")
def set_asymmetric_key(keys: dict):
    """
    Sets the asymmetric keys.

    Args:
        keys (dict): A dictionary containing the public and private keys.

    Returns:
        dict: A message indicating the success of the key setting.
    """
    global asymmetric_public_key, asymmetric_private_key
    public_bytes = binascii.unhexlify(keys.get("public_key"))
    private_bytes = binascii.unhexlify(keys.get("private_key"))
    asymmetric_public_key = serialization.load_der_public_key(public_bytes)
    asymmetric_private_key = serialization.load_pem_private_key(private_bytes, password=None)
    return {"message": "Public and private keys are set successfully"}

@app.post("/asymmetric/verify")
def verify_message(message: str, signature: str):
    """
    Verifies the authenticity of a message using a signature.

    Args:
        message (str): The message to verify.
        signature (str): The signature to verify against.

    Returns:
        dict: A dictionary indicating whether the verification succeeded.
    """
    global asymmetric_public_key
    if not asymmetric_public_key:
        raise HTTPException(status_code=400, detail="Public key not set")
    try:
        signature = binascii.unhexlify(signature)
        asymmetric_public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"verified": True}
    except InvalidSignature:
        return {"verified": False}

@app.post("/asymmetric/sign")
def sign_message(message: str):
    """
    Signs a message using the private key.

    Args:
        message (str): The message to sign.

    Returns:
        dict: A dictionary containing the signature of the message.
    """
    global asymmetric_private_key
    if not asymmetric_private_key:
        raise HTTPException(status_code=400, detail="Private key not set")
    signature = asymmetric_private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {"signature": binascii.hexlify(signature).decode()}

@app.post("/asymmetric/encode")
def asymmetric_encode(message: str):
    """
    Encrypts a message using the asymmetric public key.

    Args:
        message (str): The message to encrypt.

    Returns:
        dict: A dictionary containing the encrypted message.
    """
    global asymmetric_public_key
    if not asymmetric_public_key:
        raise HTTPException(status_code=400, detail="Asymmetric key not set")
    encrypted_message = asymmetric_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"encrypted_message": base64.b64encode(encrypted_message).decode()}

@app.post("/asymmetric/decode")
def asymmetric_decode(encrypted_message: str):
    """
    Decrypts an encrypted message using the asymmetric private key.

    Args:
        encrypted_message (str): The encrypted message to decrypt.

    Returns:
        dict: A dictionary containing the decrypted message.
    """
    global asymmetric_private_key
    if not asymmetric_private_key:
        raise HTTPException(status_code=400, detail="Asymmetric key not set")
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = asymmetric_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"decrypted_message": decrypted_message.decode()}