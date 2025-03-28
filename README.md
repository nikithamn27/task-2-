Here's the **usage documentation** based on your provided code with improved clarity and formatting:  

---

# 🔐 Secure Key Management System  

## 📌 Overview  
This system ensures **secure key generation, encryption, decryption, key exchange, and revocation** using **RSA, AES-GCM, and Diffie-Hellman key exchange** mechanisms.  

## 🚀 Features  
✔ **RSA Key Pair Generation** – Securely generates public & private keys.  
✔ **Diffie-Hellman Key Exchange** – Establishes a shared AES encryption key.  
✔ **AES Encryption & Decryption** – Ensures message confidentiality & integrity.  
✔ **Digital Signatures** – Verifies data authenticity with RSA signatures.  
✔ **Key Expiry & Revocation** – Prevents the use of compromised or expired keys.  

## ⚙️ Installation  
Ensure you have Python installed, then install the required dependencies:  
```sh
pip install pycryptodome cryptography
```  

## 🛠️ Usage  

### 🔑 Generate RSA Keys  
```python
from key_manager import gen_rsa_keys

private_key, public_key, expiry_date = gen_rsa_keys()
print(private_key.decode())  # Display private key
print(public_key.decode())   # Display public key
```

### 🔒 Establish a Shared AES Key (Diffie-Hellman)  
```python
from key_manager import gen_dhpara, gen_keypair, serialize_publickey, derive_shared

# Generate DH parameters
dh_parameters = gen_dhpara()

# User A's key pair
userA_private, userA_public = gen_keypair(dh_parameters)

# User B's key pair
userB_private, userB_public = gen_keypair(dh_parameters)

# Exchange & derive shared secret
aes_key_A = derive_shared(userA_private, serialize_publickey(userB_public))
aes_key_B = derive_shared(userB_private, serialize_publickey(userA_public))

# AES keys should be identical
print(aes_key_A == aes_key_B)  # Output: True
```

### 🔑 Encrypt & Decrypt Messages (AES)  
```python
from key_manager import encrypt, decrypt

message = "Confidential Information"
encrypted_message = encrypt(aes_key_A, message)
decrypted_message = decrypt(aes_key_B, encrypted_message)

print("Encrypted:", encrypted_message.decode())
print("Decrypted:", decrypted_message)
```

### ✍️ Sign & Verify Messages (RSA)  
```python
from key_manager import sign_message, verify_signature

message = "Authenticate this transaction"
signature = sign_message(private_key, message)
is_valid = verify_signature(public_key, message, signature)

print("Signature valid?", is_valid)  # Output: True
```

### ❌ Check Key Expiration & Revocation  
```python
from key_manager import is_expired, revoke_key, is_revoked

if is_expired(expiry_date):
    revoke_key("user_private")
    
print("Is key revoked?", is_revoked("user_private"))
```

---

## ✅ Summary  
This **key management system** ensures secure communication by:  
🔹 Generating RSA & Diffie-Hellman key pairs  
🔹 Encrypting & decrypting messages with AES  
🔹 Using digital signatures for verification  
🔹 Managing key expiration & revocation  

Would you like any modifications or additional features? 🚀
