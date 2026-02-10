"""
================================================================================
Phase 1 (Part A): Creation of a Controlled Test Case (Sanity Check)
================================================================================

Script Objective:
-----------------
This script serves to create a "test target" to validate the correctness of our
future cracking script. Instead of immediately working on the original problem,
for which we do not know the solution, we create an analogous one where we 
control every parameter, specifically the password.

Operation:
----------
1.  Defines a known password and plaintext (e.g., "giovanni0@").
2.  Replicates the cryptographic process described in the exercise slides:
    a. Generates a random 'salt', crucial for security.
    b. Uses the PBKDF2 key derivation function to transform our weak password
       into a robust cryptographic key. This process is intentionally slow
       (100,000 iterations) to hinder brute force attacks.
    c. Uses the derived key to encrypt the plaintext using the Fernet
       symmetric algorithm.
3.  Prints the results to the screen: the generated 'salt' and 'ciphertext'.
    These two values will be the input for our test script.
4.  Performs an immediate decryption to self-verify that the encryption 
    process occurred correctly.

Role in the Methodological Process:
-----------------------------------
This script is the fundamental first step. It provides us with a secure test
environment. If our cracker can decrypt this message, we will be certain that
its base logic is correct, allowing us to focus on other aspects of the problem
(performance and password generation).

"""

# Importing necessary libraries from the 'cryptography' suite and the standard 'os' library.
import base64  # To encode the binary key into a safe text format.
import os      # Used to generate secure random data (the salt).
from cryptography.fernet import Fernet, InvalidToken # The implementation of symmetric encryption.
from cryptography.hazmat.primitives import hashes      # Contains hash algorithms like SHA-256.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Our Key Derivation Function.


# --- 1. Definition of Input Parameters for the Test ---
# We establish beforehand the password and message we want to use.
# The 'b' prefix before the strings defines them as 'bytes', the format required
# by cryptographic functions.
password_da_usare = b"giovanni0@"
testo_in_chiaro = b"Se leggi questo messaggio, la logica di crittografia funziona!"


# --- 2. Encryption Process ---
# This section faithfully replicates the process that a secure application
# should follow to protect data with a password.

# 2.a. Salt Generation
# A salt is a random value that ensures that even the same password produces
# a different cryptographic output every time. 16 bytes (128 bits) is a standard
# and secure length.
salt = os.urandom(16)

# 2.b. Key Derivation Function (KDF) Configuration
# PBKDF2 is configured with the same parameters as the original exercise
# to create a realistic and consistent test case.
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),  # The hash algorithm to use iteratively.
    length=32,                  # The desired length of the final key in bytes (256 bits).
    salt=salt,                  # The random salt just generated.
    iterations=100000,          # The number of iterations (key stretching) to slow down the process.
)

# 2.c. Derivation and Encoding of the Cryptographic Key
# The 'derive' function performs the intensive PBKDF2 calculation.
# The result is then encoded in Base64 to make it a safe text string.
key = base64.urlsafe_b64encode(kdf.derive(password_da_usare))

# 2.d. Message Encryption
# We create an instance of the Fernet encryption object with our key
# and use it to encrypt the plaintext.
f = Fernet(key)
ciphertext = f.encrypt(testo_in_chiaro)


# --- 3. Printing Results for the Next Script ---
# The output of this script is the input for the next phase.
# We print the values in a format that can be easily copied and pasted.
# Using `!r` in the f-string (repr) ensures that bytes are printed
# with their correct literal notation (e.g., b'\xde\xad...').
print("=" * 60)
print("Controlled Test Case Generated Successfully")
print("=" * 60)
print(f"Reference Password: {password_da_usare.decode('utf-8')}")
print(f"Original Plaintext: {testo_in_chiaro.decode('utf-8')}")
print("-" * 60)
print("Data to copy into the script 'Fase1_bruteforce_test.py':")
print(f"salt = {salt!r}")
print(f"ciphertext = {ciphertext!r}")
print("-" * 60)


# --- 4. Process Self-Verification ---
# To be 100% sure that the generated values are valid,
# we attempt to immediately decrypt the ciphertext with the same key.
# If this step fails, there is a problem within the encryption logic itself.
try:
    decrypted_text = f.decrypt(ciphertext)
    print("Internal decryption verification: OK!")
    print(f"Decrypted text for verification: {decrypted_text.decode('utf-8')}")
except Exception as e:
    print(f"[ERROR] Decryption verification failed: {e}")

print("=" * 60)