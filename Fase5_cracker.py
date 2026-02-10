"""
================================================================================
Final Solution: Optimized Brute Force Cracker
================================================================================

Script Objective:
-----------------
This script represents the final synthesis of all analysis, validation, and 
benchmarking phases. It implements the hybrid brute force attack to solve the 
exercise, using the correct password generation logic and verified input values.

Key Features:
-------------
1.  **Correct Data:** Uses the exact 'salt' and 'ciphertext' values confirmed
    by the working reference code.
2.  **Correct Generation Logic:** Implements the confirmed rule:
    Base Word -> Capitalization of an existing letter -> Insertion of a 
    symbol -> Insertion of a number.
3.  **Memory Efficiency:** Uses a Python generator (`yield`) to produce 
    candidate passwords one at a time. This approach is extremely efficient 
    and can handle massive search spaces without consuming RAM.
4.  **Real-time Monitoring:** Provides periodic feedback on the attack 
    progress, showing the number of attempts and cracking speed, allowing 
    the process to be tracked.
5.  **Flexible Configuration:** Allows easily launching either a full attack 
    on the entire dictionary or a targeted test on a single word 
    (e.g., "sicurezza") for quick verification.

How to Use It:
--------------
1.  For a quick test (recommended for the first run), set 
    `ATTACK_MODE = "QUICK_TEST"`.
2.  To launch the full attack, set 
    `ATTACK_MODE = "FULL"`.
3.  Run the script from the terminal: python Final_Solution.py

Author: [Your Name]
Course: Data and System Security
Instructor: [Instructor's Name]
Date: [Today's Date]
"""

# Import necessary libraries
import base64
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- 1. ATTACK CONFIGURATION ---
# Choose the execution mode:
# - "FULL": Tests all words in the dictionary.
# - "QUICK_TEST": Tests only the word "sicurezza" for a fast verification.
ATTACK_MODE = "QUICK_TEST"  # Change to "FULL" for the total attack

# --- 2. TARGET DATA AND PASSWORD COMPONENTS ---
# Correct salt and ciphertext values, verified via the reference code.
salt = b"\xd2\xffs~\xb4\xf2\xd3\xda\xe3\x16('\xe6\xad\xef\xaf"
ciphertext = b'gAAAAABnE2P-qqJT-HudMbLcykzIx83XqZNEt6UqfyBBzhYKvlF9WSx8FJUvUmatzuY1-io9RHWaj7RVBuAKTWRAVT9GpGC--TZUXk387qeTC2jIJOfUrwSX3eGEb1EVFZBOqALd8EKS1CFWUoF4NpzKsc3eLeCnXihb-w6Boqi835uNzN6mZz4iP-6sSkhNxHP-TbrG-BNgjMIyeRDjSLAZhEAJoUGlz_QuOyyOYHMab9LUrXkHibU='

# Components for password construction.
# NOTE: The original dictionary excluded "password". We keep it for consistency.
full_dictionary = ["gatto", "giulia", "martina", "pisa", "poesia", "qwerty", "sicurezza", "storia", "tavolo"]
symbols = ["!", "$", "%", "&", "?", "^", "*", "+", "@", "#"]
numbers = [str(i) for i in range(10)]

# Selects the dictionary to use based on the chosen mode.
if ATTACK_MODE == "QUICK_TEST":
    dictionary_to_use = ["sicurezza"]
    print("[INFO] Running in QUICK_TEST mode on the word 'sicurezza'.")
else:
    dictionary_to_use = full_dictionary
    print("[INFO] Running in FULL ATTACK mode on the entire dictionary.")


# --- 3. PASSWORD VERIFICATION FUNCTION ---
def decrypt(passwd_bytes):
    """ Attempts to decrypt the global ciphertext using the provided password. """
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passwd_bytes))
        f = Fernet(key)
        plaintext = f.decrypt(ciphertext)
        
        print("\n" + "="*50)
        print(f"[!!!] SUCCESS! PASSWORD FOUND [!!!]")
        print(f" -> Password: {passwd_bytes.decode('utf-8')}")
        print(f" -> Plaintext: {plaintext.decode('utf-8')}")
        print("="*50)
        return True
    except InvalidToken:
        return False


# --- 4. EFFICIENT PASSWORD GENERATOR ---
def password_generator(dictionary):
    """
    Generator that constructs and 'yields' one password at a time,
    following the order: capitalization -> symbol insertion -> number insertion.
    """
    for base_word in dictionary:
        for i in range(len(base_word)):
            # 4.a. Creates the variant with one uppercase letter.
            capitalized_word = base_word[:i] + base_word[i].upper() + base_word[i+1:]
            
            # 4.b. Inserts the symbol in every possible position.
            for symbol in symbols:
                for j in range(len(capitalized_word) + 1):
                    word_with_sym = capitalized_word[:j] + symbol + capitalized_word[j:]
                    
                    # 4.c. Inserts the number in every position of the resulting string.
                    for number in numbers:
                        for k in range(len(word_with_sym) + 1):
                            final_password = word_with_sym[:k] + number + word_with_sym[k:]
                            yield final_password


# --- 5. EXECUTION AND MONITORING OF THE ATTACK ---
print("=" * 60)
print("Starting Cracker...")
print("=" * 60)

start_time = time.time()
password_found = False
attempts = 0

# Initializes the generator with the correct dictionary (full or test).
password_candidates = password_generator(dictionary_to_use)

# Main loop: tests every password produced by the generator.
for password_guess in password_candidates:
    attempts += 1
    
    # Prints a periodic update for monitoring.
    if attempts % 5000 == 0:
        elapsed_time = time.time() - start_time
        speed = attempts / elapsed_time if elapsed_time > 0 else 0
        print(f"[INFO] Progress: {attempts:,} attempts | Speed: {speed:.2f} H/s | Last test: '{password_guess}'")

    # Executes the decryption attempt.
    if decrypt(password_guess.encode('utf-8')):
        password_found = True
        break # Breaks the loop as soon as the solution is found.

# --- 6. FINAL SUMMARY ---
end_time = time.time()
duration_seconds = end_time - start_time
duration_minutes = duration_seconds / 60

print("\n" + "=" * 60)
print("Attack Summary")
print("=" * 60)
if not password_found:
    print("[RESULT] FAILURE: Password not found.")
else:
    print("[RESULT] SUCCESS: The password was found and the message decrypted.")

print(f"Total passwords tested: {attempts:,}")
print(f"Total time elapsed: {duration_minutes:.2f} minutes ({duration_seconds:.2f} seconds).")
print("=" * 60)