"""
================================================================================
Phase 2: Computational Performance Benchmarking
================================================================================

Script Objective:
-----------------
This script has a single, fundamental purpose: to measure the speed at which
our hardware can execute a single cracking attempt against the specific target
of the exercise. Due to the use of a KDF with a high number of iterations 
(key stretching), each attempt has a non-negligible computational cost. 
Quantifying this cost is essential to estimate the total duration of the attack.

Operation:
----------
1.  Uses the REAL 'salt' and 'ciphertext' of the exercise, since performance 
    depends on these fixed values.
2.  Defines a 'check_password' function optimized for speed: it performs the 
    full cycle of key derivation and decryption attempt, but suppresses any 
    screen output to avoid "polluting" the time measurement with I/O operations.
3.  Runs a loop for a predefined number of attempts (e.g., 1000). 
    For each attempt, it generates a dummy password (whose value is irrelevant)
    and passes it to the check function.
4.  Precisely measures the total time taken to complete all attempts.
5.  Calculates and presents key performance metrics:
    - Average time per single password.
    - Passwords per second (H/s - Hashes per second), the standard metric
      in the field of password cracking.
    - Passwords per minute.

Role in the Methodological Process:
-----------------------------------
This is the "reconnaissance" phase. It provides us with the most important data
for planning: our attack speed. Without this number, any estimate on the 
attack duration would be pure speculation. With this data, however, we can 
calculate with good approximation the time needed to explore password spaces 
of any size, allowing us to evaluate the feasibility of different attack 
strategies.

"""

# Import of necessary libraries.
import base64
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- 1. Definition of the Real Exercise Target ---
# We use the original data provided in the slides.
# Note: The salt is defined as a byte string.
salt = b"\xd2\xffs~\xb4\xf2\xd3\da\xe3\x16('\xe6\xad\xef\xaf"
ciphertext = b'gAAAAABmE2P-qqJT-HudMbLcykzIx83XqZNEt6UqfyBBzhYKvlF9WSx8FJUvUmatzuYl-iO9RHwAj7RVBuAkTwRAVT9GpCC--TZUXk387qeTC2jIJOfUrwSX3eGEb1EVFZBOqALd8EKS1CFWUoF4NpzKsc3eLeCnXihb-w6Boqi835uNzN6mZz4iP-6sSkhNxHF-TbrG-BNgjMIyeRDjSLAZHEAJoUGlz_QuOyyOYHMab9LUrXkHibU='


# --- 2. Check Function Optimized for Benchmarking ---
def check_password_silent(passwd_bytes):
    """
    Performs a complete decryption attempt but produces no output.
    This "silent" version is ideal for measuring pure computational
    performance without console I/O overhead.
    """
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passwd_bytes))
        f = Fernet(key)
        f.decrypt(ciphertext)
    except InvalidToken:
        pass


# --- 3. Benchmark Execution ---
number_of_passwords_to_test = 1000
print(f"Starting benchmark: {number_of_passwords_to_test} passwords will be tested...")
print("This process will measure your hardware speed against this specific cryptographic target.")
start_time = time.time()
for i in range(number_of_passwords_to_test):
    dummy_password = f"benchmark_password_{i}".encode('utf-8')
    check_password_silent(dummy_password)
    if (i + 1) % 100 == 0:
        print(f"  Progress: {i + 1}/{number_of_passwords_to_test} passwords tested...")
end_time = time.time()
total_duration = end_time - start_time


# --- 4. Calculation and Presentation of Performance Metrics ---
avg_time_per_password = total_duration / number_of_passwords_to_test
passwords_per_second = number_of_passwords_to_test / total_duration
passwords_per_minute = passwords_per_second * 60

print("\n" + "=" * 50)
print("Benchmark Results")
print("=" * 50)
print(f"Total time to test {number_of_passwords_to_test} passwords: {total_duration:.2f} seconds.")
print(f"Average time per password: {avg_time_per_password * 1000:.2f} milliseconds.")
print("-" * 50)
print("Key Performance Metric:")
print(f"CRACKING SPEED: {passwords_per_second:.2f} H/s (Hashes per second)")
print(f"                {passwords_per_minute:.2f} H/min (Hashes per minute)")
print("=" * 50)


# --- 5. Estimation Example Based on Complete Analysis ---

# Utility function to convert seconds into a readable H:M:S format
def format_time(seconds):
    """Converts a total number of seconds into hours, minutes, and seconds."""
    # `divmod` is a Python function that performs division and returns both quotient and remainder
    # Example: divmod(130, 60) -> (2, 10), i.e., 2 minutes and 10 seconds.
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)} hours, {int(minutes)} minutes and {int(seconds)} seconds"

# We use the number of combinations that will be calculated in Phase 3.
total_combinations_example = 422400

if passwords_per_second > 0:
    # We calculate the total time in seconds for the worst-case scenario.
    estimated_time_seconds_worst_case = total_combinations_example / passwords_per_second
    
    # The average case is half of the worst case.
    estimated_time_seconds_avg_case = estimated_time_seconds_worst_case / 2

    print("\nTime Estimation Example (for a space of 422,400 passwords):")
    print("-" * 65)
    
    # We present the results in a clear and unambiguous format.
    print("Worst Case (the password is the last in the list):")
    print(f" -> {format_time(estimated_time_seconds_worst_case)}")
    
    print("\nAverage Case (the password is in the middle of the list):")
    print(f" -> {format_time(estimated_time_seconds_avg_case)}")
    
    print("=" * 65)
else:
    print("\nImpossible to calculate estimate: measured speed is zero.")