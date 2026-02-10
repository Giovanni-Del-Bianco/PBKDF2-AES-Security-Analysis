"""
================================================================================
Phase 3: Problem Complexity Estimation and Attack Planning
================================================================================

Script Objective:
-----------------
This script is purely analytical and does not execute any attack. Its purpose
is to calculate the exact size of the "password space" (the total number of
possible combinations) based on the discovered rules. It then uses the speed
metric obtained in Phase 2 (benchmark) to provide an accurate time estimate
for the full attack.

Operation:
----------
1.  Defines the base components of the password (dictionary, symbols, numbers).
2.  Loads the performance metric (H/s) obtained from 'Fase2_benchmark.py'.
    This datum is fundamental for the estimation.
3.  Iterates over every word in the provided dictionary. For each word, it
    applies combinatorial principles to calculate how many unique passwords
    it can generate, following precise rules:
    a. Capitalization: Calculates how many variants are obtained by capitalizing
       any one of the letters in the word.
    b. Number Insertion: Calculates in how many ways a number (0 to 9) can be
       inserted into any position of the capitalized word.
    c. Symbol Insertion: Calculates in how many ways a special symbol can be
       inserted into any position of the resulting string (word + number).
4.  Sums the combinations of each word to obtain the grand total.
5.  Divides the total number of combinations by the cracking speed (H/s)
    to calculate the estimated attack time, both for the worst case (password
    is the last one) and the average case.

Role in the Methodological Process:
-----------------------------------
This is the strategic phase. It allows us to answer critical questions before
investing time and computational resources: "How big is the problem?" and
"How long will it take to solve it?". The result of this script determines the
feasibility of the brute force attack. If the estimate were years, we would
know this strategy is not viable and would need to look for other vulnerabilities.
In this case, an estimate of a few hours gives us the green light to proceed
with the final attack.

"""

# --- 1. Definition of Search Space Components ---
# These are the base "ingredients" we will use to build the passwords.
dictionary = ["gatto", "giulia", "martina", "password", "pisa", "poesia", "qwerty", "sicurezza", "storia", "tavolo"]
special_chars = ['!', '$', '%', '&', '?', '^', '*', '+', '@', '#']
numbers = [str(i) for i in range(10)] # Digits from '0' to '9'


# --- 2. Import of Performance Metric ---
# This value must be updated with the result obtained from 'Fase2_benchmark.py'.
# It is our "attack speed" expressed in attempts (Hashes) per second.
passwords_per_second = 58.13  # Example: 58.13 H/s


# --- 3. Combinatorial Calculation Logic ---
print("=" * 70)
print("Starting calculation of total password space...")
print("=" * 70)

# We initialize a counter for the total combinations.
total_combinations = 0

# We analyze each word in the dictionary individually.
for word in dictionary:
    word_len = len(word)
    
    # 3.a. Calculation of capitalization options.
    # Rule: any one of the letters in the word can be capitalized.
    # For a word of 'n' letters, there are 'n' options.
    capitalization_options = word_len
    
    # 3.b. Calculation of number insertion options.
    # Rule: a number (10 choices) can be inserted into any position
    # of a string of length 'n'. There are 'n+1' insertion positions.
    number_insertion_options = len(numbers) * (word_len + 1)
    
    # 3.c. Calculation of symbol insertion options.
    # Rule: a symbol (10 choices) is inserted after the number step.
    # The string now has length 'n+1', so there are 'n+2' positions.
    symbol_insertion_options = len(special_chars) * (word_len + 2)
    
    # 3.d. Calculation of combinations for the current word.
    # The total number of combinations for this word is the product of the options.
    combinations_for_this_word = capitalization_options * number_insertion_options * symbol_insertion_options
    
    # Print a detailed analysis for this word.
    print(f"Word: '{word}' (length {word_len})")
    print(f"  - Capitalization variants: {capitalization_options}")
    print(f"  - Ways to insert a number: {len(numbers)} numbers * {word_len + 1} positions = {number_insertion_options}")
    print(f"  - Ways to insert a symbol: {len(special_chars)} symbols * {word_len + 2} positions = {symbol_insertion_options}")
    print(f"  ==> Total combinations for '{word}': {combinations_for_this_word:,}")
    print("-" * 50)
    
    # Add the partial result to the grand total.
    total_combinations += combinations_for_this_word


# --- 4. Presentation of Final Results ---
print("\n" + "=" * 70)
print("Password Space Calculation Summary")
print("=" * 70)
print(f"TOTAL COMBINATIONS TO TEST (sum of all words): {total_combinations:,}")
print("=" * 70)

# 4.a. Calculation of time estimate.
if passwords_per_second > 0:
    time_seconds = total_combinations / passwords_per_second
    time_minutes = time_seconds / 60
    time_hours = time_minutes / 60
    
    # The average case statistically assumes finding the password halfway through.
    avg_time_hours = time_hours / 2
    
    print("\n" + "=" * 70)
    print(f"Time Estimate (based on a speed of {passwords_per_second:.2f} H/s)")
    print("=" * 70)
    print(f"\nWorst Case (the password is the last in the list):")
    print(f" -> {time_hours:.2f} hours ({time_minutes:.2f} minutes)")
        
    print(f"\nAverage Case (the password is in the middle of the list):")
    print(f" -> {avg_time_hours:.2f} hours ({avg_time_hours * 60:.2f} minutes)")
        
    print("=" * 70)