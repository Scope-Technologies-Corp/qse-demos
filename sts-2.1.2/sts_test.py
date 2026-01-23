import pexpect
import time

# Customize these values
sequence_length = "100000"
num_sequences = "1"
file_name = "entropies_binary_cpu_stream_10000.txt"

print("\t\t STS\n\nEnter the following: \n\n")
sequence_length = input("\nSequence Length: ")
num_sequences = input("\nNumber of Sequences: ")
file_name = input("\nFile name: ")

# Spawn the assess command with sequence length
child = pexpect.spawn(f"./assess {sequence_length}")

# Add logging
def log_step(step):
    print(f"--- Step: {step} ---")

try:
    # 1. Generator Selection
    log_step("Generator Selection")
    time.sleep(1)  # Add a delay before expecting the prompt
    child.expect("Enter Choice:", timeout=120)
    child.sendline("0")  # Choosing 0 for Input File

    # 2. Specify the input file
    log_step("Specify Input File")
    time.sleep(1)
    child.expect("User Prescribed Input File:", timeout=120)
    child.sendline(file_name)

    # 3. Statistical Tests Selection
    log_step("Statistical Tests Selection")
    time.sleep(1)
    child.expect("Enter Choice:", timeout=120)
    child.sendline("1")  # Choosing 1 to apply all tests

    # 4. Parameter Adjustments
    log_step("Parameter Adjustments")
    time.sleep(1)
    child.expect("Select Test (0 to continue):", timeout=120)
    child.sendline("0")  # Choosing 0 to skip parameter adjustments

    # 5. Number of Bit Streams
    log_step("Number of Bit Streams")
    time.sleep(1)
    child.expect("How many bitstreams?", timeout=120)
    child.sendline(num_sequences)

    # 6. Input File Format Selection
    log_step("Input File Format Selection")
    time.sleep(1)
    child.expect("Select input mode:", timeout=120)
    child.sendline("0")  # Choose 0 for ASCII format

    # Wait for the process to finish
    log_step("Waiting for completion")
    child.expect(pexpect.EOF, timeout=300)
    print("Report generation completed.")

except pexpect.exceptions.TIMEOUT as e:
    print(f"Timeout occurred at step: {e}")
except Exception as e:
    print(f"An error occurred: {e}")