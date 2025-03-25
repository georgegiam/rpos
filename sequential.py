import hashlib
import os
import time

def generate_hashes_to_file(key: str, file_path: str, file_size: int):
    key_bytes = key.encode()  # Convert key to bytes
    prev_hash = b"0"  # Initial hash input
    bytes_written = 0  

    start_time = time.time()  # Start timer

    with open(file_path, "wb") as f:
        while bytes_written < file_size:
            # Concatenate key with the previous hash
            data = key_bytes + prev_hash
            # Compute SHA-256 hash
            current_hash = hashlib.sha256(data).digest()
            # Write hash to file
            f.write(current_hash)
            bytes_written += len(current_hash)
            # Update previous hash for the next iteration
            prev_hash = current_hash
        
    end_time = time.time()  # End timer
    elapsed_time = end_time - start_time

    print(f"File '{file_path}' created with size {os.path.getsize(file_path)} bytes.")
    print(f"Time taken: {elapsed_time:.2f} seconds")

# Example usage
key = "0522a55e2d5f0993a3d66d28864b2862a7218a75ea7968b075333434404485c3"
file_path = "hashes.bin"
file_size = 1 * 1024 * 1024 * 1024  # 1GB

generate_hashes_to_file(key, file_path, file_size)
