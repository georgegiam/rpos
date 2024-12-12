import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor

def sha256_hash(data):
    """Generates a SHA-256 hash for the given data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_hashes_in_parallel(key, num_hashes, num_threads=4):
    """Generates a specified number of hashes in parallel using multiple threads."""
    def hash_worker(start_hash, num_hashes_per_thread):
        """Worker function to compute a sequence of hashes."""
        start_time = time.time()  # Start timer for this thread
        current_hash = start_hash
        results = []
        for _ in range(num_hashes_per_thread):
            current_hash = sha256_hash(current_hash + key)
            results.append(current_hash)
        duration = time.time() - start_time  # Calculate duration
        print(f"Thread completed: {num_hashes_per_thread} hashes in {duration:.2f} seconds.")
        return results, duration

    # Calculate workload per thread
    num_hashes_per_thread = num_hashes // num_threads
    remaining_hashes = num_hashes % num_threads

    # Generate initial hash for the first block
    initial_hash = sha256_hash(key + str(set()))

    # Parallel hash generation
    all_hashes = []
    durations = []
    start_collect_time = time.time()  # Time before starting the threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit tasks for all threads
        futures = [
            executor.submit(
                hash_worker,
                initial_hash,
                num_hashes_per_thread + (1 if i < remaining_hashes else 0)  # Distribute extra hashes among threads
            )
            for i in range(num_threads)
        ]
        for future in futures:
            result, thread_duration = future.result()
            all_hashes.extend(result)
            durations.append(thread_duration)

    collection_duration = time.time() - start_collect_time  # Calculate collection duration
    print(f"Data collection completed in {collection_duration:.2f} seconds.")
    return all_hashes, durations

def write_hashes_to_file(hashes, file_name, buffer_size=10000):
    """Writes hashes to a file in buffered chunks."""
    start_write_time = time.time()  # Start timer for writing to disk
    with open(file_name, 'w') as file:
        buffer = []
        for hash_val in hashes:
            buffer.append(hash_val + '\n')
            if len(buffer) >= buffer_size:
                file.writelines(buffer)
                buffer.clear()
        # Write any remaining hashes in the buffer
        if buffer:
            file.writelines(buffer)
    write_duration = time.time() - start_write_time  # Calculate write duration
    print(f"Data written to disk in {write_duration:.2f} seconds.")

def create_large_blockchain_file(key, target_size_gb=1, file_name="large_blockchain_hashes.txt", num_threads=8):
    """Generates a 1GB file of hashes efficiently using parallel processing and buffered file writes."""
    # Target file size in bytes
    target_size_bytes = target_size_gb * 1024**3  # Convert GB to bytes

    # Approximate number of hashes required (65 bytes per hash with newline)
    num_hashes = target_size_bytes // 65

    # Generate hashes in parallel
    hashes, thread_durations = generate_hashes_in_parallel(key, num_hashes, num_threads=num_threads)

    # Write hashes to the file
    write_hashes_to_file(hashes, file_name)

# Parameters
key = hashlib.sha256(b'some_secret_key').hexdigest()  # Replace with your actual key seed
file_name = "large_blockchain_hashes.txt"
num_threads = 4  # Adjust based on your CPU's core/thread count
target_size_gb = 1  # File size in GB

# Generate the file
create_large_blockchain_file(key, target_size_gb, file_name, num_threads)
