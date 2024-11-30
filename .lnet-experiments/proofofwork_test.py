import os
import hashlib
import time

def generate_task(difficulty=5, extra_diff=2, salt_length=32):
    salt = os.urandom(salt_length)
    return difficulty, extra_diff, salt

def solve_task(data: bytes, salt: bytes, difficulty: int, extra_difficulty: int) -> list[tuple[bytes, str]]:
    found_nonces = []
    nonce = os.urandom(16)
    found_nonces.append(nonce)
    found_hashes = [hashlib.sha256(data + salt + nonce)]
    for i in range(extra_difficulty):
        latest_hash = found_hashes[len(found_hashes)-1].digest()
        while True:
            hash_result = hashlib.sha256(latest_hash + salt + nonce)
            if hash_result.hexdigest()[:difficulty] == '0' * difficulty:
                found_hashes.append(hash_result)
                found_nonces.append(nonce)
                break
            nonce = os.urandom(16)
    return list(zip(found_nonces, [h.hexdigest() for h in found_hashes]))

def verify_solution(data: bytes, salt: bytes, difficulty: int, extra_difficulty: int, solution: list[tuple[bytes, str]]) -> tuple[bool, str]:
    if len(solution) != extra_difficulty + 1: # +1 initial hash
        return False, "Extra difficulty solution mismatch."
    
    prev_data = data
    required_hash_prefix = '0' * difficulty

    for i, solution_part in enumerate(solution):
        nonce, resulted_hash = solution_part
        if i > 0 and not resulted_hash.startswith(required_hash_prefix):
            return False, "Resulted hash prefix does not match it's difficulty."
        
        recomputed = hashlib.sha256(prev_data + salt + nonce)
        if recomputed.hexdigest() != resulted_hash:
            return False, f"Incorrect hash result at index: {i}."
        
        prev_data = recomputed.digest()
    
    return True, "Verification succeed!"

# Server generates a task
difficulty, extra_difficulty, salt = generate_task()

# Client prepares the transmission data
# and solves the task based on all parameters
data = b'Register{user="Test"}'
start_time = time.time()
solution = solve_task(data, salt, difficulty, extra_difficulty)
print(f"Solution: {solution} Time: {time.time() - start_time}")

# Server verifies solution.
# If first value is True, then proceed client's request.
verification = verify_solution(data, salt, difficulty, extra_difficulty, solution)
print('Verification:', verification)

# Run tests
assert verification[0] == True

verification = verify_solution(data, salt, difficulty+1, extra_difficulty, solution)
assert verification[0] == False

verification = verify_solution(data, salt, difficulty, extra_difficulty+1, solution)
assert verification[0] == False

verification = verify_solution(data, salt, difficulty+1, extra_difficulty+1, solution)
assert verification[0] == False

verification = verify_solution(data, os.urandom(32), difficulty, extra_difficulty, solution)
assert verification[0] == False

verification = verify_solution(data, os.urandom(16), difficulty, extra_difficulty, solution)
assert verification[0] == False

print("All tests passed!")