from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad 
import hmac
import hashlib
import struct

# AES Encryption Function
def encrypt_block(key, block): 
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_block = cipher.encrypt(block)
    return encrypted_block 

# Key Derivation Function with Counter Context
def derive_session_key(master_key, iv, context, counter=0):   # Master Key + IV + Context + Counter → HMAC-SHA256 → Session Key
    """
    Enhanced KDF that includes counter in key derivation
    """
    # Include counter in key for even more uniqueness
    counter_bytes = struct.pack('>Q', counter)  # 64-bit counter
    key_material = iv + context.encode('utf-8') + counter_bytes
    
    # Use HMAC-SHA256 for key derivation
    derived_key = hmac.new(master_key, key_material, hashlib.sha256).digest()[:16]
    
    return derived_key

# OFB with Counter + KDF Encryption
def ofb_counter_kdf_encrypt(master_key, iv, plaintext):
    """
    Enhanced OFB with:
    1. Key Derivation (KDF) for session keys
    2. Counter mode for keystream generation
    3. Combined them
    """
    
    padded_message = pad(plaintext, 16)
    message_blocks = [padded_message[i:i+16] for i in range(0, len(padded_message), 16)]
    encrypted_blocks = []
    
    print("\nOFB with counter + KDF encryption process :")
    print(f"Master Key: {master_key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Number of blocks to encrypt: {len(message_blocks)}")
    print("-" * 50)
    
    for block_counter, block in enumerate(message_blocks):
        # IMPROVEMENT 1: Derive session key once per encryption 
        if block_counter == 0:
            session_key = derive_session_key(master_key, iv, "encryption_session")
            print(f"\nSession Key: {session_key.hex()}")
        
        # IMPROVEMENT 2: Use counter-based keystream generation
        # Combine IV with counter for unique input to each block
        counter_bytes = struct.pack('>Q', block_counter)  # 64-bit counter
        iv_with_counter = iv[:8] + counter_bytes  # Use first 8 bytes of IV + counter
        
        # Generate keystream using counter + IV
        key_stream = encrypt_block(session_key, iv_with_counter)
        
        # XOR with plaintext block
        cipher_block = bytes([b ^ k for b, k in zip(block, key_stream)])
        encrypted_blocks.append(cipher_block)
        
        print(f"Block {block_counter}:")
        print(f"  Counter: {block_counter} → Bytes: {counter_bytes.hex()}")
        print(f"  IV+Counter: {iv_with_counter.hex()}")
        print(f"  Keystream: {key_stream.hex()}")
        print(f"  Ciphertext: {cipher_block.hex()}")
    
    return b''.join(encrypted_blocks), session_key

# OFB with Counter + KDF Decryption
def ofb_counter_kdf_decrypt(master_key, iv, ciphertext):
    """
    decryption using same counter + KDF approach
    """
    cipher_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_blocks = []
    
    # Derive the same session key
    session_key = derive_session_key(master_key, iv, "encryption_session")
    
    for block_counter, block in enumerate(cipher_blocks):
        # Recreate the same ( IV with counter )
        counter_bytes = struct.pack('>Q', block_counter)
        iv_with_counter = iv[:8] + counter_bytes
        
        # Generate same keystream
        key_stream = encrypt_block(session_key, iv_with_counter)
        
        # XOR with ciphertext block
        plain_block = bytes([b ^ k for b, k in zip(block, key_stream)])
        decrypted_blocks.append(plain_block)
    
    joined_data = b''.join(decrypted_blocks)
    unpadded_data = unpad(joined_data, 16)
    
    return unpadded_data

# Security Analysis Function
def analyze_security_improvements():
    """
    analyze the combined security benefits of Counter + KDF
    """
    master_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    
    # Test with repeating pattern
    test_message = "HELLOHELLOHELLOHELLOHELLOHELLO"
    message_bytes = test_message.encode("utf-8")
    
    print(f"\nTest message: {test_message}")
    
    print("\nEncryption with : counter + KDF")
    
    # Encrypt with enhanced OFB
    encrypted, session_key = ofb_counter_kdf_encrypt(master_key, iv, message_bytes)
    
    print("\n" + "-" * 60)
    print("\npattern Analysis")
    
    # Analyze for repeated blocks
    encrypted_blocks = [encrypted[i:i+16] for i in range(0, len(encrypted), 16)]
    unique_blocks = len(set(block.hex() for block in encrypted_blocks))
    
    print(f"total number of blocks: {len(encrypted_blocks)}")
    print(f"Unique ciphertext blocks: {unique_blocks}")
    print(f"Repeated blocks: {len(encrypted_blocks) - unique_blocks}")
    
    if unique_blocks == len(encrypted_blocks):
        print("\n✅ Success: No pattern detected ")
    else:
        print("\n❌ Warning: some patterns detected ")
    
    print("\n" + "-" * 60)
    print("\nDecryption verification :")
    
    # Verify decryption works
    decrypted = ofb_counter_kdf_decrypt(master_key, iv, encrypted)
    decoded = decrypted.decode("utf-8")
    
    print(f"\nDecrypted message : {decoded}")
    print(f"does Decryption success ? : {decoded == test_message}")

# Run the enhanced demonstration
if __name__ == "__main__":
    analyze_security_improvements()


# python3 "/Users/apple/Desktop/python/improvOFB.py" (for run)
# Joorieihab123456Joorieihab123456
# HELLOHELLOHELLOHELLOHELLOHELLO