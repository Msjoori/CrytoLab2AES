#Joori eihab 2310656
from Crypto.Cipher import AES      # For AES encryption
from Crypto.Random import get_random_bytes  # For generating random keys
from PIL import Image              # For image processes 
import os                         # For file operations

#encrypts one 16 byte block
def encrypt_block(key, block):
    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher in ECB mode
    return cipher.encrypt(block)          # Encrypt the block and return result

# ECB mode encryption for images (each block encrypted independently)
def ecb_encrypt(data, key):
    #make data length divisible by 16 (AES block size)
    length = len(data) - (len(data) % 16)
    data = data[:length]  # Trim to the new length
    
    encrypted = b''  # we start with empty bytes
    # Process data in 16 byte blocks
    for i in range(0, length, 16):
        block = data[i:i+16] #to get 16 byte block
        encrypted_block = encrypt_block(key, block)  # Encrypt the block
        encrypted += encrypted_block #Add the encryted block to the result
    return encrypted

# OFB mode encryption for images - creates stream cipher
def ofb_encrypt(data, key, iv):
    # Make data length divisible by 16
    length = len(data) - (len(data) % 16)
    data = data[:length]
    
    encrypted = b''    #We start with empty bytes
    current = iv       # Start with Initialization Vector (IV)
    
    # To process each 16 byte block
    for i in range(0, length, 16):
        block = data[i:i+16]  # Get plaintext block
        
        # Generating keystream by encrypting current value (key with IV)
        keystream = encrypt_block(key, current)
        
        # XOR plaintext with keystream to get ciphertext
        encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
        
        encrypted += encrypted_block  # Add to result
        current = keystream           # Update for next block
    return encrypted

# Load image and convert to grayscale bytes
def load_image(path):
    img = Image.open(path).convert("L")  # Open image and convert to grayscale
    return img.tobytes()                 # Convert image to raw bytes

# Save encrypted data as an image file
def save_image(data, output_path):
    # Calculate size for square image it is (simple approach)
    size = int(len(data) ** 0.5)  # Square root of data length
    
    # To make sure we don't exceed available data
    if size * size > len(data):
        size -= 1
    
    # Create image from encrypted bytes
    img = Image.frombytes("L", (size, size), data[:size * size])
    img.save(output_path)  # Save to file

# (Main function) to runs the entire encryption process *****
def main():
    # Path to my input image :
    image_path = "/Users/apple/Desktop/python/image.png"
    
    # to check if image file exists :
    if not os.path.exists(image_path):
        print(f"🚨ERROR🚨\nwe cannot find the file path : {image_path}")
        print("Please make sure that the image exists at this path")
        return
    
    # Generate random 128-bit (16 byte) key and Initialization Vector (IV)
    key = get_random_bytes(16)  # 16 bytes = 128 bits
    iv = get_random_bytes(16)   # 16 bytes for IV
    
    # Load the image as raw bytes
    image_data = load_image(image_path)
    print(f"Image loaded: {len(image_data)} bytes\n")
    
    # Encrypt using ECB mode : ****
    print("start encrypting with ECB mode......\n")
    ecb_data = ecb_encrypt(image_data, key)
    
    # Encrypt using OFB mode.  ****
    print("start encrypting with ECB mode......\n")
    ofb_data = ofb_encrypt(image_data, key, iv)
    
    # Save the encrypted results as image files
    save_image(ecb_data, "/Users/apple/Desktop/python/ecb_result.png")
    save_image(ofb_data, "/Users/apple/Desktop/python/ofb_result.png")
    
    # Displaying the results :
    print("\n✅ Encryption completed ✅")
    print("ECB result: /Users/apple/Desktop/python/ecb_result.png")
    print("OFB result: /Users/apple/Desktop/python/ofb_result.png")
    print("\n Compare the two images: ")
    print("ECB will show visible patterns from original image")
    print("OFB will look like random noise (secure)")

# start the program when script is run
if __name__ == "__main__":
    main()


# python3 "/Users/apple/Desktop/python/Encryptimage.py" (for run)