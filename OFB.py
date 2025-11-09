##Joori eihab 2310656
from Crypto.Random import get_random_bytes  #import function tp generate random key bytes
from Crypto.Util.Padding import pad, unpad #import functions to add and remove padding to the plaintext
from Crypto.Cipher import AES  #import AES function

# AES Encryption Function :
def encrypt_block(key, block):#define function to encrypt block of data using AES 
    cipher = AES.new(key, AES.MODE_ECB)#create new object in AES mode with key
    encrypted_block = cipher.encrypt(block)#encrypt block
    return encrypted_block # return the encrypted block

# AES Decryption Function :
def decrypt_block(key, block):#define function to dencrypt block of data using AES 
    cipher = AES.new(key, AES.MODE_ECB) 
    decrypted_block = cipher.decrypt(block) 
    return decrypted_block 

#1)Generate random encryption key :
encryption_key = get_random_bytes(16)# its size 16 bytes

#2)Generate a random initialization vector ------------------> new for OFB 
IV = get_random_bytes(16)

#ask user to input the text to encrypt it:
print("\nEnter your message to encrypt :") 
user_message = input() 

if user_message == "":#if user didn't enter any text 
    print("No input provided. Please enter a message.") 
    user_message = input()

message_bytes = user_message.encode("utf-8")# 3)Convert the user message to bytes

#3)Pad the message to ensure it's a multiple of 16 bytes(128 bit)
padded_message = pad(message_bytes, 16)  

#4)split the padded message into 16-byte blocks
message_blocks = [padded_message[i:i+16] for i in range(0, len(padded_message), 16)]#start 0 to length of padded msg
print(f"\nMessage Blocks: {message_blocks}")# to display the list of blocks that padded 

#5)Encrypt the message blocks(each block)
encrypted_blocks = []#empty list to store the encrypted blocks

last = IV  # Starting point for the keystream ------------------> new for OFB

for block in message_blocks:
    key_stream = encrypt_block(encryption_key, last) #------------------> new for OFB encrypt the key with the previuos keystream
    cipher_block = bytes([b ^ k for b, k in zip(block, key_stream)])  #------------------> new for OFB. XOR the resuilt above with the message block
    encrypted_blocks.append(cipher_block)#add the encrypted block to the list

    last = key_stream #------------------> new for OFB, ubdate the last to be the new keystream

#-------------- Perform Cryptanalysis on AES-ECB --------------
print("\nDetecting operation for any pattern start.........")

ciphertext_hex = [b.hex() for b in encrypted_blocks]# to convert the encrypted blocks to hexadecimal for easier comparison

counter = {}
for block in ciphertext_hex:
    if block in counter:
        counter[block] += 1
    else:
        counter[block] = 1

# Find only the blocks that repeat
repeated_blocks = {}
for block, count in counter.items():
    if count > 1: # if repeat more than once
        repeated_blocks[block] = count

# Display all encrypted blocks in hexa format
print(f"\nEncrypted blocks (hex):")
for i, block in enumerate(encrypted_blocks):
    print(f"Block {i}---> {block.hex()}")

# display warning message if repeated blocks are found
if repeated_blocks:
    print("\n🚨 WARNING: Repeat ciphertext blocks detected")
    for block, count in repeated_blocks.items():
        print(f"\nBlock {block} appears {count} times")
    print(f" 🚨 identical plaintext blocks were encrypted {count} times🚨")
else:
    print("\n ✅ No repeated ciphertext blocks detected ✅")


#--------------------------------------------------------------

#Decrypt the encrypted blocks
decrypted_blocks = []#empty list to store the dencrypted blocks

last = IV #------------------> new for OFB the started itration
for block in encrypted_blocks:
    key_stream = encrypt_block(encryption_key, last) #------------------> new for OFB decrypt the key with IV(first step)
    plain_block = bytes([b ^ k for b, k in zip(block, key_stream)])#------------------> new for OFB. XOR the resuilt above with the message block
      
    decrypted_blocks.append(plain_block)#add the dencrypted block to the list
    last = key_stream  #------------------> new for OFB, ubdate the last to be the new keystream

print(f"\nEncrypted Blocks are: {encrypted_blocks}")# to display the list of encrypted blocks
print(f"\nDecrypted Blocks are: {decrypted_blocks}")# to display the list of dencrypted blocks

# 1)Join 2)decrypted blocks and 3)unpad 4)to string
joined_decrypted_data = b''.join(decrypted_blocks)#join the decrypted block togather
unpadded_data = unpad(joined_decrypted_data, 16)# remove the padding(unpadding) 
decoded_message = unpadded_data.decode("utf-8")#from byte to string 
print(f"\nOriginal Message after the OFB Decryption : {decoded_message}")#to display the original message after decryption

# python3 "/Users/apple/Desktop/python/OFB.py" (for run)


#HELLOHELLOHELLO1HELLOHELLOHELLO1HELLOHELLOHELLO1HELLOHELLOHELLO1
#Joorieihab123456Joorieihab123456
# HELLOHELLOHELLOHELLOHELLOHELLO