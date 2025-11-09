# #Joori eihab 2310656
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

#ask user to input the text to encrypt it:
print("Enter your message to encrypt :") 
user_message = input() 

if user_message == "":#if user didn't enter any text 
    print("No input provided. Please enter a message.") 
    user_message = input()
    
message_bytes = user_message.encode("utf-8")# 1)Convert the user message to bytes

#2)Pad the message to ensure it's a multiple of 16 bytes(128 bit)
padded_message = pad(message_bytes, 16)  

#3)split the padded message into 16-byte blocks
message_blocks = [padded_message[i:i+16] for i in range(0, len(padded_message), 16)]#start 0 to length of padded msg
print(f"\nMessage Blocks: {message_blocks}")#to display the list of blocks that padded 

#4)Encrypt the message blocks(each block)
encrypted_blocks = []#empty list to store the encrypted blocks
for block in message_blocks: 
    encrypted_block = encrypt_block(encryption_key, block)#encrypt block using the function above 
    encrypted_blocks.append(encrypted_block)#add the encrypted block to the list 



#-------------- Perform Cryptanalysis on AES-ECB --------------
print("\n  Detecting for any pattern.........")

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
print(f"/nEncrypted blocks in hexadecimal :")
for i, block in enumerate(encrypted_blocks):
    print(f"\nBlock {i}---> {block.hex()}")

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
for block in encrypted_blocks:#------------ 
    decrypted_block = decrypt_block(encryption_key, block)#dencrypt block using the function above  
    decrypted_blocks.append(decrypted_block)#add the dencrypted block to the list 

print(f"\nEncrypted Blocks are: {encrypted_blocks}")#to display the list of encrypted blocks
print(f"\nDecrypted Blocks are: {decrypted_blocks}")#to display the list of dencrypted blocks

# 1)Join 2)decrypted blocks and 3)unpad 4)to string
joined_decrypted_data = b''.join(decrypted_blocks)#join the decrypted block togather
unpadded_data = unpad(joined_decrypted_data, 16)# remove the padding(unpadding) 
decoded_message = unpadded_data.decode("utf-8")#from byte to string 
print(f"\nOriginal Message after Decryption : {decoded_message}")#to display the original message after decryption

# python3 "/Users/apple/Desktop/python/ECB .py"  to run

# HELLOHELLOHELLO1HELLOHELLOHELLO1HELLOHELLOHELLO1HELLOHELLOHELLO1 