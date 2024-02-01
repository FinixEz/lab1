from pwn import *
import re

def receive_until_match(conn, pattern):
    while True:
        line = conn.recvline().decode()
        print("Received:", repr(line))
        if re.search(pattern, line):
            return line

def decrypt_shift_cipher(encrypted_text, key):
    decrypted_string = ''
    for char in encrypted_text:
        if char.isalpha():
            decrypted_string += chr((ord(char) - key - ord('a')) % 26 + ord('a'))
        else:
            decrypted_string += char
    return decrypted_string

host = '172.26.201.17'
port = 2131
conn = remote(host, port)

conn.sendline(b'1')

question = receive_until_match(conn, r'encrypted using the shift cipher')

match = re.search(r'"(.+)" is encrypted using the shift cipher with key=(\d+)', question)
if match:
    encrypted_text = match.group(1)
    key = int(match.group(2))

    print(f"Encrypted Text: {encrypted_text}")
    print(f"Key: {key}")

    decrypted_string = decrypt_shift_cipher(encrypted_text, key)
    print(f"Decrypted String: {decrypted_string}")

    conn.sendline(decrypted_string.encode())

    result = conn.recvall().decode()
    print(result)
else:
    print("Error: Could not find the encrypted string in the question.")

conn.close()
